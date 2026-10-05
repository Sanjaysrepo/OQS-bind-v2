#pragma once

/*
 * RAW UDP fragmentation
 * ---------------------
 *
 * QBF (qbf.c) only splits DNSKEY and RRSIG RDATA, relies on RR order and
 * cannot tell a fragment from a truncated reply.  RAW has none of these
 * limitations: the *complete* rendered response is treated as an opaque
 * byte stream and cut into slices.
 *
 * Wire format
 *
 *   fragment i (0 <= i < N), one UDP datagram of at most max_udp_size bytes:
 *
 *     +----------------------------------------------+
 *     | DNS header: id, flags of the original reply, |
 *     |   TC cleared, RCODE = RAW_RCODE (12)         |
 *     |   QDCOUNT=1 ANCOUNT=0 NSCOUNT=0 ARCOUNT=1     |
 *     | question: original qname/qtype/qclass        |
 *     | OPT RR: EDNS option 22 = <i:6><N:6><flags:4> |
 *     +----------------------------------------------+  <- envelope
 *     | slice i of the original wire message         |  <- payload
 *     +----------------------------------------------+
 *
 *   The envelope is a well-formed DNS message; BIND's parser accepts the
 *   payload as "trailing garbage".  The payload of all fragments
 *   concatenated is the original rendered response, byte for byte
 *   (including its own header, OPT, cookies, TSIG, ...), so reassembly
 *   needs no fix-ups at all.
 *
 *   A resolver that does not know RAW sees RCODE 12 and treats the reply
 *   as an error instead of caching an empty answer.
 *
 * Flow
 *
 *   1. ns_client_send() renders the complete reply once (raw_fragment()).
 *      If it fits in max_udp_size nothing happens (ISC_R_RANGE) and the
 *      normal path renders as usual.
 *   2. Otherwise N envelopes+slices are stored in the fragment cache under
 *      key <txid>-<client address> and fragment 0 is sent.
 *   3. The resolver (dispatch.c, or dig) detects RCODE 12 + option 22,
 *      caches the datagram and asks for fragments 1..N-1 with queries
 *      using OPCODE 7 (dns_opcode_fragment) that carry option 22 with the
 *      wanted fragment number (create_fragment_query_opt()).
 *   4. The server answers OPCODE 7 queries straight from the cache.
 *   5. When all N fragments are present raw_reassemble() rebuilds the
 *      original datagram and the resolver processes it as if it had
 *      arrived in one piece.
 */

#include <stdbool.h>

#include <isc/buffer.h>
#include <isc/mem.h>
#include <isc/region.h>
#include <isc/result.h>
#include <isc/types.h>

#include <dns/fcache.h>
#include <dns/message.h>
#include <dns/types.h>

/* chosen based on https://www.iana.org/assignments/dns-parameters/ */
#define RAW_OPCODE	  7  /* dns_opcode_fragment */
#define RAW_RCODE	  12 /* rcodes 1-11 are taken by RFC1035/RFC2136 */
#define RAW_OPT_OPTION	  22 /* == OPTION_CODE in udp_fragmentation.h */
#define RAW_MAX_FRAGMENTS 63 /* 6-bit field */
#define RAW_DEFAULT_MAX_UDP_SIZE 1232

/*
 * 1-RTT mode: when the resolver sends a query that may get a fragmented
 * answer, it sends speculative OPCODE 7 requests for fragments 1..n-1
 * together with the query, so the complete answer arrives in a single
 * round trip.  n is the number of fragments the last fragmented answer
 * from that server needed - for the same query type if there is one,
 * else for any type (per-server history kept by the dispatch manager) -
 * and this default for servers we have no history with.  The default is
 * also the lower bound: history only ever raises the estimate.  If the answer
 * needs more fragments than estimated, the remainder is requested when
 * fragment 0 arrives (two-step); if it needs fewer - or the server does
 * not support fragmentation at all - the server answers the speculative
 * requests with OPCODE 7 error echoes, which the dispatch ignores.
 * Requests are ~50 bytes and a server only ever answers fragments it
 * has, so a generous estimate costs little; a low one costs a round trip.
 */
#define RAW_1RTT_DEFAULT_ESTIMATE 4

/*
 * Server side.  Renders 'msg' (which must be in render intent and not yet
 * rendered) with 'opt' as its OPT record, and if the result does not fit
 * in 'max_udp_size' stores the fragments in 'fcache'.  'render_opts' are
 * the DNS_MESSAGERENDER_* options the caller would have used for the
 * normal rendering.  On return the message has been reset so the caller
 * can still render it normally.
 *
 * Returns:
 *   ISC_R_SUCCESS  fragments are in the cache, *nr_fragmentsp is set
 *   ISC_R_RANGE    the reply fits in one datagram, nothing was cached
 *   ISC_R_EXISTS   an entry for this key already exists
 *   ISC_R_NOSPACE  the reply is too large to be fragmented
 *   other          rendering error
 */
isc_result_t
raw_fragment(isc_mem_t *mctx, fcache_t *fcache, dns_message_t *msg,
	     dns_rdataset_t *opt, const char *client_address,
	     unsigned max_udp_size, unsigned render_opts,
	     unsigned *nr_fragmentsp);

/*
 * Cheap byte-level inspection of a datagram.  Succeeds if it has RCODE
 * RAW_RCODE and a well-formed envelope carrying option 22.  On success
 * *payload_offset is the offset of the first payload byte.
 *
 * Returns ISC_R_SUCCESS, ISC_R_NOTFOUND (not a RAW fragment),
 * ISC_R_RANGE (inconsistent fragment numbers) or ISC_R_UNEXPECTEDEND.
 */
isc_result_t
raw_parse_envelope(const isc_region_t *datagram, unsigned *frag_nr,
		   unsigned *nr_fragments, unsigned *payload_offset);

/* true if 'datagram' looks like a RAW fragment */
bool
raw_is_fragment(const isc_region_t *datagram);

/*
 * true if the wire-format query 'query' is worth 1-RTT prefetching:
 * a plain question (QR 0, OPCODE QUERY, one question, no answers) with
 * EDNS and the DO bit set - without DO the answer carries no signatures
 * and will not be fragmented.
 */
bool
raw_prefetch_candidate(const isc_region_t *query);

/*
 * 1-RTT race: a speculative request can reach the server before the
 * answer exists (a recursive server still resolving, or a slow render),
 * miss the server's fragment cache and come back as an OPCODE 7 echo.
 * Requests 1..'prefetched' were sent; the answer has 'nr_fragments'
 * fragments, so the requests beyond the answer are expected to echo.
 * Any echo on top of those means a request for a fragment the answer
 * does have was lost to the race and must be sent again.
 */
static inline bool
raw_prefetch_missed(unsigned prefetched, unsigned nr_fragments,
		    unsigned echoes) {
	unsigned beyond = (prefetched >= nr_fragments)
				  ? prefetched - nr_fragments + 1
				  : 0;
	return (echoes > beyond);
}

/* the QTYPE of the first question of a wire message; 0 if there is none */
unsigned
raw_question_type(const isc_region_t *msg);

/*
 * Builds the OPCODE 7 request for fragment 'frag_nr' of 'nr_fragments'
 * straight from the wire bytes of 'msg' - the original query or any RAW
 * fragment of the answer (both start with the same id and question).
 * Byte-level, no message parsing or rendering: cheap enough to build a
 * whole 1-RTT burst before the query leaves, so the query and its
 * speculative requests go out back to back.  The result is identical to
 * create_fragment_query_opt()'s.  *outp is allocated and owned by the
 * caller.
 *
 * Returns ISC_R_SUCCESS, ISC_R_FAILURE (bad numbers or question) or
 * ISC_R_UNEXPECTEDEND (short message).
 */
isc_result_t
raw_build_request(isc_mem_t *mctx, const isc_region_t *msg, unsigned frag_nr,
		  unsigned nr_fragments, isc_buffer_t **outp);

/*
 * Reassembles a complete cache entry (see fcache_take_complete()) into a
 * newly allocated buffer holding the original wire message.  The entry is
 * left untouched.
 *
 * Returns ISC_R_SUCCESS, ISC_R_INPROGRESS (fragments missing) or
 * ISC_R_FAILURE (fragments do not belong together).
 */
isc_result_t
raw_reassemble(isc_mem_t *mctx, const fragment_cache_entry_t *entry,
	       isc_buffer_t **outp);
