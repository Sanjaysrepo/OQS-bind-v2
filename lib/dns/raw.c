/*
 * RAW UDP fragmentation: see include/dns/raw.h for the wire format.
 */

#include <inttypes.h>
#include <stdbool.h>
#include <string.h>

#include <isc/buffer.h>
#include <isc/log.h>
#include <isc/mem.h>
#include <isc/region.h>
#include <isc/result.h>
#include <isc/util.h>

#include <dns/compress.h>
#include <dns/fcache.h>
#include <dns/log.h>
#include <dns/message.h>
#include <dns/name.h>
#include <dns/raw.h>
#include <dns/rdataset.h>
#include <dns/rdatatype.h>
#include <dns/types.h>
#include <dns/udp_fragmentation.h>

#define RAW_LOG(level, ...)                                            \
	isc_log_write(dns_lctx, DNS_LOGCATEGORY_FRAGMENTATION,         \
		      DNS_LOGMODULE_FRAGMENT, level, __VA_ARGS__)

#define DNS_HEADER_SIZE	     12
#define RR_FIXED_SIZE	     10 /* type, class, ttl, rdlength */
#define QUESTION_FIXED_SIZE  4	/* type, class */
#define DNS_MAX_MESSAGE_SIZE 65535

/*
 * Skips a (possibly compressed) wire-format name starting at *offp.
 */
static isc_result_t
skip_name(const unsigned char *p, unsigned len, unsigned *offp) {
	unsigned i = *offp;
	while (true) {
		if (i >= len) {
			return (ISC_R_UNEXPECTEDEND);
		}
		unsigned l = p[i];
		if (l == 0) {
			i++;
			break;
		}
		if ((l & 0xC0) == 0xC0) {
			if (i + 2 > len) {
				return (ISC_R_UNEXPECTEDEND);
			}
			i += 2;
			break;
		}
		if ((l & 0xC0) != 0) {
			return (ISC_R_FAILURE);
		}
		i += 1 + l;
	}
	*offp = i;
	return (ISC_R_SUCCESS);
}

isc_result_t
raw_parse_envelope(const isc_region_t *datagram, unsigned *frag_nr,
		   unsigned *nr_fragments, unsigned *payload_offset) {
	REQUIRE(datagram != NULL);

	const unsigned char *p = datagram->base;
	unsigned len = datagram->length;
	isc_result_t result;

	if (len < DNS_HEADER_SIZE) {
		return (ISC_R_UNEXPECTEDEND);
	}
	if ((p[3] & 0x0F) != RAW_RCODE) {
		return (ISC_R_NOTFOUND);
	}

	unsigned qdcount = (p[4] << 8) | p[5];
	unsigned rrcount = ((p[6] << 8) | p[7]) + ((p[8] << 8) | p[9]) +
			   ((p[10] << 8) | p[11]);
	unsigned off = DNS_HEADER_SIZE;

	for (unsigned i = 0; i < qdcount; i++) {
		result = skip_name(p, len, &off);
		if (result != ISC_R_SUCCESS) {
			return (result);
		}
		off += QUESTION_FIXED_SIZE;
		if (off > len) {
			return (ISC_R_UNEXPECTEDEND);
		}
	}

	bool found = false;
	unsigned fnr = 0, total = 0;
	for (unsigned i = 0; i < rrcount; i++) {
		result = skip_name(p, len, &off);
		if (result != ISC_R_SUCCESS) {
			return (result);
		}
		if (off + RR_FIXED_SIZE > len) {
			return (ISC_R_UNEXPECTEDEND);
		}
		unsigned type = (p[off] << 8) | p[off + 1];
		unsigned rdlen = (p[off + 8] << 8) | p[off + 9];
		off += RR_FIXED_SIZE;
		if (off + rdlen > len) {
			return (ISC_R_UNEXPECTEDEND);
		}
		if (type == dns_rdatatype_opt) {
			unsigned o = off, end = off + rdlen;
			while (o + 4 <= end) {
				unsigned code = (p[o] << 8) | p[o + 1];
				unsigned olen = (p[o + 2] << 8) | p[o + 3];
				o += 4;
				if (o + olen > end) {
					return (ISC_R_UNEXPECTEDEND);
				}
				if (code == RAW_OPT_OPTION && olen == 2 &&
				    !found) {
					unsigned v = (p[o] << 8) | p[o + 1];
					fnr = (v >> 10) & 0x3f;
					total = (v >> 4) & 0x3f;
					found = true;
				}
				o += olen;
			}
		}
		off += rdlen;
	}

	if (!found) {
		return (ISC_R_NOTFOUND);
	}
	if (total == 0 || fnr >= total) {
		return (ISC_R_RANGE);
	}
	SET_IF_NOT_NULL(frag_nr, fnr);
	SET_IF_NOT_NULL(nr_fragments, total);
	SET_IF_NOT_NULL(payload_offset, off);
	return (ISC_R_SUCCESS);
}

bool
raw_is_fragment(const isc_region_t *datagram) {
	return (raw_parse_envelope(datagram, NULL, NULL, NULL) ==
		ISC_R_SUCCESS);
}

bool
raw_prefetch_candidate(const isc_region_t *query) {
	REQUIRE(query != NULL);

	const unsigned char *p = query->base;
	unsigned len = query->length;
	unsigned off = DNS_HEADER_SIZE;

	if (len < DNS_HEADER_SIZE) {
		return (false);
	}
	if ((p[2] & 0x80) != 0) {
		return (false); /* a response, not a query */
	}
	if (((p[2] >> 3) & 0x0F) != 0) {
		return (false); /* not a plain QUERY (nor OPCODE 7) */
	}
	unsigned qdcount = (p[4] << 8) | p[5];
	unsigned ancount = (p[6] << 8) | p[7];
	unsigned nscount = (p[8] << 8) | p[9];
	unsigned arcount = (p[10] << 8) | p[11];
	if (qdcount != 1 || ancount != 0 || nscount != 0 || arcount == 0) {
		return (false);
	}
	if (skip_name(p, len, &off) != ISC_R_SUCCESS) {
		return (false);
	}
	off += QUESTION_FIXED_SIZE;
	if (off > len) {
		return (false);
	}
	for (unsigned i = 0; i < arcount; i++) {
		if (skip_name(p, len, &off) != ISC_R_SUCCESS) {
			return (false);
		}
		if (off + RR_FIXED_SIZE > len) {
			return (false);
		}
		unsigned type = (p[off] << 8) | p[off + 1];
		/* OPT TTL = ext-rcode, version, flags; DO is the top flag */
		bool do_bit = (p[off + 6] & 0x80) != 0;
		unsigned rdlen = (p[off + 8] << 8) | p[off + 9];
		off += RR_FIXED_SIZE + rdlen;
		if (off > len) {
			return (false);
		}
		if (type == dns_rdatatype_opt) {
			return (do_bit);
		}
	}
	return (false);
}

/*
 * Renders the whole message (with 'opt' attached) into a fresh buffer and
 * then resets the message so that it can be rendered again by the caller.
 */
static isc_result_t
raw_render_full(isc_mem_t *mctx, dns_message_t *msg, dns_rdataset_t *opt,
		unsigned render_opts, isc_buffer_t **bufp) {
	isc_result_t result;
	isc_buffer_t *buf = NULL;
	dns_compress_t cctx;
	bool have_cctx = false, began = false, opt_set = false;

	isc_buffer_allocate(mctx, &buf, DNS_MAX_MESSAGE_SIZE);
	dns_compress_init(&cctx, mctx, 0);
	have_cctx = true;

	result = dns_message_renderbegin(msg, &cctx, buf);
	if (result != ISC_R_SUCCESS) {
		goto cleanup;
	}
	began = true;

	result = dns_message_setopt(msg, opt);
	if (result != ISC_R_SUCCESS) {
		goto cleanup;
	}
	opt_set = true;

	result = dns_message_rendersection(msg, DNS_SECTION_QUESTION, 0);
	if (result != ISC_R_SUCCESS) {
		goto cleanup;
	}
	result = dns_message_rendersection(msg, DNS_SECTION_ANSWER,
					   render_opts);
	if (result != ISC_R_SUCCESS) {
		goto cleanup;
	}
	result = dns_message_rendersection(msg, DNS_SECTION_AUTHORITY,
					   render_opts);
	if (result != ISC_R_SUCCESS) {
		goto cleanup;
	}
	result = dns_message_rendersection(msg, DNS_SECTION_ADDITIONAL,
					   render_opts);
	if (result != ISC_R_SUCCESS) {
		goto cleanup;
	}
	result = dns_message_renderend(msg);
	if (result != ISC_R_SUCCESS) {
		goto cleanup;
	}
	opt_set = false; /* renderend released the reservation */

cleanup:
	if (opt_set) {
		dns_message_renderrelease(msg, msg->opt_reserved);
		msg->opt_reserved = 0;
	}
	/* the OPT stays owned by the caller */
	msg->opt = NULL;
	if (began) {
		dns_message_renderreset(msg);
	}
	if (have_cctx) {
		dns_compress_invalidate(&cctx);
	}
	if (result == ISC_R_SUCCESS) {
		*bufp = buf;
	} else {
		isc_buffer_free(&buf);
	}
	return (result);
}

/*
 * Builds and renders the envelope of fragment 'frag_nr' into a new buffer
 * of 'max_udp_size' bytes; the caller appends the payload.
 */
static isc_result_t
raw_render_envelope(isc_mem_t *mctx, dns_message_t *msg, unsigned frag_nr,
		    unsigned nr_fragments, unsigned max_udp_size,
		    isc_buffer_t **bufp) {
	isc_result_t result;
	dns_message_t *env = NULL;
	dns_name_t *qname = NULL, *name = NULL;
	dns_rdataset_t *qrds = NULL, *rds = NULL;
	isc_buffer_t *buf = NULL;
	dns_compress_t cctx;
	bool have_cctx = false;

	result = dns_message_firstname(msg, DNS_SECTION_QUESTION);
	if (result != ISC_R_SUCCESS) {
		return (result);
	}
	dns_message_currentname(msg, DNS_SECTION_QUESTION, &qname);
	qrds = ISC_LIST_HEAD(qname->list);
	if (qrds == NULL) {
		return (ISC_R_FAILURE);
	}

	dns_message_create(mctx, DNS_MESSAGE_INTENTRENDER, &env);
	env->id = msg->id;
	env->flags = (msg->flags | DNS_MESSAGEFLAG_QR) & ~DNS_MESSAGEFLAG_TC;
	env->opcode = msg->opcode;
	env->rcode = RAW_RCODE;
	env->rdclass = msg->rdclass;

	dns_message_gettempname(env, &name);
	dns_name_copy(qname, name);
	dns_message_gettemprdataset(env, &rds);
	dns_rdataset_makequestion(rds, qrds->rdclass, qrds->type);
	ISC_LIST_APPEND(name->list, rds, link);
	dns_message_addname(env, name, DNS_SECTION_QUESTION);

	result = create_fragment_opt(env, frag_nr, nr_fragments, 0);
	if (result != ISC_R_SUCCESS) {
		goto cleanup;
	}

	isc_buffer_allocate(mctx, &buf, max_udp_size);
	dns_compress_init(&cctx, mctx, 0);
	have_cctx = true;
	result = dns_message_renderbegin(env, &cctx, buf);
	if (result != ISC_R_SUCCESS) {
		goto cleanup;
	}
	result = dns_message_rendersection(env, DNS_SECTION_QUESTION, 0);
	if (result != ISC_R_SUCCESS) {
		goto cleanup;
	}
	result = dns_message_renderend(env);
	if (result != ISC_R_SUCCESS) {
		goto cleanup;
	}

cleanup:
	if (have_cctx) {
		dns_compress_invalidate(&cctx);
	}
	env->buffer = NULL; /* we own the buffer */
	dns_message_detach(&env);
	if (result == ISC_R_SUCCESS) {
		*bufp = buf;
	} else if (buf != NULL) {
		isc_buffer_free(&buf);
	}
	return (result);
}

isc_result_t
raw_fragment(isc_mem_t *mctx, fcache_t *fcache, dns_message_t *msg,
	     dns_rdataset_t *opt, const char *client_address,
	     unsigned max_udp_size, unsigned render_opts,
	     unsigned *nr_fragmentsp) {
	REQUIRE(mctx != NULL && fcache != NULL);
	REQUIRE(DNS_MESSAGE_VALID(msg));
	REQUIRE(msg->from_to_wire == DNS_MESSAGE_INTENTRENDER);
	REQUIRE(msg->buffer == NULL);
	REQUIRE(opt != NULL);
	REQUIRE(max_udp_size > DNS_HEADER_SIZE);

	isc_result_t result;
	isc_buffer_t *full = NULL, *env = NULL;
	unsigned char key[69];
	unsigned keysize = sizeof(key);
	unsigned nr_fragments = 0;
	bool cached = false;

	fcache_create_key(msg->id, client_address, key, &keysize);
	if (fcache_exists(fcache, key, keysize)) {
		RAW_LOG(ISC_LOG_DEBUG(8), "RAW: entry %.*s already exists",
			(int)keysize, key);
		return (ISC_R_EXISTS);
	}

	result = raw_render_full(mctx, msg, opt, render_opts, &full);
	if (result != ISC_R_SUCCESS) {
		RAW_LOG(ISC_LOG_DEBUG(8), "RAW: rendering full reply: %s",
			isc_result_totext(result));
		return (result);
	}
	unsigned total = isc_buffer_usedlength(full);
	if (total <= max_udp_size) {
		result = ISC_R_RANGE;
		goto cleanup;
	}

	/* all envelopes have the same size; measure with a dummy one */
	result = raw_render_envelope(mctx, msg, 0, 1, max_udp_size, &env);
	if (result != ISC_R_SUCCESS) {
		goto cleanup;
	}
	unsigned env_len = isc_buffer_usedlength(env);
	isc_buffer_free(&env);
	if (env_len >= max_udp_size) {
		result = ISC_R_NOSPACE;
		goto cleanup;
	}
	unsigned payload = max_udp_size - env_len;
	nr_fragments = (total + payload - 1) / payload;
	if (nr_fragments > RAW_MAX_FRAGMENTS) {
		RAW_LOG(ISC_LOG_DEBUG(8),
			"RAW: %u bytes need %u fragments (max %u)", total,
			nr_fragments, RAW_MAX_FRAGMENTS);
		result = ISC_R_NOSPACE;
		goto cleanup;
	}

	result = fcache_add(fcache, key, keysize, nr_fragments);
	if (result != ISC_R_SUCCESS) {
		goto cleanup;
	}
	cached = true;

	const unsigned char *src = isc_buffer_base(full);
	unsigned offset = 0;
	for (unsigned i = 0; i < nr_fragments; i++) {
		result = raw_render_envelope(mctx, msg, i, nr_fragments,
					     max_udp_size, &env);
		if (result != ISC_R_SUCCESS) {
			goto cleanup;
		}
		INSIST(isc_buffer_usedlength(env) == env_len);
		unsigned n = ISC_MIN(payload, total - offset);
		isc_buffer_putmem(env, src + offset, n);
		offset += n;
		result = fcache_add_fragment_buffer(fcache, key, keysize, i,
						    env);
		isc_buffer_free(&env);
		if (result != ISC_R_SUCCESS) {
			goto cleanup;
		}
	}
	INSIST(offset == total);
	RAW_LOG(ISC_LOG_DEBUG(5),
		"RAW: fragmented %u byte reply for %.*s into %u fragments "
		"(envelope %u, payload %u)",
		total, (int)keysize, key, nr_fragments, env_len, payload);
	SET_IF_NOT_NULL(nr_fragmentsp, nr_fragments);
	result = ISC_R_SUCCESS;

cleanup:
	if (result != ISC_R_SUCCESS && cached) {
		(void)fcache_remove(fcache, key, keysize);
	}
	if (full != NULL) {
		isc_buffer_free(&full);
	}
	return (result);
}

isc_result_t
raw_reassemble(isc_mem_t *mctx, const fragment_cache_entry_t *entry,
	       isc_buffer_t **outp) {
	REQUIRE(entry != NULL);
	REQUIRE(outp != NULL && *outp == NULL);

	if (!fcache_is_complete(entry)) {
		return (ISC_R_INPROGRESS);
	}

	isc_result_t result;
	unsigned offsets[FCACHE_MAX_FRAGMENTS];
	unsigned total = 0;

	for (unsigned i = 0; i < entry->nr_fragments; i++) {
		isc_region_t r;
		unsigned frag_nr, nr;
		isc_buffer_usedregion(entry->fragments[i], &r);
		result = raw_parse_envelope(&r, &frag_nr, &nr, &offsets[i]);
		if (result != ISC_R_SUCCESS || frag_nr != i ||
		    nr != entry->nr_fragments)
		{
			RAW_LOG(ISC_LOG_DEBUG(5),
				"RAW: fragment %u of %.*s is inconsistent "
				"(%s, nr %u/%u)",
				i, (int)entry->keysize, entry->key,
				isc_result_totext(result), frag_nr, nr);
			return (ISC_R_FAILURE);
		}
		total += r.length - offsets[i];
	}
	if (total < DNS_HEADER_SIZE) {
		return (ISC_R_FAILURE);
	}

	isc_buffer_t *out = NULL;
	isc_buffer_allocate(mctx, &out, total);
	for (unsigned i = 0; i < entry->nr_fragments; i++) {
		isc_region_t r;
		isc_buffer_usedregion(entry->fragments[i], &r);
		isc_buffer_putmem(out, r.base + offsets[i],
				  r.length - offsets[i]);
	}
	RAW_LOG(ISC_LOG_DEBUG(5), "RAW: reassembled %.*s from %u fragments "
				  "into %u bytes",
		(int)entry->keysize, entry->key, entry->nr_fragments, total);
	*outp = out;
	return (ISC_R_SUCCESS);
}
