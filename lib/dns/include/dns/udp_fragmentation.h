#pragma once 

#include <string.h>
#include <isc/buffer.h>
#include <isc/mem.h>
#include <isc/result.h>
#include <isc/types.h>
#include <isc/util.h>
#include <dns/message.h>
#include <dns/name.h>
#include <dns/rdata.h>
#include <dns/rdatalist.h>
#include <dns/rdataset.h>
#include <dns/types.h>

/*
udp_fragmentation.h contains all code related to UDP fragmentation for large DNS messages.
It handles basic functionality that is shared between UDP fragmentation algorithms.
Algorithm specific code are in:
1. qbf.h and qbf.c for QBF
2. raw.h and raw.c for RAW
*/

#define OPTION_CODE 22
#define OPTION_LENGTH 2

#define is_fragment_qname(a, b) is__fragment_qname(a, b, true) 
#define is_fragment_qname_noforce(a, b) is__fragment_qname(a, b, false) 
// checks if msg is a fragment
// expected format: ?fragment_nr?name
// sets the fragment number for msg if fragment
// if force is set, the logic re-checks the msg regardless if msg->is_fragment is true
bool is__fragment_qname(isc_mem_t *mctx, dns_message_t *msg, bool force);

// checks if a message is a fragment based on whether the OPT record has option 22 set
isc_result_t is_fragment_opt(dns_message_t *msg);

#define create_fragment_opt(a, b, c, d) create__fragment_opt(a, b, c, d, false) 
#define delete_fragment_opt(a) create__fragment_opt(a, 0, 1, 0, true) 
// appends a new option to the opt record in msg
// if no opt record exists, it will be added
isc_result_t create__fragment_opt(dns_message_t *msg, const unsigned frag_nr, const unsigned nr_fragments, const unsigned fragment_flags, bool skip);

// determines how many options a given msg->opt record has and what the overall size is
// returns ISC_R_FAILURE if it is malformed (should not happen)
isc_result_t parse_opt(dns_message_t *msg, unsigned *opt_size, unsigned *nr_options);

// key = id + client ip:port
// overwrites keysize to match the string length
void fcache_create_key(dns_messageid_t id, const char *client_address, unsigned char *key, unsigned *keysize);

// DNSKEY header: 2 (Flags) + 1 (Protocol) + 1 (Algorithm) = 4 Bytes
unsigned calc_dnskey_header_size(void);

// calculates the size of a name
unsigned calc_name_size(unsigned char *base, unsigned length);

// RRSIG header: 2 (Type Covered) + 1 (Algorithm) + 1 (Labels) + 4 (TTL) + 4 (Expiration) + 4 (Inception) + 2 (Key Tag) + x (Signer Name) = 18 + x
unsigned calc_rrsig_header_size(dns_rdata_t *rdata);

// create a query from a dns message buffer using qname
// LEGACY: please use the OPT-based aproach
// returns ISC_R_SUCCESS if a query was created
// NOTE: can be optimized (e.g. remove parsing):
// 1. peek at header to determine flags and id
// 2. peek at query/question to get name
// 3. construct question section 
// 4. construct OPT --> use default values
isc_result_t create_fragment_query_qname(isc_mem_t *mctx, isc_buffer_t *buffer, uint fragment_nr, isc_buffer_t **question_buffer);
// uses OPT record instead of qname
isc_result_t create_fragment_query_opt(isc_mem_t *mctx, isc_buffer_t *buffer, uint fragment_nr, uint nr_fragments, isc_buffer_t **question_buffer);

// prints the dns message in a human-readable format
void printmessage(isc_mem_t *mctx, dns_message_t *msg);


isc_result_t section_clone(dns_message_t *source, dns_message_t *target, const unsigned section);

// renders a fragment: 
// allocates msg_size bytes 
// for fragments usually 1232
// for complete messages number of fragments * 1232
// TODO:
// 1. Better error handling
// 2. Return proper result
// 3. Fix issue with TC flag
isc_result_t render_fragment(isc_mem_t *mctx, unsigned msg_size, dns_message_t **messagep);
