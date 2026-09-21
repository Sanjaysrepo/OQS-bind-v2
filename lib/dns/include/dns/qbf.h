#pragma once 

#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <dns/message.h>
#include <dns/request.h>
#include <dns/fcache.h>
#include <dns/udp_fragmentation.h>
#include <dns/keyvalues.h>

#define RRSIG 46
#define DNSKEY 48
#define MAXUDP 1232

// fragments a given message msg
// first fragment is returned in msg
// remaining fragments are added to cache
// returns true if success, false otherwise
// TODO: currently has to pass through all rr's twice --> reduce to 1 pass
isc_result_t fragment(isc_mem_t *mctx, fcache_t *fcache, dns_message_t *msg, const char *client_address, const unsigned max_udp_size);


// reassembles a given entry into a new dns_message_t
// checks if all fragments are in the entry --> otherwise returns false
// returns:
//   ISC_R_SUCCESS if succesfully reassembled
//   ISC_R_INPROGRESS if not all fragments have been received yet
//   ISC_R_FAILURE if the fragments mismatch (for example, mismatching id)
isc_result_t reassemble_fragments(isc_mem_t *mctx, fcache_t *fcache, unsigned char *key, unsigned keysize, dns_message_t **out_msg);