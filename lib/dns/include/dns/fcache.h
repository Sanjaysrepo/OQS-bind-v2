#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <isc/buffer.h>
#include <isc/ht.h>
#include <isc/job.h>
#include <isc/loop.h>
#include <isc/mem.h>
#include <isc/mutex.h>
#include <isc/result.h>
#include <isc/time.h>
#include <isc/timer.h>
#include <isc/types.h>
#include <isc/util.h>

#include <dns/message.h>

/*
------------------------------------------------------------------------------------
FRAGMENT CACHING
------------------------------------------------------------------------------------
Author: Folmer Heikamp
Year: 2025

We utilize the ISC hash table to store fragments.
Hashtable key: transaction id + address (see fcache_create_key()).
A ticker timer periodically removes expired entries.
All public functions take fcache->lock; the *_with_entry / *_from_entry
variants operate on an entry pointer and do NOT lock, so callers that use
them must be the only ones touching that entry (e.g. an entry obtained from
fcache_take_complete()).

Notes:
1. To prevent collisions we can include hash(qname + qtype) in the key (TODO)
*/

/* Hard limit: the bitmap is 64 bits wide. */
#define FCACHE_MAX_FRAGMENTS 64

typedef struct fragment_cache_entry {
	unsigned char *key; /* copy of the key (needed by the timer callback) */
	unsigned keysize;
	isc_time_t expiry;	  /* absolute time when this entry expires */
	uint8_t nr_fragments;	  /* total fragments in response */
	uint64_t bitmap;	  /* bitmask of received fragments */
	isc_buffer_t **fragments; /* raw datagrams, one per fragment */
	LINK(struct fragment_cache_entry) link; /* expiration list */
} fragment_cache_entry_t;

typedef ISC_LIST(fragment_cache_entry_t) fragmentlist_t;

typedef struct fcache {
	isc_mutex_t lock;
	isc_mem_t *mctx;
	isc_loopmgr_t *loopmgr;
	isc_ht_t *ht;		    /* fragment hashtable */
	fragmentlist_t expiry_list; /* entries ordered by expiry time */
	isc_timer_t *expiry_timer;  /* ticker that expires entries */
	isc_time_t ttl;		    /* lifetime of a cache entry */
	isc_time_t loop_timeout;    /* ticker interval */
} fcache_t;

/*
 * initializes the fcache object; ttl and loop_timeout are in seconds.
 * loopmgr may be NULL: then no expiry timer runs (entries never expire).
 */
void
fcache_init(fcache_t **fcache, isc_loopmgr_t *loopmgr, unsigned ttl,
	    unsigned loop_timeout);

/* destroys the timer and frees everything */
void
fcache_deinit(fcache_t **fcache);

/*
 * creates a new cache entry if it does not exist.
 * returns:
 *   ISC_R_SUCCESS if added
 *   ISC_R_EXISTS  if an entry with this key already exists
 *   ISC_R_RANGE   if nr_fragments is 0 or > FCACHE_MAX_FRAGMENTS
 */
isc_result_t
fcache_add(fcache_t *fcache, const unsigned char *key, unsigned keysize,
	   unsigned nr_fragments);

/* fcache_add() followed by fcache_add_fragment() */
isc_result_t
fcache_add_with_fragment(fcache_t *fcache, const unsigned char *key,
			 unsigned keysize, dns_message_t *frag,
			 unsigned nr_fragments);

/*
 * adds a fragment (copied from frag->buffer or frag->saved) to an entry.
 * returns:
 *   ISC_R_RANGE    if frag->fragment_nr >= nr_fragments
 *   ISC_R_NOTFOUND if no entry is found
 *   ISC_R_SUCCESS  if successful (an existing fragment is overwritten)
 */
isc_result_t
fcache_add_fragment_with_entry(fcache_t *fcache, fragment_cache_entry_t *entry,
			       dns_message_t *frag);
isc_result_t
fcache_add_fragment(fcache_t *fcache, const unsigned char *key,
		    unsigned keysize, dns_message_t *frag);

/* same as fcache_add_fragment() but takes the raw datagram directly */
isc_result_t
fcache_add_fragment_buffer(fcache_t *fcache, const unsigned char *key,
			   unsigned keysize, unsigned fragment_nr,
			   const isc_buffer_t *buf);

/*
 * removes a cache entry
 * returns ISC_R_SUCCESS, or ISC_R_NOTFOUND if not found
 */
isc_result_t
fcache_remove(fcache_t *fcache, const unsigned char *key, unsigned keysize);

/* removes a single fragment; ISC_R_NOTFOUND if entry or fragment missing */
isc_result_t
fcache_remove_fragment(fcache_t *fcache, const unsigned char *key,
		       unsigned keysize, unsigned fragment_nr);

/*
 * looks up a cache entry. NOTE: the entry remains owned by the cache and
 * may be expired by the timer; prefer fcache_take_complete() when the
 * entry is going to be used for reassembly.
 * returns ISC_R_SUCCESS or ISC_R_NOTFOUND
 */
isc_result_t
fcache_get(fcache_t *fcache, const unsigned char *key, unsigned keysize,
	   fragment_cache_entry_t **out_cache_entry);

/* returns the fragment buffer; ISC_R_NOTFOUND if not present */
isc_result_t
fcache_get_fragment_from_entry(fragment_cache_entry_t *entry,
			       unsigned fragment_nr, isc_buffer_t **out_frag);
isc_result_t
fcache_get_fragment(fcache_t *fcache, const unsigned char *key,
		    unsigned keysize, unsigned fragment_nr,
		    isc_buffer_t **out_frag);

/* true when every fragment 0..nr_fragments-1 is present */
bool
fcache_is_complete(const fragment_cache_entry_t *entry);

/*
 * if the entry is complete, removes it from the cache and hands ownership
 * to the caller (free it with fcache_free_taken_entry()).
 * returns:
 *   ISC_R_SUCCESS    entry complete and returned in *entryp
 *   ISC_R_INPROGRESS entry exists but fragments are missing
 *   ISC_R_NOTFOUND   no such entry
 */
isc_result_t
fcache_take_complete(fcache_t *fcache, const unsigned char *key,
		     unsigned keysize, fragment_cache_entry_t **entryp);
void
fcache_free_taken_entry(fcache_t *fcache, fragment_cache_entry_t *entry);

/* removes all entries */
isc_result_t
fcache_purge(fcache_t *fcache);

/* number of entries in the cache */
unsigned
fcache_count(fcache_t *fcache);

bool
fcache_exists(fcache_t *fcache, const unsigned char *key, unsigned keysize);

/*
 * frees an entry that is still linked in the expiry list (but has already
 * been deleted from the hash table). Does not lock.
 */
void
fcache_free_entry(fcache_t *fcache, fragment_cache_entry_t *entry);
