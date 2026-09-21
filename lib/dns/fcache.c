#include <inttypes.h>
#include <stdio.h>

#include <isc/atomic.h>
#include <isc/buffer.h>
#include <isc/log.h>
#include <isc/loop.h>
#include <isc/mem.h>
#include <isc/result.h>
#include <isc/timer.h>
#include <isc/types.h>
#include <isc/util.h>

#include <dns/fcache.h>
#include <dns/log.h>

#define FCACHE_LOG(level, ...)                                            \
	isc_log_write(dns_lctx, DNS_LOGCATEGORY_FRAGMENTATION,            \
		      DNS_LOGMODULE_FCACHE, level, __VA_ARGS__)

#define FRAG_BIT(n) (UINT64_C(1) << (n))

/*
 * Internal helpers: the caller must hold fcache->lock.
 */

static void
entry_free(fcache_t *fcache, fragment_cache_entry_t *entry) {
	for (unsigned i = 0; i < entry->nr_fragments; i++) {
		if ((entry->bitmap & FRAG_BIT(i)) != 0 &&
		    entry->fragments[i] != NULL)
		{
			isc_buffer_free(&(entry->fragments[i]));
		}
	}
	isc_mem_put(fcache->mctx, entry->fragments,
		    entry->nr_fragments * sizeof(isc_buffer_t *));
	isc_mem_put(fcache->mctx, entry->key, entry->keysize);
	isc_mem_put(fcache->mctx, entry, sizeof(*entry));
}

static isc_result_t
entry_find(fcache_t *fcache, const unsigned char *key, unsigned keysize,
	   fragment_cache_entry_t **entryp) {
	return (isc_ht_find(fcache->ht, key, keysize, (void **)entryp));
}

/* unlinks + deletes from the hashtable, then frees */
static isc_result_t
entry_delete(fcache_t *fcache, fragment_cache_entry_t *entry) {
	isc_result_t result = isc_ht_delete(fcache->ht, entry->key,
					    entry->keysize);
	if (result != ISC_R_SUCCESS) {
		FCACHE_LOG(ISC_LOG_DEBUG(10),
			   "could not delete element with key %s", entry->key);
		return (ISC_R_FAILURE);
	}
	ISC_LIST_UNLINK(fcache->expiry_list, entry, link);
	entry_free(fcache, entry);
	return (ISC_R_SUCCESS);
}

static isc_result_t
entry_add_buffer(fcache_t *fcache, fragment_cache_entry_t *entry,
		 unsigned fragment_nr, const unsigned char *base,
		 unsigned length) {
	if (fragment_nr >= entry->nr_fragments) {
		FCACHE_LOG(ISC_LOG_DEBUG(10),
			   "fragment number %u out of range (nr_fragments %u)",
			   fragment_nr, entry->nr_fragments);
		return (ISC_R_RANGE);
	}
	/* overwrite an existing fragment */
	if ((entry->bitmap & FRAG_BIT(fragment_nr)) != 0) {
		isc_buffer_free(&(entry->fragments[fragment_nr]));
	}
	isc_buffer_t *copy = NULL;
	isc_buffer_allocate(fcache->mctx, &copy, length);
	isc_buffer_putmem(copy, base, length);
	entry->fragments[fragment_nr] = copy;
	entry->bitmap |= FRAG_BIT(fragment_nr);
	return (ISC_R_SUCCESS);
}

static bool
entry_complete(const fragment_cache_entry_t *entry) {
	uint64_t all = (entry->nr_fragments >= 64)
			       ? UINT64_MAX
			       : (FRAG_BIT(entry->nr_fragments) - 1);
	return ((entry->bitmap & all) == all);
}

/* timer callback: remove expired entries (list is ordered by expiry) */
static void
fcache_timer_cb(void *arg) {
	fcache_t *fcache = (fcache_t *)arg;
	isc_time_t now = isc_time_now();
	fragment_cache_entry_t *entry, *next;

	FCACHE_LOG(ISC_LOG_DEBUG(10), "running fragment cache expiry");
	LOCK(&fcache->lock);
	for (entry = ISC_LIST_HEAD(fcache->expiry_list); entry != NULL;
	     entry = next)
	{
		next = ISC_LIST_NEXT(entry, link);
		if (isc_time_compare(&entry->expiry, &now) > 0) {
			break; /* remaining entries are newer */
		}
		FCACHE_LOG(ISC_LOG_DEBUG(10), "expiring entry %s", entry->key);
		(void)entry_delete(fcache, entry);
	}
	UNLOCK(&fcache->lock);
}

void
fcache_init(fcache_t **fcachep, isc_loopmgr_t *loopmgr, unsigned ttl,
	    unsigned loop_timeout) {
	REQUIRE(fcachep != NULL && *fcachep == NULL);
	REQUIRE(ttl > 0);
	REQUIRE(loop_timeout > 0);

	FCACHE_LOG(ISC_LOG_DEBUG(10), "initializing fragment cache");

	isc_mem_t *mctx = NULL;
	isc_mem_create(&mctx);

	fcache_t *fcache = isc_mem_get(mctx, sizeof(*fcache));
	*fcache = (fcache_t){ .mctx = mctx, .loopmgr = loopmgr };
	isc_time_set(&fcache->ttl, ttl, 0);
	isc_time_set(&fcache->loop_timeout, loop_timeout, 0);
	isc_ht_init(&fcache->ht, fcache->mctx, 16, 0); /* case sensitive */
	ISC_LIST_INIT(fcache->expiry_list);
	isc_mutex_init(&fcache->lock);

	/*
	 * Without a loop manager (one-shot tools such as dig) there is no
	 * expiry timer: an active timer would keep the event loop alive.
	 */
	if (loopmgr != NULL) {
		isc_timer_create(isc_loop_current(loopmgr), fcache_timer_cb,
				 fcache, &fcache->expiry_timer);
		isc_timer_start(fcache->expiry_timer, isc_timertype_ticker,
				&fcache->loop_timeout);
	}
	*fcachep = fcache;
}

void
fcache_deinit(fcache_t **fcachep) {
	REQUIRE(fcachep != NULL && *fcachep != NULL);
	fcache_t *fcache = *fcachep;
	*fcachep = NULL;

	FCACHE_LOG(ISC_LOG_DEBUG(10), "deinitializing fragment cache");
	if (fcache->expiry_timer != NULL) {
		isc_timer_destroy(&fcache->expiry_timer);
	}
	fcache_purge(fcache);
	isc_ht_destroy(&fcache->ht);
	isc_mutex_destroy(&fcache->lock);
	isc_mem_putanddetach(&fcache->mctx, fcache, sizeof(*fcache));
}

isc_result_t
fcache_add(fcache_t *fcache, const unsigned char *key, unsigned keysize,
	   unsigned nr_fragments) {
	REQUIRE(fcache != NULL && key != NULL);
	if (nr_fragments == 0 || nr_fragments > FCACHE_MAX_FRAGMENTS) {
		return (ISC_R_RANGE);
	}

	FCACHE_LOG(ISC_LOG_DEBUG(10), "adding entry %.*s (%u fragments)",
		   (int)keysize, (const char *)key, nr_fragments);

	isc_result_t result;
	fragment_cache_entry_t *entry = NULL;

	LOCK(&fcache->lock);
	result = entry_find(fcache, key, keysize, &entry);
	if (result == ISC_R_SUCCESS) {
		result = ISC_R_EXISTS;
		goto unlock;
	}

	entry = isc_mem_get(fcache->mctx, sizeof(*entry));
	*entry = (fragment_cache_entry_t){ .nr_fragments = nr_fragments };
	entry->key = isc_mem_get(fcache->mctx, keysize);
	memcpy(entry->key, key, keysize);
	entry->keysize = keysize;
	entry->fragments = isc_mem_get(fcache->mctx,
				       nr_fragments * sizeof(isc_buffer_t *));
	memset(entry->fragments, 0, nr_fragments * sizeof(isc_buffer_t *));
	ISC_LINK_INIT(entry, link);

	isc_time_t now = isc_time_now();
	isc_time_add(&now, &fcache->ttl, &entry->expiry);

	result = isc_ht_add(fcache->ht, entry->key, keysize, entry);
	if (result != ISC_R_SUCCESS) {
		entry_free(fcache, entry);
		goto unlock;
	}
	ISC_LIST_APPEND(fcache->expiry_list, entry, link);
	result = ISC_R_SUCCESS;
unlock:
	UNLOCK(&fcache->lock);
	return (result);
}

isc_result_t
fcache_add_with_fragment(fcache_t *fcache, const unsigned char *key,
			 unsigned keysize, dns_message_t *frag,
			 unsigned nr_fragments) {
	isc_result_t result = fcache_add(fcache, key, keysize, nr_fragments);
	if (result == ISC_R_SUCCESS) {
		return (fcache_add_fragment(fcache, key, keysize, frag));
	}
	return (result);
}

isc_result_t
fcache_add_fragment_with_entry(fcache_t *fcache, fragment_cache_entry_t *entry,
			       dns_message_t *frag) {
	REQUIRE(frag != NULL &&
		(frag->buffer != NULL || frag->saved.base != NULL));

	if (frag->buffer != NULL) {
		return (entry_add_buffer(fcache, entry, frag->fragment_nr,
					 isc_buffer_base(frag->buffer),
					 isc_buffer_usedlength(frag->buffer)));
	}
	return (entry_add_buffer(fcache, entry, frag->fragment_nr,
				 frag->saved.base, frag->saved.length));
}

isc_result_t
fcache_add_fragment(fcache_t *fcache, const unsigned char *key,
		    unsigned keysize, dns_message_t *frag) {
	REQUIRE(frag != NULL);
	isc_result_t result;
	fragment_cache_entry_t *entry = NULL;

	LOCK(&fcache->lock);
	result = entry_find(fcache, key, keysize, &entry);
	if (result == ISC_R_SUCCESS) {
		result = fcache_add_fragment_with_entry(fcache, entry, frag);
	} else {
		result = ISC_R_NOTFOUND;
	}
	UNLOCK(&fcache->lock);
	return (result);
}

isc_result_t
fcache_add_fragment_buffer(fcache_t *fcache, const unsigned char *key,
			   unsigned keysize, unsigned fragment_nr,
			   const isc_buffer_t *buf) {
	REQUIRE(buf != NULL);
	isc_result_t result;
	fragment_cache_entry_t *entry = NULL;

	LOCK(&fcache->lock);
	result = entry_find(fcache, key, keysize, &entry);
	if (result == ISC_R_SUCCESS) {
		result = entry_add_buffer(fcache, entry, fragment_nr,
					  isc_buffer_base(buf),
					  isc_buffer_usedlength(buf));
	} else {
		result = ISC_R_NOTFOUND;
	}
	UNLOCK(&fcache->lock);
	return (result);
}

isc_result_t
fcache_remove(fcache_t *fcache, const unsigned char *key, unsigned keysize) {
	isc_result_t result;
	fragment_cache_entry_t *entry = NULL;

	FCACHE_LOG(ISC_LOG_DEBUG(10), "removing entry %.*s", (int)keysize,
		   (const char *)key);
	LOCK(&fcache->lock);
	result = entry_find(fcache, key, keysize, &entry);
	if (result == ISC_R_SUCCESS) {
		result = entry_delete(fcache, entry);
	} else {
		result = ISC_R_NOTFOUND;
	}
	UNLOCK(&fcache->lock);
	return (result);
}

isc_result_t
fcache_remove_fragment(fcache_t *fcache, const unsigned char *key,
		       unsigned keysize, unsigned fragment_nr) {
	isc_result_t result;
	fragment_cache_entry_t *entry = NULL;

	LOCK(&fcache->lock);
	result = entry_find(fcache, key, keysize, &entry);
	if (result == ISC_R_SUCCESS) {
		if (fragment_nr < entry->nr_fragments &&
		    (entry->bitmap & FRAG_BIT(fragment_nr)) != 0)
		{
			isc_buffer_free(&(entry->fragments[fragment_nr]));
			entry->bitmap &= ~FRAG_BIT(fragment_nr);
			result = ISC_R_SUCCESS;
		} else {
			result = ISC_R_NOTFOUND;
		}
	} else {
		result = ISC_R_NOTFOUND;
	}
	UNLOCK(&fcache->lock);
	return (result);
}

isc_result_t
fcache_get(fcache_t *fcache, const unsigned char *key, unsigned keysize,
	   fragment_cache_entry_t **out_cache_entry) {
	REQUIRE(out_cache_entry != NULL && *out_cache_entry == NULL);
	isc_result_t result;

	LOCK(&fcache->lock);
	result = entry_find(fcache, key, keysize, out_cache_entry);
	UNLOCK(&fcache->lock);
	return (result == ISC_R_SUCCESS ? ISC_R_SUCCESS : ISC_R_NOTFOUND);
}

isc_result_t
fcache_get_fragment_from_entry(fragment_cache_entry_t *entry,
			       unsigned fragment_nr, isc_buffer_t **out_frag) {
	REQUIRE(entry != NULL && out_frag != NULL);
	if (fragment_nr < entry->nr_fragments &&
	    (entry->bitmap & FRAG_BIT(fragment_nr)) != 0)
	{
		*out_frag = entry->fragments[fragment_nr];
		isc_buffer_first(*out_frag);
		return (ISC_R_SUCCESS);
	}
	FCACHE_LOG(ISC_LOG_DEBUG(10), "fragment %u not present", fragment_nr);
	return (ISC_R_NOTFOUND);
}

isc_result_t
fcache_get_fragment(fcache_t *fcache, const unsigned char *key,
		    unsigned keysize, unsigned fragment_nr,
		    isc_buffer_t **out_frag) {
	isc_result_t result;
	fragment_cache_entry_t *entry = NULL;

	LOCK(&fcache->lock);
	result = entry_find(fcache, key, keysize, &entry);
	if (result == ISC_R_SUCCESS) {
		result = fcache_get_fragment_from_entry(entry, fragment_nr,
							out_frag);
	} else {
		FCACHE_LOG(ISC_LOG_DEBUG(10), "entry %.*s not found",
			   (int)keysize, (const char *)key);
		result = ISC_R_NOTFOUND;
	}
	UNLOCK(&fcache->lock);
	return (result);
}

bool
fcache_is_complete(const fragment_cache_entry_t *entry) {
	REQUIRE(entry != NULL);
	return (entry_complete(entry));
}

isc_result_t
fcache_take_complete(fcache_t *fcache, const unsigned char *key,
		     unsigned keysize, fragment_cache_entry_t **entryp) {
	REQUIRE(entryp != NULL && *entryp == NULL);
	isc_result_t result;
	fragment_cache_entry_t *entry = NULL;

	LOCK(&fcache->lock);
	result = entry_find(fcache, key, keysize, &entry);
	if (result != ISC_R_SUCCESS) {
		result = ISC_R_NOTFOUND;
	} else if (!entry_complete(entry)) {
		result = ISC_R_INPROGRESS;
	} else {
		result = isc_ht_delete(fcache->ht, entry->key, entry->keysize);
		INSIST(result == ISC_R_SUCCESS);
		ISC_LIST_UNLINK(fcache->expiry_list, entry, link);
		*entryp = entry;
	}
	UNLOCK(&fcache->lock);
	return (result);
}

void
fcache_free_taken_entry(fcache_t *fcache, fragment_cache_entry_t *entry) {
	REQUIRE(entry != NULL && !ISC_LINK_LINKED(entry, link));
	entry_free(fcache, entry);
}

isc_result_t
fcache_purge(fcache_t *fcache) {
	fragment_cache_entry_t *entry, *next;

	FCACHE_LOG(ISC_LOG_DEBUG(10), "purging fragment cache");
	LOCK(&fcache->lock);
	for (entry = ISC_LIST_HEAD(fcache->expiry_list); entry != NULL;
	     entry = next)
	{
		next = ISC_LIST_NEXT(entry, link);
		(void)entry_delete(fcache, entry);
	}
	UNLOCK(&fcache->lock);
	return (ISC_R_SUCCESS);
}

unsigned
fcache_count(fcache_t *fcache) {
	LOCK(&fcache->lock);
	unsigned n = isc_ht_count(fcache->ht);
	UNLOCK(&fcache->lock);
	return (n);
}

bool
fcache_exists(fcache_t *fcache, const unsigned char *key, unsigned keysize) {
	fragment_cache_entry_t *entry = NULL;
	LOCK(&fcache->lock);
	bool found = (entry_find(fcache, key, keysize, &entry) ==
		      ISC_R_SUCCESS);
	UNLOCK(&fcache->lock);
	return (found);
}

void
fcache_free_entry(fcache_t *fcache, fragment_cache_entry_t *entry) {
	ISC_LIST_UNLINK(fcache->expiry_list, entry, link);
	entry_free(fcache, entry);
}
