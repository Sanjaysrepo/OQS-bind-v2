/*
 * QBF UDP fragmentation (see also dns/qbf.h and dns/udp_fragmentation.h).
 *
 * QBF splits only the RDATA of DNSKEY and RRSIG records: every fragment
 * is a complete, parseable DNS reply that carries the same RR skeleton
 * as the original but only a proportional share of each key/signature
 * body.  Fragments are marked with the TC flag and EDNS option 22; the
 * resolver requests fragment N with a ?N?qname query and reassembly
 * (reassemble_fragments) walks the original and the fragment in
 * lockstep, appending the body bytes back together.
 *
 * fragment() works in two passes per fragment:
 *   pass 1 renders a "skeleton" fragment (everything except the
 *          DNSKEY/RRSIG bodies) only to measure how many bytes of
 *          key/signature data still fit in the datagram;
 *   pass 2 builds the real fragment with that many body bytes,
 *          distributed across the records in proportion to their size.
 * The finished fragments are stored in the fragment cache (dns/fcache.h)
 * and served from ns_client_send().
 */
#include <math.h>
#include <stdint.h>
#include <stdlib.h>
#include <isc/buffer.h>
#include <isc/list.h>
#include <isc/mem.h>
#include <isc/result.h>
#include <isc/types.h>
#include <isc/util.h>
#include <dns/compress.h>
#include <dns/enumtype.h>
#include <dns/message.h>
#include <dns/name.h>
#include <dns/rdatalist.h>
#include <dns/types.h>
#include <dns/rdata.h>
#include <dns/rdataset.h>
#include <dns/qbf.h>


isc_result_t fragment(isc_mem_t *mctx, fcache_t *fcache, dns_message_t *msg, const char *client_address, const unsigned max_udp_size) {
    REQUIRE(msg != NULL);
    REQUIRE(mctx != NULL);
    REQUIRE(DNS_MESSAGE_VALID(msg));

    // create cache key
    unsigned char key[69];
    unsigned keysize = sizeof(key) / sizeof(key[0]);
    fcache_create_key(msg->id, client_address, key, &keysize);

    // create an fcache entry
    if (fcache_exists(fcache, key, keysize)) {
        isc_log_write(dns_lctx, DNS_LOGCATEGORY_FRAGMENTATION, DNS_LOGMODULE_FRAGMENT, ISC_LOG_DEBUG(8),
                "Cannot fragment response because it is already fragmented!");  
        return ISC_R_EXISTS;        
    }

    dns_name_t *name = NULL;
    unsigned fragment_nr = 0;
    bool done = false;
    unsigned offsets[64] = {0};
    dns_message_t *frags[64] = {NULL}; // we need to pre-store because we don't know the number of fragments yet
    isc_result_t result;

    // add second clause to prevent infinite loops
    while (!done && fragment_nr < 64) {

        // pre-render:
        // for first fragment: render all except the RDATA of the DNSKEY's and RRSIG records
        // for other fragments: render question, opt, and headers of the RDATA and DNSKEY records
        dns_message_create(mctx, DNS_MESSAGE_INTENTRENDER, &(frags[fragment_nr]));

        // set metadata
        frags[fragment_nr]->id = msg->id;
        frags[fragment_nr]->flags = msg->flags;
        frags[fragment_nr]->rcode = msg->rcode;
        frags[fragment_nr]->opcode = msg->opcode;
        frags[fragment_nr]->rdclass = msg->rdclass;
        // set fragmentation metadata
        frags[fragment_nr]->is_fragment = true;
        frags[fragment_nr]->fragment_nr = fragment_nr;

        unsigned total_sig_pk_bytes = 0;
        for (unsigned section_nr = 0; section_nr < DNS_SECTION_MAX; section_nr++) {
                for (isc_result_t name_result = dns_message_firstname(msg, section_nr); name_result == ISC_R_SUCCESS;  name_result = dns_message_nextname(msg, section_nr)) {
                    name = NULL;
                    dns_message_currentname(msg, section_nr, &name);
                    dns_name_t *new_name = NULL;
                    dns_message_gettempname(frags[fragment_nr], &new_name);
                    dns_name_copy(name, new_name);

                    for (dns_rdataset_t *rdataset = ISC_LIST_HEAD(name->list); rdataset != NULL; rdataset = ISC_LIST_NEXT(rdataset, link)) {
                        dns_rdataset_t *new_rdataset = NULL;
                        dns_message_gettemprdataset(frags[fragment_nr], &new_rdataset);
                        dns_rdatalist_t *rdatalist = NULL;
                        dns_message_gettemprdatalist(frags[fragment_nr], &rdatalist);

                        // copy values
                        rdatalist->rdclass = rdataset->rdclass;
                        rdatalist->type = rdataset->type;
                        rdatalist->ttl = rdataset->ttl;

                        for (isc_result_t rdata_result = dns_rdataset_first(rdataset); rdata_result == ISC_R_SUCCESS; rdata_result = dns_rdataset_next(rdataset)) {
                            // get current rdata
                            dns_rdata_t rdata = DNS_RDATA_INIT;
                            dns_rdataset_current(rdataset, &rdata);
                            isc_region_t rdata_region;
                            dns_rdata_toregion(&rdata, &rdata_region);

                            // prepare new rdata
                            dns_rdata_t *new_rdata = NULL;
                            dns_message_gettemprdata(frags[fragment_nr], &new_rdata);
                            isc_region_t new_rdata_region;

                            if (rdata.type == DNSKEY || rdata.type == RRSIG) {
                                // at the moment, we include the RRSIG and DNSKEY header in all messages
                                // this is not strictly necessary but ensures that each fragment is well-formed
                                unsigned header_size = 0;
                                if(rdata.type == DNSKEY) {
                                    header_size = calc_dnskey_header_size();
                                }
                                // RRSIG
                                else {
                                    header_size = calc_rrsig_header_size(&rdata);
                                }
                                unsigned rdsize_no_header = rdata.length - header_size; 
                                total_sig_pk_bytes += rdsize_no_header;
                                // create a new RDATA with just the header
                                isc_buffer_t *buf = NULL;
                                isc_buffer_allocate(mctx, &buf, header_size); // allocate
                                isc_buffer_putmem(buf, rdata_region.base, header_size); // copy rdata header
                                isc_buffer_usedregion(buf, &new_rdata_region); 
                                dns_rdata_fromregion(new_rdata, rdata.rdclass, rdata.type, &new_rdata_region); // create new rdata
                                dns_message_takebuffer(msg, &buf);
                                ISC_LIST_APPEND(rdatalist->rdata, new_rdata, link); // append to list
                            }
                            else if (fragment_nr == 0) {
                                isc_buffer_t *buf = NULL;
                                isc_buffer_allocate(mctx, &buf, rdata_region.length); // allocate
                                isc_buffer_putmem(buf, rdata_region.base, rdata_region.length); // copy rdata
                                isc_buffer_usedregion(buf, &new_rdata_region); 
                                dns_rdata_fromregion(new_rdata, rdata.rdclass, rdata.type, &new_rdata_region); // create new rdata
                                REQUIRE(new_rdata_region.length == rdata_region.length);
                                dns_message_takebuffer(msg, &buf);
                                ISC_LIST_APPEND(rdatalist->rdata, new_rdata, link);
                            }
                        }
                        // convert to rdataset and link to new name
                        dns_rdatalist_tordataset(rdatalist, new_rdataset);
                        new_rdataset->attributes = rdataset->attributes; 
                        new_rdataset->attributes &= ~DNS_RDATASETATTR_RENDERED; // reset this flag to render
                        ISC_LIST_APPEND(new_name->list, new_rdataset, link);
                        REQUIRE(DNS_RDATASET_VALID(new_rdataset));
                    }
                    dns_message_addname(frags[fragment_nr], new_name, section_nr);
                }
        }
        //if (msg->opt != NULL) {
	    //    dns_rdataset_t *opt = NULL;
        //    dns_message_gettemprdataset(frags[fragment_nr], &opt);
        //    dns_rdataset_clone(msg->opt, opt);
        //    dns_message_setopt(frags[fragment_nr], opt);
        //}
        result = create_fragment_opt(frags[fragment_nr], fragment_nr, 64, 0);
        if (result != ISC_R_SUCCESS) {
            isc_log_write(dns_lctx, DNS_LOGCATEGORY_FRAGMENTATION, DNS_LOGMODULE_FRAGMENT, ISC_LOG_DEBUG(8),
                "Could not set OPT, return code %d!", result);
            goto cleanup;
        }

	    REQUIRE(DNS_MESSAGE_VALID(frags[fragment_nr]));
        result = render_fragment(mctx, max_udp_size, &(frags[fragment_nr])); 
        if (result != ISC_R_SUCCESS) {
            isc_log_write(dns_lctx, DNS_LOGCATEGORY_FRAGMENTATION, DNS_LOGMODULE_FRAGMENT, ISC_LOG_DEBUG(8),
                "Pre-parsing unsuccesful, return code %d!", result);  
            goto cleanup;
        }
        // check if it fits within the packet
        //printf("DNSMessage does not need UDP fragmentation: total_sig_pk_bytes: %u, msg_size: %u, max_udp_size: %u!\n",
        //            total_sig_pk_bytes, frags[fragment_nr]->buffer->used, max_udp_size);
        if (fragment_nr == 0 && total_sig_pk_bytes + frags[fragment_nr]->buffer->used <= max_udp_size) {
            isc_log_write(dns_lctx, DNS_LOGCATEGORY_FRAGMENTATION, DNS_LOGMODULE_FRAGMENT, ISC_LOG_DEBUG(8),
                    "DNSMessage does not need UDP fragmentation: total_sig_pk_bytes: %u, msg_size: %u, max_udp_size: %u!",
                    total_sig_pk_bytes, frags[fragment_nr]->buffer->used, max_udp_size);  
            result = ISC_R_RANGE;
            goto cleanup;
        } 

        // add RDATA and render
        // we already have the fragment set up, now we need to change the RDATA
        unsigned bytes_available = max_udp_size - frags[fragment_nr]->buffer->used;
        // reset fragment since we only needed it for an accurate size
        dns_message_detach(&(frags[fragment_nr]));        
        frags[fragment_nr] = NULL;
        dns_message_create(mctx, DNS_MESSAGE_INTENTRENDER, &(frags[fragment_nr]));
        // set metadata
        frags[fragment_nr]->id = msg->id;
        frags[fragment_nr]->flags = msg->flags;
        frags[fragment_nr]->rcode = msg->rcode;
        frags[fragment_nr]->opcode = msg->opcode;
        frags[fragment_nr]->rdclass = msg->rdclass;
        // set fragmentation metadata
        frags[fragment_nr]->is_fragment = true;
        frags[fragment_nr]->fragment_nr = fragment_nr;

        double remainder = 0.0, tmp;
        done = true;
        unsigned counter = 0; // note, we assume that the order is always the same!
        for (unsigned section_nr = 0; section_nr < DNS_SECTION_MAX; section_nr++) {
                for (isc_result_t name_result = dns_message_firstname(msg, section_nr); name_result == ISC_R_SUCCESS;  name_result = dns_message_nextname(msg, section_nr)) {
                    name = NULL;
                    dns_message_currentname(msg, section_nr, &name);
                    dns_name_t *new_name = NULL;
                    dns_message_gettempname(frags[fragment_nr], &new_name);
                    dns_name_copy(name, new_name);
                    for (dns_rdataset_t *rdataset = ISC_LIST_HEAD(name->list); rdataset != NULL; rdataset = ISC_LIST_NEXT(rdataset, link)) {
                        dns_rdataset_t *new_rdataset = NULL;
                        dns_message_gettemprdataset(frags[fragment_nr], &new_rdataset);
                        dns_rdatalist_t *rdatalist = NULL;
                        dns_message_gettemprdatalist(frags[fragment_nr], &rdatalist);

                        // copy values
                        rdatalist->rdclass = rdataset->rdclass;
                        rdatalist->type = rdataset->type;
                        rdatalist->ttl = rdataset->ttl;
                        for (isc_result_t rdata_result = dns_rdataset_first(rdataset); rdata_result == ISC_R_SUCCESS; rdata_result = dns_rdataset_next(rdataset)) {
                            // get current rdata
                            dns_rdata_t rdata = DNS_RDATA_INIT;
                            dns_rdataset_current(rdataset, &rdata);
                            isc_region_t rdata_region;
                            dns_rdata_toregion(&rdata, &rdata_region);

                            // prepare new rdata
                            dns_rdata_t *new_rdata = NULL;
                            dns_message_gettemprdata(frags[fragment_nr], &new_rdata);
                            isc_region_t new_rdata_region;

                            if (rdata.type == DNSKEY || rdata.type == RRSIG) {
                                unsigned header_size = 0;
                                if(rdata.type == DNSKEY) {
                                    header_size = calc_dnskey_header_size();
                                }
                                // RRSIG
                                else {
                                    header_size = calc_rrsig_header_size(&rdata);
                                }
                                unsigned rdsize_no_header = rdata.length - header_size; 
                                REQUIRE(offsets[counter] <= rdsize_no_header);
                                // calculate the fraction and spend that much based on how much you can send
                                unsigned new_rdata_len = ((double)rdsize_no_header / total_sig_pk_bytes) * bytes_available;
                                remainder += modf(new_rdata_len, &tmp);

                                // we can add a new byte!
                                if (remainder >= 1) {
                                    new_rdata_len++;
                                    remainder--;
                                }

                                // this rdata is completed
                                if (offsets[counter] + new_rdata_len >= rdsize_no_header) {
                                    new_rdata_len = rdsize_no_header - offsets[counter];
                                }
                                else  {
                                    done = false;
                                }
                                if (offsets[counter] < rdsize_no_header) {
                                    isc_buffer_t *buf = NULL;
                                    isc_buffer_allocate(mctx, &buf, new_rdata_len + header_size); // allocate
                                    isc_buffer_putmem(buf, rdata_region.base, header_size); // copy rdata header
                                    isc_buffer_putmem(buf, rdata_region.base + header_size + offsets[counter], new_rdata_len); // copy rdata data
                                    isc_buffer_usedregion(buf, &new_rdata_region); 
                                    dns_rdata_fromregion(new_rdata, rdata.rdclass, rdata.type, &new_rdata_region); // create new rdata
                                    REQUIRE(new_rdata_region.length == new_rdata_len + header_size);
                                    dns_message_takebuffer(msg, &buf);
                                    ISC_LIST_APPEND(rdatalist->rdata, new_rdata, link); // append to list
                                    offsets[counter] += new_rdata_len;
                                }

                                counter++;
                            }
                            else if (fragment_nr == 0) {
                                isc_buffer_t *buf = NULL;
                                isc_buffer_allocate(mctx, &buf, rdata_region.length); // allocate
                                isc_buffer_putmem(buf, rdata_region.base, rdata_region.length); // copy rdata
                                isc_buffer_usedregion(buf, &new_rdata_region); 
                                dns_rdata_fromregion(new_rdata, rdata.rdclass, rdata.type, &new_rdata_region); // create new rdata
                                REQUIRE(new_rdata_region.length == rdata_region.length);
                                dns_message_takebuffer(msg, &buf);
                                ISC_LIST_APPEND(rdatalist->rdata, new_rdata, link);
                            }
                        }
                        // convert to rdataset and link to new name
                        dns_rdatalist_tordataset(rdatalist, new_rdataset);
                        new_rdataset->attributes = rdataset->attributes; 
                        new_rdataset->attributes &= ~DNS_RDATASETATTR_RENDERED; // reset this flag to render
                        ISC_LIST_APPEND(new_name->list, new_rdataset, link);
                        REQUIRE(DNS_RDATASET_VALID(new_rdataset));
                    }
                    dns_message_addname(frags[fragment_nr], new_name, section_nr);
                }
        }        
        fragment_nr++;
    }
    unsigned nr_fragments = fragment_nr;
    REQUIRE(nr_fragments != 64); // should not happen
    // add all fragments to fcache
    result = fcache_add(fcache, key, keysize, nr_fragments);
    if (result != ISC_R_SUCCESS) {
        isc_log_write(dns_lctx, DNS_LOGCATEGORY_FRAGMENTATION, DNS_LOGMODULE_FRAGMENT, ISC_LOG_DEBUG(8),
            "Could not create a fragment entry in cache...");
        goto cleanup;
    }
    for(unsigned i = 0; i < nr_fragments; i++) {
        // first create the OPT record now we know the nr of fragments
        result = create_fragment_opt(frags[i], i, nr_fragments, 0);
        if (result != ISC_R_SUCCESS) {
            isc_log_write(dns_lctx, DNS_LOGCATEGORY_FRAGMENTATION, DNS_LOGMODULE_FRAGMENT, ISC_LOG_DEBUG(8),
                "Could not add OPT record, result: %d...", result);
            goto cleanup;
        }
        // render complete fragment
        result = render_fragment(mctx, max_udp_size + 100, &(frags[i])); 
        REQUIRE(frags[i]->buffer->used <= max_udp_size);
        if (result != ISC_R_SUCCESS) {
            isc_log_write(dns_lctx, DNS_LOGCATEGORY_FRAGMENTATION, DNS_LOGMODULE_FRAGMENT, ISC_LOG_DEBUG(8),
                "Could not render fragment, result: %d...", result);
            goto cleanup;
        }
        // add fragment and detach
        result = fcache_add_fragment(fcache, key, keysize, frags[i]);
        if (result != ISC_R_SUCCESS) { 
            isc_log_write(dns_lctx, DNS_LOGCATEGORY_FRAGMENTATION, DNS_LOGMODULE_FRAGMENT, ISC_LOG_DEBUG(8),
                "Could not add fragment to cache...");
            goto cleanup;
        }
    }
    result = ISC_R_SUCCESS;
cleanup:
    for(unsigned i = 0; i < fragment_nr; i++) {
        if(frags[i] != NULL) {
            dns_message_detach(&(frags[i]));     
        }
    }
    return result;
}

// reassembles the complete message from cache
// assumption: cache contains all fragments
// assumption: size of fragments should add up to size specified in entry
isc_result_t reassemble_fragments(isc_mem_t *mctx, fcache_t *fcache, unsigned char *key, unsigned keysize, dns_message_t **out_msg) {
    REQUIRE(out_msg != NULL && *out_msg == NULL);

    // try to find cache entry
    fragment_cache_entry_t *entry = NULL;
    isc_result_t result = fcache_get(fcache, key, keysize, &entry);
    if (result != ISC_R_SUCCESS) {
        isc_log_write(dns_lctx, DNS_LOGCATEGORY_FRAGMENTATION, DNS_LOGMODULE_FRAGMENT, ISC_LOG_DEBUG(8),
            "Could not get fragment entry from cache!");  
        return result;
    }

    // check if all fragments are in cache
    if (entry->bitmap != (1u << entry->nr_fragments) - 1) {    
        isc_log_write(dns_lctx, DNS_LOGCATEGORY_FRAGMENTATION, DNS_LOGMODULE_FRAGMENT, ISC_LOG_DEBUG(8),
            "Not all fragments have been received for entry %s (bitmap: %lx)", entry->key, entry->bitmap);  
        return ISC_R_INPROGRESS;
    }

    // create new message
    //dns_message_t *tmp_msg = NULL;
    dns_message_create(mctx, DNS_MESSAGE_INTENTPARSE, out_msg);

    // copy first fragment
    isc_buffer_t *frag_buf = NULL;
    fcache_get_fragment_from_entry(entry, 0, &frag_buf);
    result = dns_message_parse(*out_msg, frag_buf, DNS_MESSAGEPARSE_PRESERVEORDER); // create first fragment message
    if (result != ISC_R_SUCCESS) {
        isc_log_write(dns_lctx, DNS_LOGCATEGORY_FRAGMENTATION, DNS_LOGMODULE_FRAGMENT, ISC_LOG_DEBUG(8),
            "Could not parse fragment!");  
        dns_message_detach(out_msg);
        return result;
    }
    dns_messageid_t id = (*out_msg)->id;

    // first fragment is already copied
    for(unsigned frag_nr = 1; frag_nr < entry->nr_fragments; frag_nr++) {
        dns_message_t *frag = NULL;
        dns_message_create(mctx, DNS_MESSAGE_INTENTPARSE, &frag);
        frag_buf = NULL;
        fcache_get_fragment_from_entry(entry, frag_nr, &frag_buf);
        result = dns_message_parse(frag, frag_buf, DNS_MESSAGEPARSE_PRESERVEORDER);
        if (result != ISC_R_SUCCESS) {
            isc_log_write(dns_lctx, DNS_LOGCATEGORY_FRAGMENTATION, DNS_LOGMODULE_FRAGMENT, ISC_LOG_DEBUG(8),
                "Could not parse fragment!");  
            dns_message_detach(out_msg);
            return result;
        }
        // check if the fragments in fcache belong to the same message
        if (id != frag->id) {
            isc_log_write(dns_lctx, DNS_LOGCATEGORY_FRAGMENTATION, DNS_LOGMODULE_FRAGMENT, ISC_LOG_DEBUG(8),
                "Fragments have a mismatching ID: %u and %u", id, frag->id);  
            dns_message_detach(&frag);
            dns_message_detach(out_msg);
            return ISC_R_FAILURE;            
        }

        // we build a new message everytime
        //dns_message_t *builder = NULL;
        //dns_message_create(mctx, DNS_MESSAGE_INTENTRENDER, &builder);

        for(unsigned section = 1; section < DNS_SECTION_MAX; section++) {
            // set msg pointer to first name, first rrset, first rr
            // I think this should always work...
            isc_result_t result_msg = dns_message_firstname(*out_msg, section);
            
            // possible. for example OPT record is not stored in the main dns message structure
            if(frag->counts[section] > 0 && result_msg == ISC_R_SUCCESS) {
                dns_name_t *name_msg = NULL;
                dns_message_currentname(*out_msg, section, &name_msg);
                dns_rdataset_t *rdataset_msg = ISC_LIST_HEAD(name_msg->list);
                //REQUIRE(rdataset_msg != NULL);
                isc_result_t tresult_msg = dns_rdataset_first(rdataset_msg); 

                // by definition, all records in later fragments must be in earlier fragments
                // so, we start with the fragment and keep iterating until we find the corresponding rr in the earlier fragment
                // loop through fragment resource records
                for (isc_result_t result_frag = dns_message_firstname(frag, section); result_frag == ISC_R_SUCCESS;  result_frag = dns_message_nextname(frag, section)) {
                    dns_name_t *name_frag = NULL;
                    dns_message_currentname(frag, section, &name_frag);

                    for (dns_rdataset_t *rdataset_frag = ISC_LIST_HEAD(name_frag->list); rdataset_frag != NULL; rdataset_frag = ISC_LIST_NEXT(rdataset_frag, link)) {
                        for (isc_result_t tresult_frag = dns_rdataset_first(rdataset_frag); tresult_frag == ISC_R_SUCCESS; tresult_frag = dns_rdataset_next(rdataset_frag)) {
                            dns_rdata_t rdata_frag = DNS_RDATA_INIT;
                            dns_rdataset_current(rdataset_frag, &rdata_frag);

                            // find matching resource record in the message
                            while (result_msg == ISC_R_SUCCESS) {
                                while (rdataset_msg != NULL) {
                                    while(tresult_msg == ISC_R_SUCCESS) {
                                        //dns_rdata_t rdata = DNS_RDATA_INIT;
                                        //dns_rdataset_current(rdataset, &rdata);

                                        dns_rdata_t *rdata_msg = rdataset_msg->rdlist.iter; // pointer not copy, we need to change the values inside
                                        tresult_msg = dns_rdataset_next(rdataset_msg);

                                        // error prone: assumes message structure is the same for all
                                        // better is to check if it has the same qname/header
                                        if((rdata_msg->type == RRSIG && rdata_frag.type == RRSIG) || (rdata_msg->type == DNSKEY && rdata_frag.type == DNSKEY)) {
                                            // get rr header size
                                            unsigned header_size = 0;
                                            if(rdata_msg->type == DNSKEY) {
                                                header_size = calc_dnskey_header_size();
                                            }
                                            // RRSIG
                                            else {
                                                header_size = calc_rrsig_header_size(rdata_msg);
                                            }
                                            REQUIRE(memcmp(rdata_msg->data, rdata_frag.data, header_size) == 0); // headers should be the same
                                            
                                            isc_region_t new_rdata_region;
                                            isc_buffer_t *buf = NULL;
                                            unsigned new_rdata_region_length = rdata_msg->length + rdata_frag.length - header_size; 
                                            isc_buffer_allocate(mctx, &buf, new_rdata_region_length); // deduplicate header
                                            isc_buffer_putmem(buf, rdata_msg->data, rdata_msg->length); // copy existing data
                                            isc_buffer_putmem(buf, rdata_frag.data + header_size, rdata_frag.length - header_size); // copy new data (excluding header)
                                            isc_buffer_usedregion(buf, &new_rdata_region); 
                                            rdata_msg->data = new_rdata_region.base;
                                            rdata_msg->length = new_rdata_region.length;
                                            
                                            // not great, but I don't know how to keep track of the buffers otherwise
                                            // maybe its better to create a new dns_message_t object everytime
                                            dns_message_takebuffer(*out_msg, &buf);
                                            goto next_rr;
                                        }
                                    }
                                    rdataset_msg = ISC_LIST_NEXT(rdataset_msg, link);
                                    if(rdataset_msg != NULL) {
                                        tresult_msg = dns_rdataset_first(rdataset_msg); // reset to first rdata
                                    }
                                }
                                result_msg = dns_message_nextname(*out_msg, section); 
                                if (result_msg == ISC_R_SUCCESS) {
                                    name_msg = NULL;
                                    dns_message_currentname(*out_msg, section, &name_msg);
                                    rdataset_msg = ISC_LIST_HEAD(name_msg->list); // reset to first rdataset 
                                    tresult_msg = dns_rdataset_first(rdataset_msg); // reset to first rdata
                                }
                            }
                            //REQUIRE(false); // there should always be a match
                            next_rr:
                        }
                    }
                }
            }
        }
        //isc_buffer_free(&(frag->buffer));
        dns_message_detach(&frag);
    }
    (*out_msg)->from_to_wire = DNS_MESSAGE_INTENTRENDER;
    (*out_msg)->state = DNS_SECTION_ANY;
    delete_fragment_opt(*out_msg); // delete the option
    result = render_fragment(mctx, entry->nr_fragments * 1232, out_msg); 
    if (result != ISC_R_SUCCESS) {
        isc_log_write(dns_lctx, DNS_LOGCATEGORY_FRAGMENTATION, DNS_LOGMODULE_FRAGMENT, ISC_LOG_DEBUG(8),
            "Failed to render the reassembled message!");  
        return result;
    }
    // unset the TC flag so it gets parsed by resolver.c (resquery_response)
    (*out_msg)->flags &= ~DNS_MESSAGEFLAG_TC;
    *(unsigned short *)((*out_msg)->buffer->base + 1) &= ~DNS_MESSAGEFLAG_TC;

    isc_log_write(dns_lctx, DNS_LOGCATEGORY_FRAGMENTATION, DNS_LOGMODULE_FRAGMENT, ISC_LOG_DEBUG(8),
            "Reassembled entry %s from %u fragments into one message with size %u", entry->key, entry->nr_fragments, (*out_msg)->buffer->used);  
    
    // would be slightly more efficient to do this in the loop
    result = fcache_remove(fcache, entry->key, entry->keysize);
    if (result != ISC_R_SUCCESS) {
        isc_log_write(dns_lctx, DNS_LOGCATEGORY_FRAGMENTATION, DNS_LOGMODULE_FRAGMENT, ISC_LOG_DEBUG(8),
            "Could not remove cache entry after reassembly!");  
        return result;
    }
    return ISC_R_SUCCESS;
}
