/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * SPDX-License-Identifier: MPL-2.0
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

#include <inttypes.h>
#include <sched.h> /* IWYU pragma: keep */
#include <setjmp.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <sys/param.h>
#include <sys/types.h>
#include <unistd.h>
#include <time.h>
#include <isc/loop.h>
#include <isc/result.h>
#include <isc/time.h>
#include <isc/types.h>

#define UNIT_TESTING
#include <cmocka.h>

#include <isc/buffer.h>
#include <isc/commandline.h>
#include <isc/managers.h>
#include <isc/md.h>
#include <isc/mem.h>
#include <isc/os.h>
#include <isc/thread.h>
#include <isc/urcu.h>
#include <isc/util.h>
#include <isc/uv.h>

#include <dns/fcache.h>
#include <dns/message.h>

#include <tests/dns.h>


static void compare_buffers(isc_buffer_t *a, isc_buffer_t *b) {
    //printf("Comparing buffers...\n");
    //printf("a->used: %d\nb->used: %d\n", a->used, b->used);
    assert_true(a->used == b->used);
    for (unsigned i = 0; i < a->used; i++) {
        assert_true(((char *)(a->base))[i] == ((char *)(b->base))[i]);
    }
}

static unsigned char* load_binary_file(const char* filename, size_t* out_size) {
    FILE* file = fopen(filename, "rb");
    if (!file) {
        perror("Failed to open file");
        return NULL;
    }

    // get file size
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    if (file_size < 0) {
        perror("Failed to get file size");
        fclose(file);
        return NULL;
    }

    unsigned char* buffer = (unsigned char*)isc_mem_get(mctx, file_size);
    if (!buffer) {
        perror("Failed to allocate memory");
        fclose(file);
        return NULL;
    }
    size_t bytes_read = fread(buffer, 1, file_size, file);
    if (bytes_read != (size_t)file_size) {
        perror("Failed to read file");
        isc_mem_put(mctx, buffer, file_size);
        fclose(file);
        return NULL;
    }

    fclose(file);
    *out_size = file_size;
    return buffer;
}


// tests the init and deinit functions
ISC_LOOP_TEST_IMPL(test_fcache_init) {

    assert_true(loopmgr != NULL);
    assert_true(mctx != NULL);
    // test case 1: normal case
    fcache_t *fcache = NULL;
    fcache_init(&fcache, loopmgr, 10, 20);
    assert_true(fcache->mctx != NULL);
    assert_true(fcache->ht != NULL);
    assert_true(fcache->expiry_list.head == NULL);
    assert_true(fcache->expiry_list.tail == NULL);
    assert_true(fcache->expiry_timer != NULL);
    assert_int_equal(fcache->ttl.seconds, 10);
    assert_int_equal(fcache->loop_timeout.seconds, 20);
    fcache_deinit(&fcache);
    
    // test case 2: different values
    fcache = NULL;
    fcache_init(&fcache, loopmgr, 1, 1);
    assert_true(fcache->mctx != NULL);
    assert_true(fcache->ht != NULL);
    assert_true(fcache->expiry_list.head == NULL);
    assert_true(fcache->expiry_list.tail == NULL);
    assert_true(fcache->expiry_timer != NULL);
    assert_int_equal(fcache->ttl.seconds, 1);
    assert_int_equal(fcache->loop_timeout.seconds, 1);
    fcache_deinit(&fcache);
        
    // test case 3: different values
    fcache = NULL;
    fcache_init(&fcache, loopmgr, 12345, 98765);
    assert_true(fcache->mctx != NULL);
    assert_true(fcache->ht != NULL);
    assert_true(fcache->expiry_list.head == NULL);
    assert_true(fcache->expiry_list.tail == NULL);
    assert_true(fcache->expiry_timer != NULL);
    assert_int_equal(fcache->ttl.seconds, 12345);
    assert_int_equal(fcache->loop_timeout.seconds, 98765);
    fcache_deinit(&fcache);
    
	isc_loopmgr_shutdown(loopmgr);
}

// tests the add function
ISC_LOOP_TEST_IMPL(test_fcache_add) {

    assert_true(loopmgr != NULL);
    assert_true(mctx != NULL);

    fcache_t *fcache = NULL;
    fcache_init(&fcache, loopmgr, 10, 20);
    unsigned buflen = 16;
    unsigned nr_fragments = 5;
    unsigned frag_nr = 0;
    unsigned keysize = 96;
    unsigned char key[keysize];
    unsigned char key2[keysize];
    unsigned char key4[keysize];
    strcpy((char *)key, "thisisakey!");
    strcpy((char *)key2, "thisisanotherkey!");
    strcpy((char *)key2, "stillanotherkey!");
    fragment_cache_entry_t *out_ce;
    isc_result_t result;
    isc_time_t now = isc_time_now();

    // test case 1: normal case
    dns_message_t *frag1 = NULL;
    isc_buffer_t *buffer1 = NULL;
    isc_buffer_allocate(mctx, &buffer1, buflen);
    isc_buffer_putuint32(buffer1, 12345678);
    isc_buffer_putuint32(buffer1, 11111111); 
    frag1 = isc_mem_get(mctx, sizeof(dns_message_t)); 
    memset(frag1, 0, sizeof(dns_message_t));
    assert_int_equal(buffer1->length, buflen);
    frag1->fragment_nr = frag_nr;
    frag1->buffer = buffer1;
    result = fcache_add_with_fragment(fcache, key, keysize, frag1, nr_fragments);
    assert_true(result == ISC_R_SUCCESS);
    result = fcache_get(fcache, key, keysize, &out_ce);
    assert_true(result == ISC_R_SUCCESS);
    assert_true(out_ce != NULL);
    assert_string_equal((char *)out_ce->key, (char *)key);
    assert_int_equal(out_ce->keysize, keysize);
    assert_int_equal(out_ce->nr_fragments, nr_fragments);
    assert_true(out_ce->bitmap == (1u << frag_nr));
    assert_true(out_ce->expiry.seconds > now.seconds - 10); // assumption that it takes less than 10 seconds

    // test case 2: new case with first frag set to 2
    out_ce = NULL;
    dns_message_t *frag2 = NULL;
    isc_buffer_t *buffer2 = NULL;
    frag_nr = 2;
    isc_buffer_allocate(mctx, &buffer2, buflen);
    isc_buffer_putuint32(buffer2, 53633633);
    isc_buffer_putuint32(buffer2, 11111221); 
    isc_buffer_putuint32(buffer2, 11111221); 
    frag2 = isc_mem_get(mctx, sizeof(dns_message_t)); 
    memset(frag2, 0, sizeof(dns_message_t));
    assert_int_equal(buffer2->length, buflen);
    frag2->fragment_nr = frag_nr;
    frag2->buffer = buffer2;
    result = fcache_add_with_fragment(fcache, key2, keysize, frag2, nr_fragments);
    assert_true(result == ISC_R_SUCCESS);
    result = fcache_get(fcache, key2, keysize, &out_ce);
    assert_true(result == ISC_R_SUCCESS);
    assert_true(out_ce != NULL);
    assert_string_equal((char *)out_ce->key, (char *)key2);
    assert_int_equal(out_ce->keysize, keysize);
    assert_int_equal(out_ce->nr_fragments, nr_fragments);
    assert_true(out_ce->bitmap == (1u << frag_nr));
    assert_true(out_ce->expiry.seconds > now.seconds - 10); // assumption that it takes less than 10 seconds

    // test case 3: already exists
    result = fcache_add_with_fragment(fcache, key2, keysize, frag2, nr_fragments);
    assert_true(result == ISC_R_EXISTS);
    assert_true(out_ce->bitmap == (1u << frag_nr)); // just to check

    // test case 4: fragment number out of range
    out_ce = NULL;
    dns_message_t *frag4 = NULL;
    isc_buffer_t *buffer4 = NULL;
    frag_nr = 5;
    isc_buffer_allocate(mctx, &buffer4, buflen);
    isc_buffer_putuint32(buffer4, 53633633);
    isc_buffer_putuint32(buffer4, 11111221); 
    isc_buffer_putuint32(buffer4, 11111221); 
    frag4 = isc_mem_get(mctx, sizeof(dns_message_t)); 
    memset(frag4, 0, sizeof(dns_message_t));
    assert_int_equal(buffer4->length, buflen);
    frag4->fragment_nr = frag_nr;
    frag4->buffer = buffer4;
    result = fcache_add_with_fragment(fcache, key4, keysize, frag4, nr_fragments);
    assert_true(result == ISC_R_RANGE);
    result = fcache_get(fcache, key4, keysize, &out_ce);
    assert_true(result == ISC_R_SUCCESS);
    assert_true(out_ce != NULL);
    assert_string_equal((char *)out_ce->key, (char *)key4);
    assert_int_equal(out_ce->keysize, keysize);
    assert_int_equal(out_ce->nr_fragments, nr_fragments);
    assert_true(out_ce->expiry.seconds > now.seconds - 10); // assumption that it takes less than 10 seconds


    // free everything
    isc_buffer_free(&buffer1);
    isc_mem_put(mctx, frag1, sizeof(dns_message_t));
    isc_buffer_free(&buffer2);
    isc_mem_put(mctx, frag2, sizeof(dns_message_t));
    isc_buffer_free(&buffer4);
    isc_mem_put(mctx, frag4, sizeof(dns_message_t));
    fcache_deinit(&fcache);
	isc_loopmgr_shutdown(loopmgr);
}

// tests all variants of adding and removing entries
ISC_LOOP_TEST_IMPL(test_fcache_add_remove) {
    assert_true(loopmgr != NULL);
    assert_true(mctx != NULL);

    fcache_t *fcache = NULL;
    fcache_init(&fcache, loopmgr, 10, 20);
    unsigned buflen = 16;
    unsigned nr_fragments = 5;
    unsigned frag_nr = 0;
    unsigned keysize = 96;
    unsigned char key[keysize];
    unsigned char key2[keysize];
    unsigned char key4[keysize];
    strcpy((char *)key, "thisisakey!");
    strcpy((char *)key2, "thisisanotherkey!");
    strcpy((char *)key2, "stillanotherkey!");
    fragment_cache_entry_t *out_ce;
    isc_result_t result;
    isc_time_t now = isc_time_now();
    
    // keep adding and removing randomly
    dns_message_t *frag1 = NULL;
    isc_buffer_t *buffer1 = NULL;
    isc_buffer_allocate(mctx, &buffer1, buflen);
    isc_buffer_putuint32(buffer1, 12345678);
    isc_buffer_putuint32(buffer1, 11111111); 
    frag1 = isc_mem_get(mctx, sizeof(dns_message_t)); 
    memset(frag1, 0, sizeof(dns_message_t));
    assert_int_equal(buffer1->length, buflen);
    frag1->fragment_nr = 1;
    frag1->buffer = buffer1;
    result = fcache_add(fcache, key, keysize, nr_fragments);
    assert_true(result == ISC_R_SUCCESS);
    result = fcache_get(fcache, key, keysize, &out_ce);
    assert_true(result == ISC_R_SUCCESS);
    assert_true(out_ce != NULL);
    assert_string_equal((char *)out_ce->key, (char *)key);
    assert_int_equal(out_ce->keysize, keysize);
    assert_int_equal(out_ce->nr_fragments, nr_fragments);
    assert_true(out_ce->expiry.seconds > now.seconds - 10); 
    // add fragment 1
    result = fcache_add_fragment(fcache, key, keysize, frag1);
    assert_true(result == ISC_R_SUCCESS);
    out_ce = NULL;
    result = fcache_get(fcache, key, keysize, &out_ce);
    assert_true(out_ce->bitmap == (1u << 1));
    // add fragment 0
    frag1->fragment_nr = 0;
    result = fcache_add_fragment(fcache, key, keysize, frag1);
    assert_true(result == ISC_R_SUCCESS);
    out_ce = NULL;
    result = fcache_get(fcache, key, keysize, &out_ce);
    assert_true(out_ce->bitmap == (1u << 1 | 1u << 0));
    // add fragment 1 again, will overwrite
    frag1->fragment_nr = 1;
    result = fcache_add_fragment(fcache, key, keysize, frag1);
    assert_true(result == ISC_R_SUCCESS);
    out_ce = NULL;
    result = fcache_get(fcache, key, keysize, &out_ce);
    assert_true(out_ce->bitmap == (1u << 1 | 1u << 0));
    // add new entry
    result = fcache_add(fcache, "newentry", 10, 6);
    assert_true(result == ISC_R_SUCCESS);
    assert_int_equal(fcache_count(fcache), 2);
    // add new entry
    result = fcache_add(fcache, "newentry2", 11, 6);
    assert_true(result == ISC_R_SUCCESS);
    assert_int_equal(fcache_count(fcache), 3);
    // add new entry (already exists)
    result = fcache_add(fcache, "newentry2", 11, 6);
    assert_true(result == ISC_R_EXISTS);
    assert_int_equal(fcache_count(fcache), 3);
    // remove fragment 0
    result = fcache_remove_fragment(fcache, key, keysize, 0);
    assert_true(result == ISC_R_SUCCESS);
    assert_int_equal(fcache_count(fcache), 3);
    out_ce = NULL;
    result = fcache_get(fcache, key, keysize, &out_ce);
    assert_true(out_ce->bitmap == (1u << 1));
    // remove fragment 2 (not exists)
    result = fcache_remove_fragment(fcache, key, keysize, 2);
    assert_true(result == ISC_R_NOTFOUND);
    assert_int_equal(fcache_count(fcache), 3);
    out_ce = NULL;
    result = fcache_get(fcache, key, keysize, &out_ce);
    assert_true(out_ce->bitmap == (1u << 1));
    // remove fragment 222 (not exists)
    result = fcache_remove_fragment(fcache, key, keysize, 222);
    assert_true(result == ISC_R_NOTFOUND);
    assert_int_equal(fcache_count(fcache), 3);
    out_ce = NULL;
    result = fcache_get(fcache, key, keysize, &out_ce);
    assert_true(out_ce->bitmap == (1u << 1));
    // remove fragment 0 (not exists)
    result = fcache_remove_fragment(fcache, key, keysize, 0);
    assert_true(result == ISC_R_NOTFOUND);
    assert_int_equal(fcache_count(fcache), 3);
    out_ce = NULL;
    result = fcache_get(fcache, key, keysize, &out_ce);
    assert_true(out_ce->bitmap == (1u << 1));
    // remove fragment 1 but wrong key
    result = fcache_remove_fragment(fcache, key2, keysize, 1);
    assert_true(result == ISC_R_NOTFOUND);
    assert_int_equal(fcache_count(fcache), 3);
    out_ce = NULL;
    result = fcache_get(fcache, key, keysize, &out_ce);
    assert_true(out_ce->bitmap == (1u << 1));
    // remove non-existing entry
    result = fcache_remove(fcache, key4, keysize);
    assert_true(result == ISC_R_NOTFOUND);
    // add new entry with fragment, but fragment number is too high (still add)
    frag1->fragment_nr = 9;
    result = fcache_add_with_fragment(fcache, key4, keysize, frag1, 9);
    assert_true(result == ISC_R_RANGE);
    assert_int_equal(fcache_count(fcache), 4);
    out_ce = NULL;
    result = fcache_get(fcache, key4, keysize, &out_ce);
    assert_true(out_ce->bitmap == 0);

    // free everything
    isc_buffer_free(&buffer1);
    isc_mem_put(mctx, frag1, sizeof(dns_message_t));
    fcache_deinit(&fcache);
	isc_loopmgr_shutdown(loopmgr);
}

// tests basic insertion and deletion
ISC_LOOP_TEST_IMPL(test_basic) {
    
    // initialize
    assert_true(loopmgr != NULL);
    assert_true(mctx != NULL);

    fcache_t *fcache = NULL;
    fcache_init(&fcache, loopmgr, 10, 20);
    
    // set up a dns message with random buffer
    dns_message_t *frag = NULL;
    dns_message_t *frag2 = NULL;
    dns_message_t *frag4 = NULL;
    dns_message_t *frag5 = NULL;
    isc_buffer_t *buffer = NULL;
    isc_buffer_t *buffer2 = NULL;
    isc_buffer_t *buffer4 = NULL;
    isc_buffer_t *buffer5 = NULL;

    unsigned buflen = 10;
    // frag 1
    isc_buffer_allocate(mctx, &buffer, buflen);
    isc_buffer_putuint32(buffer, 12345678); // put some data
    frag = isc_mem_get(mctx, sizeof(dns_message_t));
    memset(frag, 0, sizeof(dns_message_t));
    assert_int_equal(buffer->length, buflen);
    frag->fragment_nr = 1;
    frag->buffer = buffer;
    // frag 2
    isc_buffer_allocate(mctx, &buffer2, buflen);
    isc_buffer_putuint32(buffer2, 87654321); // put some data
    frag2 = isc_mem_get(mctx, sizeof(dns_message_t));
    memset(frag2, 0, sizeof(dns_message_t));
    frag2->fragment_nr = 2;
    frag2->buffer = buffer2;
    // frag 4
    isc_buffer_allocate(mctx, &buffer4, buflen);
    isc_buffer_putuint32(buffer4, 55555555); // put some data
    frag4 = isc_mem_get(mctx, sizeof(dns_message_t));
    memset(frag4, 0, sizeof(dns_message_t));
    frag4->fragment_nr = 4;
    frag4->buffer = buffer4;
    // frag 5 -> should not get added since nr_fragment = 5 (0, 1, 2, 3, 4)
    isc_buffer_allocate(mctx, &buffer5, buflen);
    isc_buffer_putuint32(buffer5, 88118811); // put some data
    frag5 = isc_mem_get(mctx, sizeof(dns_message_t));
    memset(frag5, 0, sizeof(dns_message_t));
    frag5->fragment_nr = 5;
    frag5->buffer = buffer5;

    unsigned nr_fragments = 5;
    unsigned keysize = 96;
    unsigned char key[keysize];
    unsigned char key_non_exist[keysize];
    strcpy((char *)key, "thisisakey!");
    strcpy((char *)key_non_exist, "thisisalsoakey!");
    
    // outputs
    isc_result_t res;
    isc_buffer_t *out = NULL;
    fragment_cache_entry_t *out_ce;
    assert_int_equal(fcache_count(fcache), 0);
    // add new entry to cache
    res = fcache_add_with_fragment(fcache, key, keysize, frag, nr_fragments);
    assert_true(res == ISC_R_SUCCESS);
    assert_int_equal(fcache_count(fcache), 1);
    // get existing fragment
    res = fcache_get_fragment(fcache, key, keysize, frag->fragment_nr, &out);
    assert_true(res == ISC_R_SUCCESS);
    // get non-existing fragment
    res = fcache_get_fragment(fcache, key, keysize, 2, &out);
    assert_true(res == ISC_R_NOTFOUND);
    // remove non-existing fragment
    res = fcache_remove_fragment(fcache, key, keysize, 2);
    assert_true(res == ISC_R_NOTFOUND);
    assert_int_equal(fcache_count(fcache), 1);
    // remove fragment with non-existing key
    res = fcache_remove_fragment(fcache, key_non_exist, keysize, frag->fragment_nr);
    assert_true(res == ISC_R_NOTFOUND);
    assert_int_equal(fcache_count(fcache), 1);
    // remove fragment
    res = fcache_remove_fragment(fcache, key, keysize, frag->fragment_nr);
    assert_true(res == ISC_R_SUCCESS);
    assert_int_equal(fcache_count(fcache), 1); // entry still exists
    // remove non-existing entry
    res = fcache_remove(fcache, key_non_exist, keysize);
    assert_true(res == ISC_R_NOTFOUND);
    // remove entry
    res = fcache_remove(fcache, key, keysize);
    assert_true(res == ISC_R_SUCCESS);
    assert_int_equal(fcache_count(fcache), 0);

    // add new entry
    res = fcache_add_with_fragment(fcache, key, keysize, frag, nr_fragments);
    assert_true(res == ISC_R_SUCCESS);
    assert_int_equal(fcache_count(fcache), 1);
    // add same fragment, should overwrite
    res = fcache_add_fragment(fcache, key, keysize, frag);
    assert_true(res == ISC_R_SUCCESS);
    assert_int_equal(fcache_count(fcache), 1);
    // add new fragment
    res = fcache_add_fragment(fcache, key, keysize, frag4);
    assert_true(res == ISC_R_SUCCESS);
    assert_int_equal(fcache_count(fcache), 1);
    out_ce = NULL;
    res = fcache_get(fcache, key, keysize, &out_ce);
    assert_true(out_ce->bitmap == ((1u << frag->fragment_nr) | (1u << frag4->fragment_nr)));
    // try to add fragment 5
    res = fcache_add_fragment(fcache, key, keysize, frag5);
    assert_true(res == ISC_R_RANGE);
    assert_int_equal(fcache_count(fcache), 1);
    out_ce = NULL;
    res = fcache_get(fcache, key, keysize, &out_ce);
    assert_true(out_ce->bitmap == ((1u << frag->fragment_nr) | (1u << frag4->fragment_nr)));
    // add new fragment
    res = fcache_add_fragment(fcache, key, keysize, frag2);
    assert_true(res == ISC_R_SUCCESS);
    assert_int_equal(fcache_count(fcache), 1);
    out_ce = NULL;
    res = fcache_get(fcache, key, keysize, &out_ce);
    assert_true(out_ce->bitmap == ((1u << frag->fragment_nr) | (1u << frag4->fragment_nr) | (1u << frag2->fragment_nr)));

    // purge before loop
    fcache_purge(fcache);
    assert_int_equal(fcache_count(fcache), 0);

    // add 100 entries, use the same fragment
    for(unsigned i = 0; i < 100; i++) {
        out_ce = NULL;
        unsigned char key2[keysize];
        snprintf((char *)key2, keysize, "key%d!", i);
        res = fcache_add_with_fragment(fcache, key2, keysize, frag, nr_fragments);
        assert_true(res == ISC_R_SUCCESS);
        assert_int_equal(fcache_count(fcache), i + 1);
        // test if fragment has been copied (e.g. does not use the same memory address)
        res = fcache_get(fcache, key2, keysize, &out_ce);
        assert_true(frag != out_ce);    // should have been copied
        assert_true(key2 != out_ce->key);
        assert_true(keysize == out_ce->keysize); // size should be the same
        assert_true(out_ce->bitmap == (1u << frag->fragment_nr));
        // get first fragment
        res = fcache_get_fragment(fcache, key2, keysize, frag->fragment_nr, &out);
        compare_buffers(frag->buffer, out);
    }

    // deallocate memory
    isc_buffer_free(&buffer);
    isc_buffer_free(&buffer2);
    isc_buffer_free(&buffer4);
    isc_buffer_free(&buffer5);
    isc_mem_put(mctx, frag, sizeof(dns_message_t));
    isc_mem_put(mctx, frag2, sizeof(dns_message_t));
    isc_mem_put(mctx, frag4, sizeof(dns_message_t));
    isc_mem_put(mctx, frag5, sizeof(dns_message_t));
    fcache_deinit(&fcache);
	isc_loopmgr_shutdown(loopmgr);
}

// tests the fragmentation cache with real dns messages
ISC_LOOP_TEST_IMPL(test_real_dns_messages) {
    // initialize
    assert_true(loopmgr != NULL);
    assert_true(mctx != NULL);
    fcache_t *fcache = NULL;
    fcache_init(&fcache, loopmgr, 10, 20);
    
    // set up a dns message with random buffer
    dns_message_t *msg = NULL;
    unsigned char *buffer = NULL;

    const char *filename = "testdata/message/response1-falcon512";
    size_t buffer_size;
    buffer = load_binary_file(filename, &buffer_size);

    if(buffer != NULL) {
        printf("buffer_size: %zu\n", buffer_size);
        isc_buffer_t buf;
        isc_buffer_init(&buf, buffer, buffer_size);
        isc_buffer_add(&buf, buffer_size);
        printf("buf used: %d\n", buf.used);
        printf("buf used: %d\n", buf.length);
        //isc_buffer_printf(&buf, "aa");
        msg = NULL;
        dns_message_create(mctx, DNS_MESSAGE_INTENTPARSE, &msg);
        dns_message_parse(msg, &buf, 0);
        printf("msgid: %d\n", msg->id);

        unsigned nr_fragments = 5;
        unsigned keysize = 96;
        unsigned char key[keysize];
        unsigned char key_non_exist[keysize];
        strcpy((char *)key, "thisisakey!");
        strcpy((char *)key_non_exist, "thisisalsoakey!");
        
        // outputs
        isc_result_t res;
        fragment_cache_entry_t *out_ce;

        assert_int_equal(fcache_count(fcache), 0);
        // add new message to cache
        res = fcache_add(fcache, key, keysize, nr_fragments);
        assert_true(res == ISC_R_SUCCESS);
        assert_int_equal(fcache_count(fcache), 1);
        res = fcache_add_fragment(fcache, key, keysize, msg);
        assert_true(res == ISC_R_SUCCESS);
        out_ce = NULL;
        res = fcache_get(fcache, key, keysize, &out_ce);
        assert_true(res == ISC_R_SUCCESS);
        assert_int_equal(out_ce->nr_fragments, nr_fragments);
        assert_int_equal(out_ce->bitmap, 1); // 000001
        printf("fragment size: %u, expected: %u\n", out_ce->fragments[0]->used, msg->saved.length);
        assert_int_equal(msg->saved.length, out_ce->fragments[0]->used);

        // clean up
        dns_message_detach(&msg);
        isc_mem_put(mctx, buffer, buffer_size);
    }
    else {
        fprintf(stderr, "Could not find file: %s\n", filename);
    }
    fcache_deinit(&fcache);
	isc_loopmgr_shutdown(loopmgr);
}

ISC_LOOP_TEST_IMPL(test_fcache_purge) {
    // initialize
    assert_true(loopmgr != NULL);
    assert_true(mctx != NULL);
    fcache_t *fcache = NULL;
    fcache_init(&fcache, loopmgr, 10, 20);

    // keys
    unsigned keysize = 32;
    unsigned char key[keysize];
    strcpy((char *)key, "thisis1akey!");

    assert_int_equal(fcache_count(fcache), 0);
    fcache_add(fcache, key, keysize, 5);
    fcache_add(fcache, "test", 5, 5);
    fcache_add(fcache, "does this work as well?", 35, 5);
    fcache_add(fcache, "too short", 3, 5);
    assert_int_equal(fcache_count(fcache), 4);
    fcache_purge(fcache);
    assert_int_equal(fcache_count(fcache), 0);

    fcache_deinit(&fcache);
	isc_loopmgr_shutdown(loopmgr);
}

/*
the following tests test if the fcache cleans up properly after a time-out
it is somehwat difficult to test because it is asynchronous

the way twe do the testing is as follows:
1. create timers that call timer_cb after a time period
2. set the global variables (fcache_g) and nevents_g (indicartes the amount of expected calls)
3. the timer_cb receives the expected count and does the following tests
    a. does the expected count match the count in the global fcache
    b. is the expiry list ordered
4. the timer cleans up if nevents_g == 0
this way we can test before the timer in fcache goes off, after, and in between

notes:
1. we cannot use local variables to pass as a parameter because they get removed before the cb is called
2. do not reuse global variables, it might lead to race conditions
3. it often HANGS if it fails, so debugging is a bit of a struggle
*/

// globals for timer testing
static isc_timer_t *timer_g = NULL;
static isc_timer_t *timer_add_g = NULL;
static isc_timer_t *timer_during_g = NULL;
static isc_timer_t *timer_during_2_g = NULL;
static isc_timer_t *timer_during_3_g = NULL;
static isc_timer_t *timer_during_4_g = NULL;
static isc_timer_t *timer_after_g = NULL;
static fcache_t *fcache_g;
static unsigned expected_count_g;
static unsigned expected_count_2_g;
static unsigned expected_count_3_g;
static unsigned expected_count_4_g;
static unsigned expected_count_5_g;
static unsigned nevents_g;

// adds some additional entries to the fcache
static void fcache_add_cb(void *data) {
    // keys
    unsigned keysize = 32;
    unsigned char key1[keysize];
    strcpy((char *)key1, "abcd1234!");
    unsigned char key2[keysize];
    strcpy((char *)key2, "1234abcd!");
    unsigned char key3[keysize];
    strcpy((char *)key3, "a1b2c3d4!");

    // reuse buffer and frag
    unsigned buflen = 24;
    unsigned nr_fragments = 3;
    unsigned frag_nr = 1;
    isc_buffer_t *buffer = NULL;
    isc_buffer_allocate(mctx, &buffer, buflen);
    isc_buffer_putuint32(buffer, 45454545);
    isc_buffer_putuint32(buffer, 54545454); 
    isc_buffer_putuint32(buffer, 32323232); 
    dns_message_t *frag = NULL;
    frag = isc_mem_get(mctx, sizeof(dns_message_t));
    memset(frag, 0, sizeof(dns_message_t));
    frag->fragment_nr = frag_nr;
    frag->buffer = buffer;
    isc_result_t result;

    // add 5 items
    result = fcache_add_with_fragment(fcache_g, key1, keysize, frag, nr_fragments);
    assert_true(result == ISC_R_SUCCESS);
    result = fcache_add(fcache_g, key2, keysize, nr_fragments);
    assert_true(result == ISC_R_SUCCESS);
    result = fcache_add_with_fragment(fcache_g, key3, keysize, frag, nr_fragments);
    assert_true(result == ISC_R_SUCCESS);

    // empty
    isc_buffer_free(&buffer);
    isc_mem_put(mctx, frag, sizeof(dns_message_t));
}

static void timer_cb(void *data) {
    nevents_g--;
    unsigned *expected_count = (unsigned *)data;
    printf("timer_cb, nevents_g: %u, expected_count: %u, actual count: %u\n", nevents_g, *expected_count, fcache_count(fcache_g));
    assert_int_equal(fcache_count(fcache_g), *expected_count);
    // test if expiry list is ordered and matches the count
    fragment_cache_entry_t *entry = ISC_LIST_HEAD(fcache_g->expiry_list);
    unsigned count = 0;
    unsigned prev_seconds = 0;
    unsigned prev_nanoseconds = 0;
    while (entry != NULL) {
        // new entries should always have a higher expiry since TTL stays the same
        assert_true(entry->expiry.seconds > prev_seconds || 
                    (entry->expiry.seconds == prev_seconds && entry->expiry.nanoseconds >= prev_nanoseconds));
        prev_seconds = entry->expiry.seconds;
        prev_nanoseconds = entry->expiry.nanoseconds;
        entry = entry->link.next;
        count++;
    }
    assert_int_equal(count, *expected_count);
    // shutdown if this is the last event
    if (nevents_g == 0) {
        if (timer_g != NULL) {
		    isc_timer_destroy(&timer_g);
        }
        if (timer_during_g != NULL) {
		    isc_timer_destroy(&timer_during_g);
        }
        if (timer_during_2_g != NULL) {
		    isc_timer_destroy(&timer_during_2_g);
        }
        if (timer_during_3_g != NULL) {
		    isc_timer_destroy(&timer_during_3_g);
        }
        if (timer_during_4_g != NULL) {
		    isc_timer_destroy(&timer_during_4_g);
        }
        if (timer_after_g != NULL) {
		    isc_timer_destroy(&timer_after_g);
        }
        if (timer_add_g != NULL) {
		    isc_timer_destroy(&timer_add_g);
        }
        fcache_deinit(&fcache_g);
        isc_loopmgr_shutdown(loopmgr);
    }
}

// tests if the fache gets emptied
ISC_LOOP_TEST_IMPL(test_fcache_expiry) {
    assert_true(loopmgr != NULL);
    assert_true(mctx != NULL);

    nevents_g = 2;
    fcache_g = NULL;
    unsigned ttl = 3;
    unsigned timeout = 5;

    fcache_init(&fcache_g, loopmgr, ttl, timeout);
    // test case 1: 3 ttl and 5 second time-out
    unsigned buflen = 16;
    unsigned nr_fragments = 5;
    unsigned frag_nr = 0;
    unsigned keysize = 96;
    unsigned char key[keysize];
    strcpy((char *)key, "thisisakey!");
    isc_result_t result;

    // test case 1: normal case
    dns_message_t *frag1 = NULL;
    isc_buffer_t *buffer1 = NULL;
    isc_buffer_allocate(mctx, &buffer1, buflen);
    isc_buffer_putuint32(buffer1, 12345678);
    isc_buffer_putuint32(buffer1, 11111111); 
    frag1 = isc_mem_get(mctx, sizeof(dns_message_t)); 
    memset(frag1, 0, sizeof(dns_message_t));
    assert_int_equal(buffer1->length, buflen);
    frag1->fragment_nr = frag_nr;
    frag1->buffer = buffer1;
    result = fcache_add_with_fragment(fcache_g, key, keysize, frag1, nr_fragments);
    assert_true(result == ISC_R_SUCCESS);

    // test case 1
    expected_count_g = 1;
    isc_timer_create(isc_loop_main(loopmgr), timer_cb, &expected_count_g, &timer_g);
    isc_interval_t interval;
	isc_interval_set(&interval, 1, 0);
	isc_timer_start(timer_g, isc_timertype_once, &interval);

    // test case 2
    expected_count_2_g = 0;
    isc_timer_create(isc_loop_main(loopmgr), timer_cb, &expected_count_2_g, &timer_after_g);
    isc_interval_t interval2;
	isc_interval_set(&interval2, 6, 0);
	isc_timer_start(timer_after_g, isc_timertype_once, &interval2);


    // empty
    isc_buffer_free(&buffer1);
    isc_mem_put(mctx, frag1, sizeof(dns_message_t));
}


// adds a few more 
ISC_LOOP_TEST_IMPL(test_fcache_expiry_advanced) {
    assert_true(loopmgr != NULL);
    assert_true(mctx != NULL);

    nevents_g = 5;
    fcache_g = NULL;
    unsigned ttl = 4;
    unsigned timeout = 8;

    // keys
    unsigned keysize = 96;
    unsigned char key1[keysize];
    strcpy((char *)key1, "thisis1akey!");
    unsigned char key2[keysize];
    strcpy((char *)key2, "th2isisakey!");
    unsigned char key3[keysize];
    strcpy((char *)key3, "thisisa3key!");
    unsigned char key4[keysize];
    strcpy((char *)key4, "thi4sisakey!");
    unsigned char key5[keysize];
    strcpy((char *)key5, "thisis5akey!");

    fcache_init(&fcache_g, loopmgr, ttl, timeout);
    // keep reusing the same buffer and fragment
    unsigned buflen = 16;
    unsigned nr_fragments = 5;
    unsigned frag_nr = 0;
    isc_buffer_t *buffer = NULL;
    isc_buffer_allocate(mctx, &buffer, buflen);
    isc_buffer_putuint32(buffer, 12345678);
    isc_buffer_putuint32(buffer, 11111111); 
    isc_buffer_putuint32(buffer, 22222222); 
    dns_message_t *frag = NULL;
    frag = isc_mem_get(mctx, sizeof(dns_message_t));
    memset(frag, 0, sizeof(dns_message_t));
    frag->fragment_nr = frag_nr;
    frag->buffer = buffer;
    isc_result_t result;

    // add 5 items
    result = fcache_add_with_fragment(fcache_g, key1, keysize, frag, nr_fragments);
    assert_true(result == ISC_R_SUCCESS);
    result = fcache_add(fcache_g, key2, keysize, nr_fragments);
    assert_true(result == ISC_R_SUCCESS);
    result = fcache_add_with_fragment(fcache_g, key3, keysize, frag, nr_fragments);
    assert_true(result == ISC_R_SUCCESS);
    result = fcache_add(fcache_g, key4, keysize, nr_fragments);
    assert_true(result == ISC_R_SUCCESS);
    result = fcache_add_with_fragment(fcache_g, key5, keysize, frag, nr_fragments);
    assert_true(result == ISC_R_SUCCESS);
    // remove 1 of them
    result = fcache_remove(fcache_g, key3, keysize);
    assert_true(result == ISC_R_SUCCESS);
    
    // create timers     
    isc_interval_t interval;
    expected_count_g = 4;
    // set time to 5 seconds, ttl is expired, but entries should still be there
    isc_timer_create(isc_loop_main(loopmgr), timer_cb, &expected_count_g, &timer_during_g);
	isc_interval_set(&interval, 5, 0);
	isc_timer_start(timer_during_g, isc_timertype_once, &interval);
    
    // will add three more entries after 6 seconds (after TTL but before timeout)
    isc_timer_create(isc_loop_main(loopmgr), fcache_add_cb, NULL, &timer_add_g);
	isc_interval_set(&interval, 6, 0);
	isc_timer_start(timer_add_g, isc_timertype_once, &interval);
    
    // set time to 7 seconds, ttl is expired, but entries should still be there including the three new ones
    expected_count_2_g = 7;
    isc_timer_create(isc_loop_main(loopmgr), timer_cb, &expected_count_2_g, &timer_during_2_g);
	isc_interval_set(&interval, 7, 0);
	isc_timer_start(timer_during_2_g, isc_timertype_once, &interval);

    // set time to 9 seconds, only new entries will be there
    expected_count_3_g = 3;
    isc_timer_create(isc_loop_main(loopmgr), timer_cb, &expected_count_3_g, &timer_during_3_g);
	isc_interval_set(&interval, 9, 0);
	isc_timer_start(timer_during_3_g, isc_timertype_once, &interval);
    
    // set time to 15 seconds, new entries should still be there
    expected_count_4_g = 3;
    isc_timer_create(isc_loop_main(loopmgr), timer_cb, &expected_count_4_g, &timer_during_4_g);
	isc_interval_set(&interval, 15, 0);
	isc_timer_start(timer_during_4_g, isc_timertype_once, &interval);
    
    // set time to 17 seconds, should be empty
    expected_count_5_g = 0;
    isc_timer_create(isc_loop_main(loopmgr), timer_cb, &expected_count_5_g, &timer_after_g);
	isc_interval_set(&interval, 17, 0);
	isc_timer_start(timer_after_g, isc_timertype_once, &interval);
    
    // empty
    isc_buffer_free(&buffer);
    isc_mem_put(mctx, frag, sizeof(dns_message_t));
}

ISC_TEST_LIST_START
//ISC_TEST_ENTRY_CUSTOM(test_fcache_init, setup_managers, teardown_managers)
ISC_TEST_ENTRY_CUSTOM(test_fcache_add, setup_managers, teardown_managers)
ISC_TEST_ENTRY_CUSTOM(test_fcache_add_remove, setup_managers, teardown_managers)
ISC_TEST_ENTRY_CUSTOM(test_basic, setup_loopmgr, teardown_loopmgr)
ISC_TEST_ENTRY_CUSTOM(test_real_dns_messages, setup_loopmgr, teardown_loopmgr)
ISC_TEST_ENTRY_CUSTOM(test_fcache_purge, setup_loopmgr, teardown_loopmgr)
ISC_TEST_ENTRY_CUSTOM(test_fcache_expiry, setup_loopmgr, teardown_loopmgr)
ISC_TEST_ENTRY_CUSTOM(test_fcache_expiry_advanced, setup_loopmgr, teardown_loopmgr)
ISC_TEST_LIST_END

ISC_TEST_MAIN
