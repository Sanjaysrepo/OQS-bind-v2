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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <unistd.h>
#include <time.h>
#include <isc/region.h>
#include <isc/result.h>
#include <isc/sockaddr.h>
#include <isc/types.h>
#include <dns/enumclass.h>
#include <dns/fcache.h>
#include <dns/types.h>

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

#include <dns/udp_fragmentation.h>
#include <dns/message.h>
#include <dns/name.h>
#include <dns/fixedname.h>

#include <tests/dns.h>

// global variables so the teardown function can deallocate
static dns_message_t *msg = NULL;
unsigned char *buffer = NULL;
size_t buffer_size;

static void compare_buffer(unsigned char *a, unsigned char *b, unsigned length) {
    for (unsigned i = 0; i < length; i++) {
        assert_true(a[i] == b[i]);
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

// tests the is_fragment function (based on qname)
ISC_RUN_TEST_IMPL(test_is_fragment) {
    dns_fixedname_t fname;
    dns_name_t *name = NULL;

    typedef struct {
        const char *qname;  
        bool is_fragment; 
        unsigned frag_nr;
        bool valid;
    } FragmentTestcase;

    FragmentTestcase testcases[] = {
        {"?1?test.com", true, 0, true},
        {"?12?.somethingsomething.com.com.com", true, 11, true},
        {"example.ca", false, 0, true},
        {"?some.xyz", false, 0, true},
        {"?12af?.example.com", false, 0, true}, // not a number between ??
        {"something.?12?example.com", false, 0, true}, // should start with fragment
        {"?1243?.dfhhdjjhhd.com", true, 1242, true},
        {"a?1243?.com", false, 0, true},
        {"?1243?..com", false, 0, false}, // invalid qname
    };

    name = dns_fixedname_initname(&fname);
    dns_message_create(mctx, DNS_MESSAGE_INTENTRENDER, &msg);
    
    for (unsigned i = 0; i < sizeof(testcases) / sizeof(testcases[0]); i++) {
        fprintf(stderr, "testcase %d: %s\n", i, testcases[i].qname);
        char *qname = NULL;
        dns_name_fromstring(name, testcases[i].qname, NULL, 0, mctx);
        dns_message_addname(msg, name, DNS_SECTION_QUESTION);
        
        bool res = is_fragment_qname(mctx, msg);
        assert_true(dns_message_firstname(msg, DNS_SECTION_QUESTION) == ISC_R_SUCCESS); // qname should be there
        assert_true(res == testcases[i].is_fragment);                        // test if outcome is the same

        assert_true(msg->is_fragment == testcases[i].is_fragment); 
        // test if msg has been updated
        assert_true(!msg->is_fragment || msg->fragment_nr == testcases[i].frag_nr);              // test if fragment number has been parsed
        
        // test if msg has the correct qname
        dns_name_tostring(msg->cursors[DNS_SECTION_QUESTION], &qname, mctx);
        if (testcases[i].valid) {
            assert_true(strcmp(qname, testcases[i].qname) == 0); 
        }

        // reset for next testcase
        dns_message_removename(msg, name, DNS_SECTION_QUESTION);
        dns_message_reset(msg, DNS_MESSAGE_INTENTRENDER);
        isc_mem_free(mctx, qname);
        dns_name_reset(name);

    }
    dns_message_detach(&msg);
}


ISC_RUN_TEST_IMPL(test_is_fragment_opt) {
    const char *filename = "testdata/udp_fragmentation/fragment_opt_test";
    buffer = load_binary_file(filename, &buffer_size);
    isc_result_t result;

    if(buffer != NULL) {
        isc_buffer_t buf;
        isc_buffer_init(&buf, buffer, buffer_size);
        isc_buffer_add(&buf, buffer_size);
        msg = NULL;
        dns_message_create(mctx, DNS_MESSAGE_INTENTPARSE, &msg);
        dns_message_parse(msg, &buf, DNS_MESSAGEPARSE_PRESERVEORDER);
        msg->from_to_wire = 2;
        msg->state = DNS_SECTION_ANY;
        
        // test case 1: message with OPT but no option 22 : failure
        result = is_fragment_opt(msg);
        assert_true(result == ISC_R_NOTFOUND);

        // test case 2: add a valid OPT 22
        // 001001 (9) 001011 (11) 0000 (0)
        char opt_value_bytes[] = { 0x24, 0xB0};
        dns_rdataset_t *opt_2 = NULL;
        dns_ednsopt_t ednsopt;
        ednsopt.code = 22;
        ednsopt.length = 2;
        ednsopt.value = (unsigned char *)opt_value_bytes;
        result = dns_message_buildopt(msg, &opt_2, 0, 1232, 0, &ednsopt, 1);
        dns_message_setopt(msg, opt_2);
        result = is_fragment_opt(msg);
        assert_true(result == ISC_R_SUCCESS);
        assert_int_equal(msg->fragment_nr, 9);
        assert_int_equal(msg->nr_fragments, 11);
        assert_int_equal(msg->fragment_flags, 0);

        // test case 3: message without OPT : failure
        dns_rdataset_t *temp_opt = msg->opt;
        msg->opt = NULL;
        result = is_fragment_opt(msg);
        assert_true(result == ISC_R_EMPTY);
        dns_message_setopt(msg, temp_opt);

        // test case 4: add a valid OPT 22 but the nr_fragments is equal to fragment_nr
        // 001001 (9) 001001 (9) 0000 (0)
        char opt_value_bytes4[] = { 0x24, 0x90};
        dns_rdataset_t *opt_4 = NULL;
        dns_ednsopt_t ednsopt4;
        ednsopt4.code = 22;
        ednsopt4.length = 2;
        ednsopt4.value = (unsigned char *)opt_value_bytes4;
        result = dns_message_buildopt(msg, &opt_4, 0, 1232, 0, &ednsopt4, 1);
        dns_message_setopt(msg, opt_4);
        result = is_fragment_opt(msg);
        assert_true(result == ISC_R_FAILURE);

        // test case 5: add a valid OPT 22 but the number of value bytes are too large (3)
        // 001001 (9) 001011 (11) 0000 (0)
        char opt_value_bytes5[] = { 0x24, 0xB0, 0x00};
        dns_rdataset_t *opt_5 = NULL;
        dns_ednsopt_t ednsopt5;
        ednsopt5.code = 22;
        ednsopt5.length = 3;
        ednsopt5.value = (unsigned char *)opt_value_bytes5;
        result = dns_message_buildopt(msg, &opt_5, 0, 1232, 0, &ednsopt5, 1);
        dns_message_setopt(msg, opt_5);
        result = is_fragment_opt(msg);
        assert_true(result == ISC_R_NOTFOUND);

        // test case 6: add 3 options with the 22 at the end
        char opt_value_bytes6_1[] = { 0x00, 0x01, 0x02, 0x03, 0x04};
        char opt_value_bytes6_2[] = { 0xaa, 0xbb, 0xcc};
        // 12, 16 and 1
        char opt_value_bytes6_3[] = { 0x31, 0x01};
        dns_rdataset_t *opt_6 = NULL;
        dns_ednsopt_t ednsopt6[3];
        ednsopt6[0].code = 1;
        ednsopt6[0].length = 5;
        ednsopt6[0].value = (unsigned char *)opt_value_bytes6_1;
        ednsopt6[1].code = 25;
        ednsopt6[1].length = 3;
        ednsopt6[1].value = (unsigned char *)opt_value_bytes6_2;
        ednsopt6[2].code = 22;
        ednsopt6[2].length = 2;
        ednsopt6[2].value = (unsigned char *)opt_value_bytes6_3;
        result = dns_message_buildopt(msg, &opt_6, 0, 1232, 0, ednsopt6, 3);
        dns_message_setopt(msg, opt_6);
        result = is_fragment_opt(msg);
        assert_true(result == ISC_R_SUCCESS);
        assert_int_equal(msg->fragment_nr, 12);
        assert_int_equal(msg->nr_fragments, 16);
        assert_int_equal(msg->fragment_flags, 1);

        // test case 7: when multiple 22's are found, it should return the first
        // 12, 16 and 2
        char opt_value_bytes7_1[] = { 0x31, 0x02};
        char opt_value_bytes7_2[] = { 0x31, 0x01};
        dns_rdataset_t *opt_7 = NULL;
        dns_ednsopt_t ednsopt7[2];
        ednsopt7[0].code = 22;
        ednsopt7[0].length = 2;
        ednsopt7[0].value = (unsigned char *)opt_value_bytes7_1;
        ednsopt7[1].code = 22;
        ednsopt7[1].length = 2;
        ednsopt7[1].value = (unsigned char *)opt_value_bytes7_2;
        result = dns_message_buildopt(msg, &opt_7, 0, 1232, 0, ednsopt7, 2);
        dns_message_setopt(msg, opt_7);
        result = is_fragment_opt(msg);
        assert_true(result == ISC_R_SUCCESS);
        assert_int_equal(msg->fragment_flags, 2);

        // clean up
        dns_message_detach(&msg);
        isc_mem_put(mctx, buffer, buffer_size);
    }
    else {
        fprintf(stderr, "Could not find file: %s\n", filename);
    }
}


// tests if OPT records are correctly created
ISC_RUN_TEST_IMPL(test_create_fragment_opt) {
    const char *filename = "testdata/udp_fragmentation/fragment_opt_test";
    buffer = load_binary_file(filename, &buffer_size);
    isc_result_t result;
    unsigned option_length;

    if(buffer != NULL) {
        isc_buffer_t buf;
        isc_buffer_init(&buf, buffer, buffer_size);
        isc_buffer_add(&buf, buffer_size);
        msg = NULL;
        dns_message_create(mctx, DNS_MESSAGE_INTENTPARSE, &msg);
        dns_message_parse(msg, &buf, DNS_MESSAGEPARSE_PRESERVEORDER);
        msg->from_to_wire = 2;
        msg->state = DNS_SECTION_ANY;
        unsigned opt_size, nr_options;
        unsigned new_opt_size, new_nr_options;

        // test case 1: create a new OPTION in message without OPT record
        dns_rdataset_t *tmp_opt = msg->opt;
        msg->opt = NULL;
        parse_opt(msg, &opt_size, &nr_options);
        assert_int_equal(opt_size, 0);
        assert_int_equal(nr_options, 0);
        result = create_fragment_opt(msg, 1, 2, 0);
        parse_opt(msg, &new_opt_size, &new_nr_options);
        assert_true(result == ISC_R_SUCCESS);
        assert_true(msg->opt != NULL);
        assert_int_equal(new_opt_size, 17);
        assert_int_equal(new_nr_options, 1);
        dns_message_setopt(msg, tmp_opt);


        // test case 2: create a new OPTION in message with existing OPT record without data, however, fragment_nr >= nr_fragments
        parse_opt(msg, &opt_size, &nr_options);
        assert_int_equal(opt_size, 11);
        assert_int_equal(nr_options, 0);
        result = create_fragment_opt(msg, 2, 2, 0);
        parse_opt(msg, &new_opt_size, &new_nr_options);
        assert_true(result == ISC_R_FAILURE);
        assert_int_equal(new_opt_size, 11);
        assert_int_equal(new_nr_options, 0);

        // test case 3: create a new OPTION in message with existing OPT record without data
        parse_opt(msg, &opt_size, &nr_options);
        assert_int_equal(opt_size, 11);
        assert_int_equal(nr_options, 0);
        result = create_fragment_opt(msg, 1, 2, 0);
        parse_opt(msg, &new_opt_size, &new_nr_options);
        assert_true(result == ISC_R_SUCCESS);
        assert_true(msg->opt != NULL);
        assert_int_equal(new_opt_size, 17);
        assert_int_equal(new_nr_options, 1);

        // test case 4: create an OPT with three options 21, 23
        //              should add option 22 at the end
        // create OPT record
        char opt_4_value_1_bytes[] = { 0xaa, 0xbb, 0xcc};
        char opt_4_value_2_bytes[] = { 0x01, 0x02, 0x03, 0x04, 0x05};
        dns_rdataset_t *opt_4 = NULL;
        dns_ednsopt_t ednsopt[2];
        ednsopt[0].code = 21;
        ednsopt[0].length = 3;
        ednsopt[0].value = (unsigned char *)opt_4_value_1_bytes;
        ednsopt[1].code = 23;
        ednsopt[1].length = 5;
        ednsopt[1].value = (unsigned char *)opt_4_value_2_bytes;
        result = dns_message_buildopt(msg, &opt_4, 0, 1232, 0, ednsopt, 2);
        dns_message_setopt(msg, opt_4);
        // get the rdata field to test against
        if (msg->opt != NULL) {
            dns_rdata_t rdata;
            isc_result_t result = dns_rdataset_first(msg->opt);
            if (result == ISC_R_SUCCESS) {
                dns_rdata_init(&rdata);
                dns_rdataset_current(msg->opt, &rdata);      
                // test opt
                result = parse_opt(msg, &opt_size, &nr_options);
                assert_true(result == ISC_R_SUCCESS);
                assert_int_equal(opt_size, 27);
                assert_int_equal(nr_options, 2);
                option_length = rdata.data[2] << 8 | rdata.data[3]; // first two bytes are option code
                assert_int_equal(3, option_length);
                compare_buffer(opt_4_value_1_bytes, rdata.data + 4, 3);
                result = create_fragment_opt(msg, 11, 33, 0);
                parse_opt(msg, &new_opt_size, &new_nr_options);
                assert_true(result == ISC_R_SUCCESS);
                assert_true(msg->opt != NULL);
                assert_int_equal(new_opt_size, 33);
                assert_int_equal(new_nr_options, 3);
            }
            else {
                assert_true(false); // should not happen
            }
        }
        else {
            assert_true(false); // should not happen
        }   
        
        // test case 5: overwrite existing OPTION 22
        // create OPT record
        char opt_5_value_1_bytes[] = { 0xaa, 0xbb, 0xcc};
        char opt_5_value_2_bytes[] = { 0x01, 0x02, 0x03, 0x04, 0x05};
        dns_rdataset_t *opt_5 = NULL;
        dns_ednsopt_t ednsopt5[2];
        ednsopt5[0].code = 21;
        ednsopt5[0].length = 3;
        ednsopt5[0].value = (unsigned char *)opt_5_value_1_bytes;
        ednsopt5[1].code = 22;
        ednsopt5[1].length = 5;
        ednsopt5[1].value = (unsigned char *)opt_5_value_2_bytes;
        result = dns_message_buildopt(msg, &opt_5, 0, 1232, 0, ednsopt5, 2);
        dns_message_setopt(msg, opt_5);
        // get the rdata field to test against
        if (msg->opt != NULL) {
            dns_rdata_t rdata;
            isc_result_t result = dns_rdataset_first(msg->opt);
            if (result == ISC_R_SUCCESS) {
                dns_rdata_init(&rdata);
                dns_rdataset_current(msg->opt, &rdata);      
                // test opt
                result = parse_opt(msg, &opt_size, &nr_options);
                assert_true(result == ISC_R_SUCCESS);
                assert_int_equal(opt_size, 27);
                assert_int_equal(nr_options, 2);
                option_length = rdata.data[2] << 8 | rdata.data[3]; // first two bytes are option code
                assert_int_equal(3, option_length);
                compare_buffer(opt_4_value_1_bytes, rdata.data + 4, 3);
                result = create_fragment_opt(msg, 11, 33, 0);
                parse_opt(msg, &new_opt_size, &new_nr_options);
                assert_true(result == ISC_R_SUCCESS);
                assert_true(msg->opt != NULL);
                assert_int_equal(new_opt_size, 24);
                assert_int_equal(new_nr_options, 2);
            }
            else {
                assert_true(false); // should not happen
            }
        }
        else {
            assert_true(false); // should not happen
        }   

        // test case 6: overflow flags    
        tmp_opt = msg->opt;
        msg->opt = NULL;
        result = parse_opt(msg, &opt_size, &nr_options);
        assert_true(result == ISC_R_SUCCESS);
        assert_int_equal(opt_size, 0);
        assert_int_equal(nr_options, 0);
        result = create_fragment_opt(msg, 11, 33, 32);
        parse_opt(msg, &new_opt_size, &new_nr_options);
        assert_true(result == ISC_R_SUCCESS);
        assert_true(msg->opt != NULL);
        assert_int_equal(new_opt_size, 17);
        assert_int_equal(new_nr_options, 1);
        if (msg->opt != NULL) {
            dns_rdata_t rdata;
            isc_result_t result = dns_rdataset_first(msg->opt);
            if (result == ISC_R_SUCCESS) {
                dns_rdata_init(&rdata);
                dns_rdataset_current(msg->opt, &rdata);     
                assert_int_equal(rdata.length, 6); 
                unsigned char expected[2] = {0x2e, 0x10};
                compare_buffer(rdata.data + 4, expected, 2);
            }
        }
        dns_message_setopt(msg, tmp_opt);

        // test case 7: delete OPTION
        result = create_fragment_opt(msg, 1, 33, 1);
        assert_true(result == ISC_R_SUCCESS);
        result = parse_opt(msg, &opt_size, &nr_options);
        result = delete_fragment_opt(msg);
        assert_true(result == ISC_R_SUCCESS);
        parse_opt(msg, &new_opt_size, &new_nr_options);
        assert_int_equal(new_opt_size, opt_size - 6);
        assert_int_equal(new_nr_options, nr_options - 1);

        // clean up
        dns_message_detach(&msg);
        isc_mem_put(mctx, buffer, buffer_size);
    }
    else {
        fprintf(stderr, "Could not find file: %s\n", filename);
    }

}

// tests if OPT records are properly created and subsequently detected by is_fragment
ISC_RUN_TEST_IMPL(test_create_and_is_fragment_opt) {
    const char *filename = "testdata/udp_fragmentation/fragment_opt_test";
    buffer = load_binary_file(filename, &buffer_size);
    isc_result_t result;

    if(buffer != NULL) {
        isc_buffer_t buf;
        isc_buffer_init(&buf, buffer, buffer_size);
        isc_buffer_add(&buf, buffer_size);
        msg = NULL;
        dns_message_create(mctx, DNS_MESSAGE_INTENTPARSE, &msg);
        dns_message_parse(msg, &buf, DNS_MESSAGEPARSE_PRESERVEORDER);
        msg->from_to_wire = 2;
        msg->state = DNS_SECTION_ANY;
        unsigned opt_size, nr_options;

        // test case 1: create a new OPTION in message without OPT record
        dns_rdataset_t *tmp_opt = msg->opt;
        msg->opt = NULL;
        parse_opt(msg, &opt_size, &nr_options);
        assert_int_equal(opt_size, 0);
        assert_int_equal(nr_options, 0);
        result = create_fragment_opt(msg, 11, 23, 0);
        assert_true(result == ISC_R_SUCCESS);
        result = is_fragment_opt(msg);
        assert_true(result == ISC_R_SUCCESS);
        assert_int_equal(msg->fragment_nr, 11);
        assert_int_equal(msg->nr_fragments, 23);
        assert_int_equal(msg->fragment_flags, 0);
        dns_message_setopt(msg, tmp_opt);

        // test case 2: add a new OPTION 22
        result = create_fragment_opt(msg, 12, 23, 3);
        assert_true(result == ISC_R_SUCCESS);
        result = is_fragment_opt(msg);
        assert_true(result == ISC_R_SUCCESS);
        assert_int_equal(msg->fragment_nr, 12);
        assert_int_equal(msg->nr_fragments, 23);
        assert_int_equal(msg->fragment_flags, 3);

        // clean up
        dns_message_detach(&msg);
        isc_mem_put(mctx, buffer, buffer_size);
    }
    else {
        fprintf(stderr, "Could not find file: %s\n", filename);
    }
}


ISC_RUN_TEST_IMPL(test_create_fragment_query_qname) {

    /*
    Name: response1-falcon512 
    Original PCAP file: /home/dev/qbf_src/data/resolver/mode 1/FALCON512.pcap
    Source: root NS (172.20.0.3)
    Destination: resolver (172.20.0.2)
    Size: 3244 bytes
    Nr. of fragments: 3
    */
    const char *filename = "testdata/message/response1-falcon512";
    const char *src_address = "172.20.0.3";
    buffer = load_binary_file(filename, &buffer_size);

    // outputs
    isc_result_t res;
    if(buffer != NULL) {

        isc_buffer_t input_buffer;
        isc_region_t region;
        region.base = buffer;
        region.length = buffer_size;
		isc_buffer_init(&input_buffer, region.base, region.length);
		isc_buffer_add(&input_buffer, region.length);

        // main test
        isc_buffer_t *query_buffer = NULL;
        res = create_fragment_query_qname(mctx, &input_buffer, 3, &query_buffer);
        assert_int_equal(res, ISC_R_SUCCESS);

        size_t exp_buffer_size;
        const char *exp_filename = "testdata/message/response1-falcon512-query3";
        unsigned char *expected_buffer = load_binary_file(exp_filename, &exp_buffer_size);
        assert_true(expected_buffer != NULL);
        if (expected_buffer != NULL) {
            assert_int_equal(exp_buffer_size, query_buffer->used);
            for (unsigned i = 0; i < exp_buffer_size; i++) {
                assert_true(((char *)(expected_buffer))[i] == ((char *)(query_buffer->base))[i]);
            }
            isc_mem_put(mctx, expected_buffer, exp_buffer_size);
        }

        // clean up
        if (query_buffer != NULL) {
            isc_buffer_free(&query_buffer);
        }
        isc_mem_put(mctx, buffer, buffer_size);
    }
    else {
        fprintf(stderr, "Could not find file: %s\n", filename);
    }
}

ISC_RUN_TEST_IMPL(test_create_fragment_query_opt) {
    /*
     * A RAW fragment request built from a response: OPCODE 7, same id and
     * question, EDNS option 22 with the wanted fragment number.
     */
    const char *filename = "testdata/message/response1-falcon512";
    buffer = load_binary_file(filename, &buffer_size);
    assert_non_null(buffer);

    isc_buffer_t input_buffer;
    isc_buffer_init(&input_buffer, buffer, buffer_size);
    isc_buffer_add(&input_buffer, buffer_size);

    dns_message_t *orig = NULL;
    dns_message_create(mctx, DNS_MESSAGE_INTENTPARSE, &orig);
    assert_int_equal(dns_message_parse(orig, &input_buffer, 0), ISC_R_SUCCESS);
    dns_name_t *orig_qname = NULL;
    assert_int_equal(dns_message_firstname(orig, DNS_SECTION_QUESTION), ISC_R_SUCCESS);
    dns_message_currentname(orig, DNS_SECTION_QUESTION, &orig_qname);
    dns_rdataset_t *orig_q = ISC_LIST_HEAD(orig_qname->list);
    assert_non_null(orig_q);

    isc_buffer_t *query_buffer = NULL;
    isc_result_t res = create_fragment_query_opt(mctx, &input_buffer, 3, 5, &query_buffer);
    assert_int_equal(res, ISC_R_SUCCESS);
    assert_non_null(query_buffer);
    assert_true(isc_buffer_usedlength(query_buffer) < 512);

    dns_message_t *q = NULL;
    dns_message_create(mctx, DNS_MESSAGE_INTENTPARSE, &q);
    isc_buffer_first(query_buffer);
    assert_int_equal(dns_message_parse(q, query_buffer, 0), ISC_R_SUCCESS);
    assert_int_equal(q->id, orig->id);
    assert_int_equal(q->opcode, dns_opcode_fragment);
    assert_true((q->flags & DNS_MESSAGEFLAG_QR) == 0);
    assert_int_equal(q->counts[DNS_SECTION_QUESTION], 1);
    assert_int_equal(q->counts[DNS_SECTION_ANSWER], 0);
    dns_name_t *qname = NULL;
    assert_int_equal(dns_message_firstname(q, DNS_SECTION_QUESTION), ISC_R_SUCCESS);
    dns_message_currentname(q, DNS_SECTION_QUESTION, &qname);
    assert_true(dns_name_equal(qname, orig_qname));
    dns_rdataset_t *qrds = ISC_LIST_HEAD(qname->list);
    assert_non_null(qrds);
    assert_int_equal(qrds->type, orig_q->type);
    assert_int_equal(qrds->rdclass, orig_q->rdclass);
    assert_non_null(q->opt);
    assert_int_equal(is_fragment_opt(q), ISC_R_SUCCESS);
    assert_int_equal(q->fragment_nr, 3);
    assert_int_equal(q->nr_fragments, 5);

    // fragment number must be below the total
    isc_buffer_t *bad = NULL;
    assert_int_equal(create_fragment_query_opt(mctx, &input_buffer, 5, 5, &bad), ISC_R_FAILURE);
    assert_null(bad);

    dns_message_detach(&q);
    dns_message_detach(&orig);
    isc_buffer_free(&query_buffer);
    isc_mem_put(mctx, buffer, buffer_size);
    buffer = NULL;
}

ISC_TEST_LIST_START
ISC_TEST_ENTRY(test_is_fragment)
ISC_TEST_ENTRY(test_is_fragment_opt)
ISC_TEST_ENTRY(test_create_fragment_opt)
ISC_TEST_ENTRY(test_create_and_is_fragment_opt)
ISC_TEST_ENTRY(test_create_fragment_query_qname)
ISC_TEST_ENTRY(test_create_fragment_query_opt)
ISC_TEST_LIST_END

ISC_TEST_MAIN
