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

/*
 * RAW UDP fragmentation tests: fragment real PQC responses from
 * testdata/message, check every fragment, reassemble and compare.
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
#include <unistd.h>

#define UNIT_TESTING
#include <cmocka.h>

#include <isc/buffer.h>
#include <isc/loop.h>
#include <isc/mem.h>
#include <isc/region.h>
#include <isc/result.h>
#include <isc/util.h>

#include <dns/fcache.h>
#include <dns/message.h>
#include <dns/raw.h>
#include <dns/types.h>
#include <dns/udp_fragmentation.h>

#include <tests/dns.h>

#define MAX_UDP 1232

static unsigned char *
load_binary_file(const char *filename, size_t *out_size) {
	FILE *file = fopen(filename, "rb");
	if (file == NULL) {
		return NULL;
	}
	fseek(file, 0, SEEK_END);
	long file_size = ftell(file);
	fseek(file, 0, SEEK_SET);
	if (file_size <= 0) {
		fclose(file);
		return NULL;
	}
	unsigned char *data = isc_mem_get(mctx, file_size);
	if (fread(data, 1, file_size, file) != (size_t)file_size) {
		isc_mem_put(mctx, data, file_size);
		fclose(file);
		return NULL;
	}
	fclose(file);
	*out_size = file_size;
	return data;
}

/*
 * Parses 'data' and prepares the message the way ns_client_send() sees it
 * (render intent, OPT detached).
 */
static dns_message_t *
parse_response(unsigned char *data, size_t size, dns_rdataset_t **optp) {
	dns_message_t *msg = NULL;
	isc_buffer_t buf;

	isc_buffer_init(&buf, data, size);
	isc_buffer_add(&buf, size);
	dns_message_create(mctx, DNS_MESSAGE_INTENTPARSE, &msg);
	assert_int_equal(dns_message_parse(msg, &buf,
					   DNS_MESSAGEPARSE_PRESERVEORDER),
			 ISC_R_SUCCESS);
	assert_non_null(msg->opt);

	*optp = msg->opt;
	msg->opt = NULL;
	msg->from_to_wire = DNS_MESSAGE_INTENTRENDER;
	msg->state = DNS_SECTION_ANY;
	return msg;
}

static void
check_file(fcache_t *fcache, const char *filename, unsigned expected_frags) {
	size_t size = 0;
	unsigned char *data = load_binary_file(filename, &size);
	assert_non_null(data);

	dns_rdataset_t *opt = NULL;
	dns_message_t *msg = parse_response(data, size, &opt);
	const char *addr = "172.20.0.3#5353";
	unsigned counts[DNS_SECTION_MAX];
	for (unsigned i = 0; i < DNS_SECTION_MAX; i++) {
		counts[i] = msg->counts[i];
	}

	unsigned char key[69];
	unsigned keysize = sizeof(key);
	fcache_create_key(msg->id, addr, key, &keysize);

	/* a huge datagram limit: nothing to fragment */
	unsigned nr = 0;
	assert_int_equal(fcache_count(fcache), 0);
	assert_int_equal(raw_fragment(mctx, fcache, msg, opt, addr, 65535, 0,
				      &nr),
			 ISC_R_RANGE);
	assert_int_equal(fcache_count(fcache), 0);
	assert_null(msg->buffer);
	assert_null(msg->opt);

	/* the real thing */
	assert_int_equal(raw_fragment(mctx, fcache, msg, opt, addr, MAX_UDP, 0,
				      &nr),
			 ISC_R_SUCCESS);
	assert_int_equal(nr, expected_frags);
	assert_int_equal(fcache_count(fcache), 1);
	assert_null(msg->buffer); /* the message can be rendered again */

	/* a second call must not clobber the cached entry */
	assert_int_equal(raw_fragment(mctx, fcache, msg, opt, addr, MAX_UDP, 0,
				      NULL),
			 ISC_R_EXISTS);

	/* every fragment: well-formed envelope, parseable, right numbers */
	unsigned payload_total = 0;
	for (unsigned i = 0; i < nr; i++) {
		isc_buffer_t *frag = NULL;
		isc_region_t r;
		unsigned frag_nr = 99, total = 0, off = 0;

		assert_int_equal(fcache_get_fragment(fcache, key, keysize, i,
						     &frag),
				 ISC_R_SUCCESS);
		isc_buffer_usedregion(frag, &r);
		assert_true(r.length <= MAX_UDP);
		assert_true(raw_is_fragment(&r));
		assert_int_equal(raw_parse_envelope(&r, &frag_nr, &total, &off),
				 ISC_R_SUCCESS);
		assert_int_equal(frag_nr, i);
		assert_int_equal(total, nr);
		assert_true(off < r.length);
		payload_total += r.length - off;

		/* same id, RCODE 12, question + OPT, option 22 */
		assert_int_equal(r.base[0], (msg->id >> 8) & 0xff);
		assert_int_equal(r.base[1], msg->id & 0xff);
		assert_int_equal(r.base[3] & 0x0f, RAW_RCODE);
		assert_int_equal(r.base[2] & 0x02, 0); /* no TC */

		dns_message_t *env = NULL;
		isc_buffer_t envbuf;
		isc_buffer_init(&envbuf, r.base, r.length);
		isc_buffer_add(&envbuf, r.length);
		dns_message_create(mctx, DNS_MESSAGE_INTENTPARSE, &env);
		assert_int_equal(dns_message_parse(env, &envbuf, 0),
				 ISC_R_SUCCESS);
		assert_int_equal(env->id, msg->id);
		assert_int_equal(env->rcode, RAW_RCODE);
		assert_int_equal(env->counts[DNS_SECTION_QUESTION], 1);
		assert_int_equal(env->counts[DNS_SECTION_ANSWER], 0);
		assert_int_equal(is_fragment_opt(env), ISC_R_SUCCESS);
		assert_int_equal(env->fragment_nr, i);
		assert_int_equal(env->nr_fragments, nr);
		dns_message_detach(&env);

		/* all fragments but the last one are full */
		if (i + 1 < nr) {
			assert_int_equal(r.length, MAX_UDP);
		}
	}

	/* a fragment request built from fragment 0 */
	{
		isc_buffer_t *frag0 = NULL, *req = NULL;
		assert_int_equal(fcache_get_fragment(fcache, key, keysize, 0,
						     &frag0),
				 ISC_R_SUCCESS);
		assert_int_equal(create_fragment_query_opt(mctx, frag0, nr - 1,
							   nr, &req),
				 ISC_R_SUCCESS);
		dns_message_t *q = NULL;
		dns_message_create(mctx, DNS_MESSAGE_INTENTPARSE, &q);
		isc_buffer_first(req);
		assert_int_equal(dns_message_parse(q, req, 0), ISC_R_SUCCESS);
		assert_int_equal(q->id, msg->id);
		assert_int_equal(q->opcode, dns_opcode_fragment);
		assert_int_equal(q->counts[DNS_SECTION_QUESTION], 1);
		assert_int_equal(is_fragment_opt(q), ISC_R_SUCCESS);
		assert_int_equal(q->fragment_nr, nr - 1);
		assert_int_equal(q->nr_fragments, nr);
		assert_true(isc_buffer_usedlength(req) < 512);
		dns_message_detach(&q);
		isc_buffer_free(&req);
	}

	/* reassemble */
	fragment_cache_entry_t *entry = NULL;
	assert_int_equal(fcache_take_complete(fcache, key, keysize, &entry),
			 ISC_R_SUCCESS);
	assert_non_null(entry);
	assert_int_equal(fcache_count(fcache), 0);

	isc_buffer_t *full = NULL;
	assert_int_equal(raw_reassemble(mctx, entry, &full), ISC_R_SUCCESS);
	fcache_free_taken_entry(fcache, entry);
	assert_int_equal(isc_buffer_usedlength(full), payload_total);
	assert_true(isc_buffer_usedlength(full) > MAX_UDP);

	/* the reassembled bytes are the original message (modulo flags) */
	assert_int_equal(isc_buffer_usedlength(full), size);
	unsigned char *fb = isc_buffer_base(full);
	assert_memory_equal(fb, data, 2);	      /* id */
	assert_memory_equal(fb + 4, data + 4, size - 4); /* everything else */

	/* and it parses back to the same message */
	dns_message_t *out = NULL;
	dns_message_create(mctx, DNS_MESSAGE_INTENTPARSE, &out);
	isc_buffer_first(full);
	assert_int_equal(dns_message_parse(out, full,
					   DNS_MESSAGEPARSE_PRESERVEORDER),
			 ISC_R_SUCCESS);
	assert_int_equal(out->id, msg->id);
	assert_int_equal(out->rcode, msg->rcode);
	assert_non_null(out->opt);
	assert_int_equal(is_fragment_opt(out), ISC_R_NOTFOUND);
	for (unsigned i = 0; i < DNS_SECTION_MAX; i++) {
		assert_int_equal(out->counts[i], counts[i]);
	}
	assert_true((out->flags & DNS_MESSAGEFLAG_TC) == 0);
	dns_message_detach(&out);
	isc_buffer_free(&full);

	/* the original message is not a fragment */
	{
		isc_region_t r = { .base = data, .length = size };
		assert_false(raw_is_fragment(&r));
		assert_int_equal(raw_parse_envelope(&r, NULL, NULL, NULL),
				 ISC_R_NOTFOUND);
	}

	msg->opt = opt;
	dns_message_detach(&msg);
	isc_mem_put(mctx, data, size);
}

ISC_LOOP_TEST_IMPL(raw_fragment_and_reassemble) {
	fcache_t *fcache = NULL;
	fcache_init(&fcache, loopmgr, 10, 20);

	/*
	 * Envelope for these files: 12 (header) + qname + 4 + 17 (OPT with
	 * option 22).  "example" -> 1183 payload bytes per fragment.
	 */
	check_file(fcache, "testdata/message/response1-falcon512", 3);
	check_file(fcache, "testdata/message/falcon512-full-message", 3);
	check_file(fcache, "testdata/message/P256_FALCON512", 3);
	check_file(fcache, "testdata/message/response1-dilithium", 7);
	check_file(fcache,
		   "testdata/message/P256_FALCON512-test.example.local2", 3);

	fcache_deinit(&fcache);
	isc_loopmgr_shutdown(loopmgr);
}

ISC_RUN_TEST_IMPL(raw_parse_envelope_garbage) {
	unsigned char short_msg[8] = { 0 };
	isc_region_t r = { .base = short_msg, .length = sizeof(short_msg) };
	assert_int_equal(raw_parse_envelope(&r, NULL, NULL, NULL),
			 ISC_R_UNEXPECTEDEND);

	/* RCODE 12 but no OPT at all */
	unsigned char hdr[12] = { 0x12, 0x34, 0x80, 0x0c, 0, 0, 0, 0,
				  0,	0,    0,    0 };
	r.base = hdr;
	r.length = sizeof(hdr);
	assert_int_equal(raw_parse_envelope(&r, NULL, NULL, NULL),
			 ISC_R_NOTFOUND);

	/* RCODE 12, one question, truncated RR */
	unsigned char trunc[] = { 0x12, 0x34, 0x80, 0x0c, 0, 1, 0, 0, 0, 0, 0,
				  1,	1,    'a',  0,	  0, 1, 0, 1, 0 };
	r.base = trunc;
	r.length = sizeof(trunc);
	assert_int_equal(raw_parse_envelope(&r, NULL, NULL, NULL),
			 ISC_R_UNEXPECTEDEND);

	/* a well-formed envelope with fragment 2 of 5, followed by junk */
	unsigned char env[] = { 0x12, 0x34, 0x80, 0x0c, 0, 1, 0, 0, 0, 0, 0, 1,
				/* question a. A IN */
				1, 'a', 0, 0, 1, 0, 1,
				/* OPT: root, type 41, class 1232, ttl 0, rdlen 6 */
				0, 0, 41, 0x04, 0xd0, 0, 0, 0, 0, 0, 6,
				/* option 22, length 2, value 2<<10 | 5<<4 */
				0, 22, 0, 2, 0x08, 0x50,
				/* payload */
				0xde, 0xad, 0xbe, 0xef };
	unsigned frag_nr = 0, nr = 0, off = 0;
	r.base = env;
	r.length = sizeof(env);
	assert_int_equal(raw_parse_envelope(&r, &frag_nr, &nr, &off),
			 ISC_R_SUCCESS);
	assert_int_equal(frag_nr, 2);
	assert_int_equal(nr, 5);
	assert_int_equal(off, sizeof(env) - 4);
	assert_true(raw_is_fragment(&r));

	/* fragment number >= total */
	env[sizeof(env) - 5] = 0x50; /* 5<<10 | 5<<4 -> 0x1450 */
	env[sizeof(env) - 6] = 0x14;
	assert_int_equal(raw_parse_envelope(&r, NULL, NULL, NULL),
			 ISC_R_RANGE);
}

ISC_RUN_TEST_IMPL(raw_prefetch_candidate_check) {
	/* a. IN A query with EDNS + DO: the 1-RTT prefetch case */
	unsigned char q[] = { 0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 1,
			      /* question: a. A IN */
			      1, 'a', 0, 0, 1, 0, 1,
			      /* OPT: root, type 41, class 1232, ttl DO, rdlen 0 */
			      0, 0, 41, 0x04, 0xd0, 0, 0, 0x80, 0, 0, 0 };
	isc_region_t r = { .base = q, .length = sizeof(q) };
	assert_true(raw_prefetch_candidate(&r));

	q[26] = 0x00; /* clear the DO bit: unsigned answer, no prefetch */
	assert_false(raw_prefetch_candidate(&r));
	q[26] = 0x80;

	q[2] = 0x81; /* QR set: a response, not a query */
	assert_false(raw_prefetch_candidate(&r));
	q[2] = 0x38; /* OPCODE 7: already a fragment request */
	assert_false(raw_prefetch_candidate(&r));
	q[2] = 0x01;

	r.length = 19; /* no additional section at all: no EDNS */
	q[11] = 0;
	assert_false(raw_prefetch_candidate(&r));
	q[11] = 1;
	r.length = sizeof(q);

	r.length = 25; /* truncated OPT */
	assert_false(raw_prefetch_candidate(&r));
}

ISC_TEST_LIST_START
ISC_TEST_ENTRY_CUSTOM(raw_fragment_and_reassemble, setup_loopmgr,
		      teardown_loopmgr)
ISC_TEST_ENTRY(raw_parse_envelope_garbage)
ISC_TEST_ENTRY(raw_prefetch_candidate_check)
ISC_TEST_LIST_END

ISC_TEST_MAIN
