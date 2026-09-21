#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <isc/buffer.h>
#include <isc/log.h>
#include <isc/mem.h>
#include <isc/result.h>
#include <isc/sockaddr.h>
#include <isc/types.h>
#include <isc/util.h>

#include <dns/compress.h>
#include <dns/log.h>
#include <dns/message.h>
#include <dns/name.h>
#include <dns/rdata.h>
#include <dns/rdatalist.h>
#include <dns/rdataset.h>
#include <dns/types.h>
#include <dns/udp_fragmentation.h>

#define FRAG_LOG(level, ...)                                            \
	isc_log_write(dns_lctx, DNS_LOGCATEGORY_FRAGMENTATION,          \
		      DNS_LOGMODULE_FRAGMENT, level, __VA_ARGS__)

// TODO: remove mctx and use an array for name
bool
is__fragment_qname(isc_mem_t *mctx, dns_message_t *msg, bool force) {
	// check if already done
	if (msg->is_fragment && !force) {
		return true;
	}
	// check if it has name in the question section
	if (dns_message_firstname(msg, DNS_SECTION_QUESTION) != ISC_R_SUCCESS) {
		return false;
	}
	// set default values
	// will get overwritten if valid fragment
	bool success = false;
	msg->fragment_nr = 0;
	msg->is_fragment = false;
	// names are compressed use dns_name_tostring to get decompressed string
	char *qname = NULL;
	dns_name_tostring(msg->cursors[DNS_SECTION_QUESTION], &qname, mctx);

	// should start with '?'
	if (qname[0] == '?') {
		int i = 1;
		int qname_len = strlen(qname);
		// find second '?'
		for (; i < qname_len; i++) {
			if (qname[i] == '?') {
				break;
			}
		}

		// second '?' not found
		if (i == qname_len) {
			FRAG_LOG(ISC_LOG_DEBUG(8),
				 "not a valid fragment for qname %s", qname);
			success = false;
		} else {
			// parse fragment number
			char *frag_str = isc_mem_get(mctx, i * sizeof(char));
			strncpy(frag_str, qname + 1, i - 1);
			frag_str[i - 1] = '\0';
			char *end;
			unsigned long nr = strtoul(frag_str, &end, 10);
			if (frag_str == end) {
				FRAG_LOG(ISC_LOG_DEBUG(8),
					 "fragment number could not be parsed "
					 "for qname %s",
					 qname);
				success = false;
			} else if (*end != '\0') {
				FRAG_LOG(ISC_LOG_DEBUG(8),
					 "incorrect fragment number ensure "
					 "format is ?[nr]?[qname]");
				success = false;
			} else {
				// fragment found, set msg values
				msg->fragment_nr = nr - 1;
				msg->is_fragment = true;
				// TODO: parse qname
				success = true;
			}
			// free memory
			isc_mem_put(mctx, frag_str, i * sizeof(char));
		}
	}
	isc_mem_free(mctx, qname);
	return success;
}

isc_result_t
is_fragment_opt(dns_message_t *msg) {
	if (msg->opt != NULL) {
		dns_ednsopt_t ednsopt;
		dns_rdata_t rdata;
		isc_buffer_t optbuf;
		isc_result_t result = dns_rdataset_first(msg->opt);
		if (result == ISC_R_SUCCESS) {
			dns_rdata_init(&rdata);
			dns_rdataset_current(msg->opt, &rdata);
			isc_buffer_init(&optbuf, rdata.data, rdata.length);
			isc_buffer_add(&optbuf, rdata.length);

			// parse ednsopt
			while (isc_buffer_remaininglength(&optbuf) >= 4) {
				ednsopt.code = isc_buffer_getuint16(&optbuf);
				ednsopt.length = isc_buffer_getuint16(&optbuf);
				if (isc_buffer_remaininglength(&optbuf) >=
				    ednsopt.length) {
					ednsopt.value =
						isc_buffer_current(&optbuf);
					isc_buffer_forward(&optbuf,
							   ednsopt.length);
					// check if this an OPTION for UDP
					// fragmentation format:  | FRAGMENT
					// NR. (6b) | NR. OF FRAGMENTS (6b) |
					// FLAGS 4(b) | : 2 Bytes total
					if (ednsopt.code == OPTION_CODE &&
					    ednsopt.length == OPTION_LENGTH)
					{
						uint16_t fragment_nr,
							nr_fragments, flags;
						unsigned value =
							ednsopt.value[0] << 8 |
							ednsopt.value[1];
						fragment_nr = value >> 10 & 0x3f;
						nr_fragments = value >> 4 & 0x3f;
						flags = value & 0xf;
						msg->is_fragment = true;
						msg->fragment_nr = fragment_nr;
						msg->nr_fragments = nr_fragments;
						msg->fragment_flags = flags;
						// frag nr check
						if (fragment_nr >= nr_fragments) {
							return ISC_R_FAILURE;
						}
						return ISC_R_SUCCESS;
					}
				} else {
					return ISC_R_FAILURE;
				}
			}
			return ISC_R_NOTFOUND; // OPTION 22 not found
		}
	}
	return ISC_R_EMPTY; // no OPT record found
}

isc_result_t
parse_opt(dns_message_t *msg, unsigned *opt_size, unsigned *nr_options) {
	*opt_size = 0;
	*nr_options = 0;
	if (msg->opt != NULL) {
		dns_rdata_t rdata;
		isc_buffer_t optbuf;
		isc_result_t result = dns_rdataset_first(msg->opt);
		if (result == ISC_R_SUCCESS) {
			dns_rdata_init(&rdata);
			dns_rdataset_current(msg->opt, &rdata);
			isc_buffer_init(&optbuf, rdata.data, rdata.length);
			isc_buffer_add(&optbuf, rdata.length);
			*opt_size = rdata.length + 11; // only 1 rdata for an
						       // OPT record but
						       // multiple options are
						       // possible
			while (isc_buffer_remaininglength(&optbuf) >= 4) {
				isc_buffer_getuint16(&optbuf);
				unsigned option_length =
					isc_buffer_getuint16(&optbuf);
				// check if enough space is available
				if (isc_buffer_remaininglength(&optbuf) >=
				    option_length) {
					isc_buffer_forward(&optbuf,
							   option_length);
				} else {
					return ISC_R_FAILURE;
				}
				(*nr_options)++;
			}
		}
	}
	return ISC_R_SUCCESS;
}

isc_result_t
create__fragment_opt(dns_message_t *msg, const unsigned frag_nr,
		     const unsigned nr_fragments, const unsigned fragment_flags,
		     bool skip) {
	// copy opt if exists, else create new one
	isc_result_t result;
	dns_rdataset_t *opt = NULL;
	dns_rdata_t rdata;
	isc_buffer_t optbuf;
	unsigned version = 0;
	uint16_t udpsize = 1232; // max UDP packet size
	unsigned flags = DNS_MESSAGEEXTFLAG_DO;
	dns_ednsopt_t ednsopts[DNS_EDNSOPTIONS + 1]; // we allow for a max of 9
	size_t opts_count = 0;
	/*
	 * The option value must stay alive until dns_message_buildopt() has
	 * copied it, so it lives at function scope.
	 */
	unsigned char value[2];

	// frag nr check
	if (frag_nr >= nr_fragments) {
		return ISC_R_FAILURE;
	}

	// parse the old opt message if exists
	if (msg->opt != NULL) {
		result = dns_rdataset_first(msg->opt);
		if (result == ISC_R_SUCCESS) {
			// copy buffer
			dns_rdata_init(&rdata);
			dns_rdataset_current(msg->opt, &rdata);
			isc_buffer_init(&optbuf, rdata.data, rdata.length);
			isc_buffer_add(&optbuf, rdata.length);

			// parse count and ednsopts and add to array
			while (isc_buffer_remaininglength(&optbuf) >= 4) {
				REQUIRE(opts_count < DNS_EDNSOPTIONS);
				ednsopts[opts_count].code =
					isc_buffer_getuint16(&optbuf);
				ednsopts[opts_count].length =
					isc_buffer_getuint16(&optbuf);
				// test if enough buffer space is available
				if (isc_buffer_remaininglength(&optbuf) >=
				    ednsopts[opts_count].length)
				{
					ednsopts[opts_count].value =
						isc_buffer_current(&optbuf);
					isc_buffer_forward(
						&optbuf,
						ednsopts[opts_count].length);
				} else {
					return ISC_R_FAILURE;
				}
				if (ednsopts[opts_count].code == OPTION_CODE) {
					continue; // skip this entry, we will
						  // overwrite it
				}
				opts_count++;
			}

			// copy values
			version = msg->opt->ttl >> 16;
			flags = msg->opt->ttl & 0xffff;
			udpsize = msg->opt->rdclass;
		}
	}
	if (!skip) {
		// add the new opt data
		ednsopts[opts_count].code = OPTION_CODE;
		ednsopts[opts_count].length = 2;
		// 6 bits for frag_nr, 6 bits for nr_fragments, and 4 bits for
		// flags
		uint16_t data = ((frag_nr & 0x3f) << 10) |
				((nr_fragments & 0x3f) << 4) |
				(fragment_flags & 0xf);
		value[0] = (data >> 8);
		value[1] = data & 0xff;
		ednsopts[opts_count].value = value;
		opts_count++;
	}

	// build and set opt record
	result = dns_message_buildopt(msg, &opt, version, udpsize, flags,
				      ednsopts, opts_count);
	if (result != ISC_R_SUCCESS) {
		return result;
	}
	return dns_message_setopt(msg, opt);
}

void
fcache_create_key(dns_messageid_t id, const char *client_address,
		  unsigned char *key, unsigned *keysize) {
	REQUIRE(*keysize >= 64);
	int tmp = snprintf((char *)key, *keysize, "%x-%s", id, client_address);
	*keysize = tmp > 0 ? (unsigned)tmp : *keysize; // set keysize to string
						       // length
}

unsigned
calc_dnskey_header_size(void) {
	return 4;
}

unsigned
calc_name_size(unsigned char *base, unsigned length) {
	unsigned size = 0;
	while (base[size] != 0 && size < length) {
		size++;
	}
	return size;
}

unsigned
calc_rrsig_header_size(dns_rdata_t *rdata) {
	unsigned header_size = 18;
	// signer's name length is variable
	while (rdata->data[header_size] != 0 && header_size < rdata->length) {
		header_size++;
	}
	return ++header_size;
}

void
printmessage(isc_mem_t *mctx, dns_message_t *msg) {
	isc_buffer_t b;
	char *buf = NULL;
	int len = 1024;
	isc_result_t result = ISC_R_SUCCESS;

	do {
		buf = isc_mem_get(mctx, len);

		isc_buffer_init(&b, buf, len);
		result = dns_message_totext(msg, &dns_master_style_debug, 0,
					    &b);
		if (result == ISC_R_NOSPACE) {
			isc_mem_put(mctx, buf, len);
			len *= 2;
		} else if (result == ISC_R_SUCCESS) {
			printf("%.*s\n", (int)isc_buffer_usedlength(&b), buf);
		}
	} while (result == ISC_R_NOSPACE);

	if (buf != NULL) {
		isc_mem_put(mctx, buf, len);
	}
}

/*
 * Clones a complete section from source to target.  Names and rdatasets
 * are shallow clones: they reference the source message's data, so the
 * target must be rendered while the source is still alive.
 */
isc_result_t
section_clone(dns_message_t *source, dns_message_t *target,
	      const unsigned section) {
	REQUIRE(section < DNS_SECTION_MAX);
	REQUIRE(DNS_MESSAGE_VALID(source));
	REQUIRE(DNS_MESSAGE_VALID(target));
	isc_result_t ret = ISC_R_SUCCESS;
	for (isc_result_t result = dns_message_firstname(source, section);
	     result == ISC_R_SUCCESS;
	     result = dns_message_nextname(source, section))
	{
		dns_name_t *name = NULL;
		dns_message_currentname(source, section, &name);
		dns_name_t *new_name = NULL;
		dns_message_gettempname(target, &new_name);
		dns_name_clone(name, new_name);
		for (dns_rdataset_t *rdataset = ISC_LIST_HEAD(name->list);
		     rdataset != NULL; rdataset = ISC_LIST_NEXT(rdataset, link))
		{
			dns_rdataset_t *new_rdataset = NULL;
			dns_message_gettemprdataset(target, &new_rdataset);
			dns_rdataset_clone(rdataset, new_rdataset);
			new_rdataset->attributes &= ~DNS_RDATASETATTR_RENDERED;
			ISC_LIST_APPEND(new_name->list, new_rdataset, link);
		}
		dns_message_addname(target, new_name, section);
	}
	// clone OPT if in the additional section
	if (source->opt != NULL && section == DNS_SECTION_ADDITIONAL) {
		dns_rdataset_t *new_opt = NULL;
		dns_message_gettemprdataset(target, &new_opt);
		dns_rdataset_clone(source->opt, new_opt);
		ret = dns_message_setopt(target, new_opt);
	}
	return ret;
}

/*
 * Creates a fragment request for fragment 'fragment_nr' (of 'nr_fragments')
 * from a datagram that carries the wanted id and question: OPCODE 7 with an
 * OPT record holding option 22.
 */
isc_result_t
create_fragment_query_opt(isc_mem_t *mctx, isc_buffer_t *buffer,
			  uint fragment_nr, uint nr_fragments,
			  isc_buffer_t **question_buffer) {
	REQUIRE(question_buffer != NULL);
	REQUIRE(*question_buffer == NULL);

	isc_result_t result = ISC_R_FAILURE;
	dns_message_t *parsed = NULL;
	dns_message_t *query = NULL;
	dns_compress_t cctx;
	bool compression_initialized = false;

	/* parse the original message (only header + question are used) */
	dns_message_create(mctx, DNS_MESSAGE_INTENTPARSE, &parsed);
	isc_buffer_first(buffer);
	result = dns_message_parse(parsed, buffer,
				   DNS_MESSAGEPARSE_BESTEFFORT |
					   DNS_MESSAGEPARSE_IGNORETRUNCATION);
	if (result != ISC_R_SUCCESS && result != DNS_R_RECOVERABLE) {
		FRAG_LOG(ISC_LOG_DEBUG(8),
			 "could not parse message in "
			 "create_fragment_query_opt: %s",
			 isc_result_totext(result));
		goto done;
	}

	dns_message_create(mctx, DNS_MESSAGE_INTENTRENDER, &query);
	query->id = parsed->id;
	query->opcode = dns_opcode_fragment;

	result = section_clone(parsed, query, DNS_SECTION_QUESTION);
	if (result != ISC_R_SUCCESS) {
		goto done;
	}
	result = create_fragment_opt(query, fragment_nr, nr_fragments, 0);
	if (result != ISC_R_SUCCESS) {
		FRAG_LOG(ISC_LOG_DEBUG(8),
			 "could not attach OPT record in "
			 "create_fragment_query_opt");
		goto done;
	}

	isc_buffer_allocate(mctx, question_buffer, 512);
	dns_compress_init(&cctx, mctx, 0);
	compression_initialized = true;

	result = dns_message_renderbegin(query, &cctx, *question_buffer);
	if (result != ISC_R_SUCCESS) {
		goto done;
	}
	result = dns_message_rendersection(query, DNS_SECTION_QUESTION, 0);
	if (result != ISC_R_SUCCESS) {
		goto done;
	}
	result = dns_message_renderend(query);
	if (result != ISC_R_SUCCESS) {
		goto done;
	}
	query->buffer = NULL; /* the caller owns the buffer */

done:
	if (compression_initialized) {
		dns_compress_invalidate(&cctx);
	}
	if (result != ISC_R_SUCCESS && *question_buffer != NULL) {
		isc_buffer_free(question_buffer);
	}
	if (query != NULL) {
		query->buffer = NULL;
		dns_message_detach(&query);
	}
	if (parsed != NULL) {
		dns_message_detach(&parsed);
	}
	return result;
}

/*
 * Creates a fragment query by changing the qname to ?N?qname (QBF).
 */
isc_result_t
create_fragment_query_qname(isc_mem_t *mctx, isc_buffer_t *buffer,
			    uint fragment_nr, isc_buffer_t **question_buffer) {
	REQUIRE(question_buffer != NULL && *question_buffer == NULL);

	// parse buffer into dns_message_t
	dns_message_t *msg = NULL;
	dns_message_t *question = NULL;
	dns_message_create(mctx, DNS_MESSAGE_INTENTPARSE, &msg);
	isc_buffer_first(buffer); // start from 0
	isc_result_t result = dns_message_parse(msg, buffer, 0);
	if (result == ISC_R_SUCCESS) {
		// get question
		dns_name_t *orig_name = NULL;
		result = dns_message_firstname(msg, DNS_SECTION_QUESTION);
		if (result == ISC_R_SUCCESS) {
			dns_message_currentname(msg, DNS_SECTION_QUESTION,
						&orig_name);
			char *name_str = NULL;
			dns_name_tostring(orig_name, &name_str, mctx);
			char new_name_str[128];
			snprintf(new_name_str, 128, "?%u?%s", fragment_nr,
				 name_str);

			// get first rdataset
			dns_rdataset_t *rdataset = ISC_LIST_HEAD(orig_name->list);
			REQUIRE(rdataset != NULL);

			// set up question
			dns_message_create(mctx, DNS_MESSAGE_INTENTRENDER,
					   &question);
			dns_name_t *qname = NULL;
			dns_rdataset_t *qrdataset = NULL;

			dns_message_gettempname(question, &qname);
			dns_message_gettemprdataset(question, &qrdataset);
			dns_name_fromstring(qname, new_name_str, NULL, 0, mctx);
			dns_rdataset_makequestion(qrdataset, rdataset->rdclass,
						  rdataset->type);
			ISC_LIST_APPEND(qname->list, qrdataset, link);

			// add name and set id
			dns_message_addname(question, qname,
					    DNS_SECTION_QUESTION);
			question->id = msg->id;

			// set opt
			if (msg->opt != NULL) {
				REQUIRE(dns_rdataset_count(msg->opt) == 1);
				dns_rdataset_t *new_opt_rdataset = NULL;
				dns_message_gettemprdataset(question,
							    &new_opt_rdataset);

				// get first rdata from msg->opt
				REQUIRE(dns_rdataset_first(msg->opt) ==
					ISC_R_SUCCESS);
				dns_rdata_t rdata = DNS_RDATA_INIT;
				dns_rdataset_current(msg->opt, &rdata);
				isc_region_t rdata_region;
				dns_rdata_toregion(&rdata, &rdata_region);

				// prepare new rdata
				dns_rdata_t *new_opt_rdata = NULL;
				dns_message_gettemprdata(question,
							 &new_opt_rdata);
				dns_rdata_fromregion(new_opt_rdata, rdata.rdclass,
						     rdata.type, &rdata_region);

				// add to new rdataset
				dns_rdatalist_t *rdatalist = NULL;
				dns_message_gettemprdatalist(question,
							     &rdatalist);
				ISC_LIST_APPEND(rdatalist->rdata, new_opt_rdata,
						link);
				// copy values
				rdatalist->rdclass = msg->opt->rdclass;
				rdatalist->type = msg->opt->type;
				rdatalist->ttl = msg->opt->ttl;
				dns_rdatalist_tordataset(rdatalist,
							 new_opt_rdataset);
				REQUIRE(dns_message_setopt(question,
							   new_opt_rdataset) ==
					ISC_R_SUCCESS);
			}

			// parsing: only question and additional
			dns_compress_t cctx;
			isc_buffer_allocate(mctx, question_buffer, 1232);
			dns_compress_init(&cctx, mctx, 0);
			result = dns_message_renderbegin(question, &cctx,
							 *question_buffer);
			if (result != ISC_R_SUCCESS) {
				goto done;
			}
			result = dns_message_rendersection(
				question, DNS_SECTION_QUESTION, 0);
			if (result != ISC_R_SUCCESS) {
				goto done;
			}
			result = dns_message_rendersection(
				question, DNS_SECTION_ADDITIONAL, 0);
			if (result != ISC_R_SUCCESS) {
				goto done;
			}
			result = dns_message_renderend(question);
			if (result != ISC_R_SUCCESS) {
				goto done;
			}
			dns_compress_invalidate(&cctx);

			// free memory
			isc_mem_free(mctx, name_str);
		} else {
			FRAG_LOG(ISC_LOG_DEBUG(8),
				 "could not find a question in "
				 "create_fragment_query_qname");
			goto done;
		}
	} else {
		FRAG_LOG(ISC_LOG_DEBUG(8),
			 "could not parse message in "
			 "create_fragment_query_qname");
		goto done;
	}
	result = ISC_R_SUCCESS;
done:
	if (question != NULL) {
		question->buffer = NULL; /* the caller owns the buffer */
		dns_message_detach(&question);
	}
	dns_message_detach(&msg);
	return result;
}

isc_result_t
render_fragment(isc_mem_t *mctx, unsigned msg_size, dns_message_t **messagep) {
	FRAG_LOG(ISC_LOG_DEBUG(8), "rendering message %u with buffer size %u",
		 (*messagep)->id, msg_size);
	// if already rendered
	if ((*messagep)->buffer != NULL) {
		return ISC_R_EXISTS;
	}

	// dynamic allocation, so we can attach to the message
	isc_buffer_t *buffer = NULL;
	isc_buffer_allocate(mctx, &buffer, msg_size);
	isc_result_t result = ISC_R_SUCCESS;
	dns_message_t *message = *messagep;
	dns_compress_t cctx;

	message->from_to_wire = DNS_MESSAGE_INTENTRENDER;
	for (size_t i = 0; i < DNS_SECTION_MAX; i++) {
		message->counts[i] = 0;
	}

	dns_compress_init(&cctx, mctx, 0);

	REQUIRE(dns_message_renderbegin(message, &cctx, buffer) ==
		ISC_R_SUCCESS);

	// always the same order
	unsigned options = 0;
	const dns_section_t sections[] = { DNS_SECTION_QUESTION,
					   DNS_SECTION_ANSWER,
					   DNS_SECTION_AUTHORITY,
					   DNS_SECTION_ADDITIONAL };
	for (size_t i = 0; i < 4; i++) {
		result = dns_message_rendersection(message, sections[i],
						   options);
		if (result != ISC_R_SUCCESS) {
			FRAG_LOG(ISC_LOG_DEBUG(8),
				 "could not render section %u: %s (buffer "
				 "size %u)",
				 sections[i], isc_result_totext(result),
				 msg_size);
			dns_compress_invalidate(&cctx);
			message->buffer = NULL;
			isc_buffer_free(&buffer);
			return result;
		}
	}
	message->flags &= ~DNS_MESSAGEFLAG_TC; // disable TC to trick renderend
					       // to render complete message
	REQUIRE(dns_message_renderend(message) == ISC_R_SUCCESS);

	dns_compress_invalidate(&cctx);
	FRAG_LOG(ISC_LOG_DEBUG(8), "finished rendering, stored %u bytes",
		 buffer->used);
	message->buffer = buffer;
	dns_message_takebuffer(message, &buffer); // the message now owns the
						  // buffer

	/*
	 * QBF fragments are detected by the resolver through the TC flag,
	 * so set it both in the message and in the rendered header.
	 */
	message->flags |= DNS_MESSAGEFLAG_TC;
	*(unsigned short *)((unsigned char *)message->buffer->base + 1) |=
		DNS_MESSAGEFLAG_TC;
	return (result);
}
