/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

/*! \file */

#include <stdbool.h>
#include <stdio.h>

#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/param_build.h>
#if !defined(OPENSSL_NO_ENGINE)
#include <openssl/engine.h>
#endif

#include <isc/mem.h>
#include <isc/safe.h>
#include <isc/string.h>
#include <isc/util.h>

#include <dns/keyvalues.h>

#include "dst_internal.h"
#include "dst_openssl.h"
#include "dst_parse.h"

#define DST_RET(a)        \
	{                 \
		ret = a;  \
		goto err; \
	}

#define FALCON512_PRIVATEKEYSIZE	 1281
#define P256_FALCON512_PRIVATEKEYSIZE	 1406 // 1281 + 32 + 93 (overhead)
#define RSA3072_FALCON512_PRIVATEKEYSIZE	 3055 // 1281 + 384 + 93 (overhead)
#define FALCON1024_PRIVATEKEYSIZE	 2305
#define P521_FALCON1024_PRIVATEKEYSIZE	 2532 // 2305 + 66 + 93 = 2464
#define MLDSA44_PRIVATEKEYSIZE	 2560
#define P256_MLDSA44_PRIVATEKEYSIZE	 2685 // 2560 + 32 + 93 (overhead)
#define RSA3072_MLDSA44_PRIVATEKEYSIZE	  4334 // 2944 // 2560 + 384
#define SLHDSASHA2128S_PRIVATEKEYSIZE 64	
#define P256_SLHDSASHA2128S_PRIVATEKEYSIZE 189 // 64 + 32 + 93 (overhead)
#define RSA3072_SLHDSASHA2128S_PRIVATEKEYSIZE 1838 // 448 // 64 + 384	
#define MAYO1_PRIVATEKEYSIZE	 24
#define P256_MAYO1_PRIVATEKEYSIZE	 149 // 24 + 32 + 93 (overhead)
#define SNOVA2454_PRIVATEKEYSIZE 48 
#define P256_SNOVA2454_PRIVATEKEYSIZE 173 // 48 + 32 + 93(overhead)

typedef struct oqs_tags {
	unsigned int ntags, private_key_tag, public_key_tag, engine_tag,
		label_tag;
} oqs_tags_t;

typedef struct oqs_alginfo {
	const char *alg_name;
	unsigned int key_size, priv_key_size, sig_size;
	oqs_tags_t tags;
} oqs_alginfo_t;

static const oqs_alginfo_t *
openssloqs_alg_info(unsigned int key_alg) {
	if (key_alg == DST_ALG_FALCON512) {
		static const oqs_alginfo_t oqs_alginfo = {
			.alg_name = "falconpadded512", //"falcon512",
			.key_size = DNS_KEY_FALCON512SIZE,
			.priv_key_size = FALCON512_PRIVATEKEYSIZE,
			.sig_size = DNS_SIG_FALCON512SIZE,
			.tags = {
				.ntags = OQS_NTAGS,
				.private_key_tag = TAG_FALCON512_PRIVATEKEY,
				.public_key_tag = TAG_FALCON512_PUBLICKEY,
				.engine_tag = TAG_FALCON512_ENGINE,
				.label_tag = TAG_FALCON512_LABEL,
			},
		};
		return &oqs_alginfo;
	}
	if (key_alg == DST_ALG_P256_FALCON512) {
		static const oqs_alginfo_t oqs_alginfo = {
			.alg_name = "p256_falconpadded512", //"p256_falcon512",
			.key_size = DNS_KEY_P256_FALCON512SIZE,
			.priv_key_size = P256_FALCON512_PRIVATEKEYSIZE,
			.sig_size = DNS_SIG_P256_FALCON512SIZE,
			.tags = {
				.ntags = OQS_NTAGS,
				.private_key_tag = TAG_P256_FALCON512_PRIVATEKEY,
				.public_key_tag = TAG_P256_FALCON512_PUBLICKEY,
				.engine_tag = TAG_P256_FALCON512_ENGINE,
				.label_tag = TAG_P256_FALCON512_LABEL,
			},
		};
		return &oqs_alginfo;
	}
	if (key_alg == DST_ALG_RSA3072_FALCON512) {
		static const oqs_alginfo_t oqs_alginfo = {
			.alg_name = "rsa3072_falconpadded512", //"rsa3072_falcon512",
			.key_size = DNS_KEY_RSA3072_FALCON512SIZE,
			.priv_key_size = RSA3072_FALCON512_PRIVATEKEYSIZE,
			.sig_size = DNS_SIG_RSA3072_FALCON512SIZE,
			.tags = {
				.ntags = OQS_NTAGS,
				.private_key_tag = TAG_RSA3072_FALCON512_PRIVATEKEY,
				.public_key_tag = TAG_RSA3072_FALCON512_PUBLICKEY,
				.engine_tag = TAG_RSA3072_FALCON512_ENGINE,
				.label_tag = TAG_RSA3072_FALCON512_LABEL,
			},
		};
		return &oqs_alginfo;
	}
	if (key_alg == DST_ALG_FALCON1024) {
		static const oqs_alginfo_t oqs_alginfo = {
			.alg_name = "falconpadded1024", 
			.key_size = DNS_KEY_FALCON1024SIZE,
			.priv_key_size = FALCON1024_PRIVATEKEYSIZE,
			.sig_size = DNS_SIG_FALCON1024SIZE,
			.tags = {
				.ntags = OQS_NTAGS,
				.private_key_tag = TAG_FALCON1024_PRIVATEKEY,
				.public_key_tag = TAG_FALCON1024_PUBLICKEY,
				.engine_tag = TAG_FALCON1024_ENGINE,
				.label_tag = TAG_FALCON1024_LABEL,
			},
		};
		return &oqs_alginfo;
	}
	if (key_alg == DST_ALG_P521_FALCON1024) {
		static const oqs_alginfo_t oqs_alginfo = {
			.alg_name = "p521_falconpadded1024", 
			.key_size = DNS_KEY_P521_FALCON1024SIZE,
			.priv_key_size = P521_FALCON1024_PRIVATEKEYSIZE,
			.sig_size = DNS_SIG_P521_FALCON1024SIZE,
			.tags = {
				.ntags = OQS_NTAGS,
				.private_key_tag = TAG_P521_FALCON1024_PRIVATEKEY,
				.public_key_tag = TAG_P521_FALCON1024_PUBLICKEY,
				.engine_tag = TAG_P521_FALCON1024_ENGINE,
				.label_tag = TAG_P521_FALCON1024_LABEL,
			},
		};
		return &oqs_alginfo;
	}
	if (key_alg == DST_ALG_MLDSA44) {
		static const oqs_alginfo_t oqs_alginfo = {
			.alg_name = "mldsa44", //"dilithium2",
			.key_size = DNS_KEY_MLDSA44SIZE,
			.priv_key_size = MLDSA44_PRIVATEKEYSIZE,
			.sig_size = DNS_SIG_MLDSA44SIZE,
			.tags = {
				.ntags = OQS_NTAGS,
				.private_key_tag = TAG_MLDSA44_PRIVATEKEY,
				.public_key_tag = TAG_MLDSA44_PUBLICKEY,
				.engine_tag = TAG_MLDSA44_ENGINE,
				.label_tag = TAG_MLDSA44_LABEL,
			},
		};
		return &oqs_alginfo;
	}
	if (key_alg == DST_ALG_P256_MLDSA44) {
		static const oqs_alginfo_t oqs_alginfo = {
			.alg_name = "p256_mldsa44", //"p256_dilithium2",
			.key_size = DNS_KEY_P256_MLDSA44SIZE,
			.priv_key_size = P256_MLDSA44_PRIVATEKEYSIZE,
			.sig_size = DNS_SIG_P256_MLDSA44SIZE,
			.tags = {
				.ntags = OQS_NTAGS,
				.private_key_tag = TAG_P256_MLDSA44_PRIVATEKEY,
				.public_key_tag = TAG_P256_MLDSA44_PUBLICKEY,
				.engine_tag = TAG_P256_MLDSA44_ENGINE,
				.label_tag = TAG_P256_MLDSA44_LABEL,
			},
		};
		return &oqs_alginfo;
	}
	if (key_alg == DST_ALG_RSA3072_MLDSA44) {
		static const oqs_alginfo_t oqs_alginfo = {
			.alg_name = "rsa3072_mldsa44", //"rsa3072_dilithium2",
			.key_size = DNS_KEY_RSA3072_MLDSA44SIZE,
			.priv_key_size = RSA3072_MLDSA44_PRIVATEKEYSIZE,
			.sig_size = DNS_SIG_RSA3072_MLDSA44SIZE,
			.tags = {
				.ntags = OQS_NTAGS,
				.private_key_tag = TAG_RSA3072_MLDSA44_PRIVATEKEY,
				.public_key_tag = TAG_RSA3072_MLDSA44_PUBLICKEY,
				.engine_tag = TAG_RSA3072_MLDSA44_ENGINE,
				.label_tag = TAG_RSA3072_MLDSA44_LABEL,
			},
		};
		return &oqs_alginfo;
	}
	if (key_alg == DST_ALG_SLHDSASHA2128S) {
		static const oqs_alginfo_t oqs_alginfo = {
			.alg_name = "SLH-DSA-SHA2-128s", //"sphincssha2128ssimple",
			.key_size = DNS_KEY_SLHDSASHA2128SSIZE,
			.priv_key_size = SLHDSASHA2128S_PRIVATEKEYSIZE,
			.sig_size = DNS_SIG_SLHDSASHA2128SSIZE,
			.tags = {
				.ntags = OQS_NTAGS,
				.private_key_tag = TAG_SLHDSASHA2128S_PRIVATEKEY,
				.public_key_tag = TAG_SLHDSASHA2128S_PUBLICKEY,
				.engine_tag = TAG_SLHDSASHA2128S_ENGINE,
				.label_tag = TAG_SLHDSASHA2128S_LABEL,
			},
		};
		return &oqs_alginfo;
	}
	if (key_alg == DST_ALG_P256_SLHDSASHA2128S) {
		static const oqs_alginfo_t oqs_alginfo = {
			.alg_name = "p256_sphincssha2128ssimple",
			.key_size = DNS_KEY_P256_SLHDSASHA2128SSIZE,
			.priv_key_size = P256_SLHDSASHA2128S_PRIVATEKEYSIZE,
			.sig_size = DNS_SIG_P256_SLHDSASHA2128SSIZE,
			.tags = {
				.ntags = OQS_NTAGS,
				.private_key_tag = TAG_P256_SLHDSASHA2128S_PRIVATEKEY,
				.public_key_tag = TAG_P256_SLHDSASHA2128S_PUBLICKEY,
				.engine_tag = TAG_P256_SLHDSASHA2128S_ENGINE,
				.label_tag = TAG_P256_SLHDSASHA2128S_LABEL,
			},
		};
		return &oqs_alginfo;
	}
	if (key_alg == DST_ALG_RSA3072_SLHDSASHA2128S) {
		static const oqs_alginfo_t oqs_alginfo = {
			.alg_name = "rsa3072_sphincssha2128ssimple",
			.key_size = DNS_KEY_RSA3072_SLHDSASHA2128SSIZE,
			.priv_key_size = RSA3072_SLHDSASHA2128S_PRIVATEKEYSIZE,
			.sig_size = DNS_SIG_RSA3072_SLHDSASHA2128SSIZE,
			.tags = {
				.ntags = OQS_NTAGS,
				.private_key_tag = TAG_RSA3072_SLHDSASHA2128S_PRIVATEKEY,
				.public_key_tag = TAG_RSA3072_SLHDSASHA2128S_PUBLICKEY,
				.engine_tag = TAG_RSA3072_SLHDSASHA2128S_ENGINE,
				.label_tag = TAG_RSA3072_SLHDSASHA2128S_LABEL,
			},
		};
		return &oqs_alginfo;
	}
	if (key_alg == DST_ALG_MAYO1) {
		static const oqs_alginfo_t oqs_alginfo = {
			.alg_name = "mayo1", 
			.key_size = DNS_KEY_MAYO1SIZE,
			.priv_key_size = MAYO1_PRIVATEKEYSIZE,
			.sig_size = DNS_SIG_MAYO1SIZE,
			.tags = {
				.ntags = OQS_NTAGS,
				.private_key_tag = TAG_MAYO1_PRIVATEKEY,
				.public_key_tag = TAG_MAYO1_PUBLICKEY,
				.engine_tag = TAG_MAYO1_ENGINE,
				.label_tag = TAG_MAYO1_LABEL,
			},
		};
		return &oqs_alginfo;
	}
	if (key_alg == DST_ALG_P256_MAYO1) {
		static const oqs_alginfo_t oqs_alginfo = {
			.alg_name = "p256_mayo1", 
			.key_size = DNS_KEY_P256_MAYO1SIZE,
			.priv_key_size = P256_MAYO1_PRIVATEKEYSIZE,
			.sig_size = DNS_SIG_P256_MAYO1SIZE,
			.tags = {
				.ntags = OQS_NTAGS,
				.private_key_tag = TAG_P256_MAYO1_PRIVATEKEY,
				.public_key_tag = TAG_P256_MAYO1_PUBLICKEY,
				.engine_tag = TAG_P256_MAYO1_ENGINE,
				.label_tag = TAG_P256_MAYO1_LABEL,
			},
		};
		return &oqs_alginfo;
	}
	if (key_alg == DST_ALG_SNOVA2454) {
		static const oqs_alginfo_t oqs_alginfo = {
			.alg_name = "snova2454", 
			.key_size = DNS_KEY_SNOVA2454SIZE,
			.priv_key_size = SNOVA2454_PRIVATEKEYSIZE,
			.sig_size = DNS_SIG_SNOVA2454SIZE,
			.tags = {
				.ntags = OQS_NTAGS,
				.private_key_tag = TAG_SNOVA2454_PRIVATEKEY,
				.public_key_tag = TAG_SNOVA2454_PUBLICKEY,
				.engine_tag = TAG_SNOVA2454_ENGINE,
				.label_tag = TAG_SNOVA2454_LABEL,
			},
		};
		return &oqs_alginfo;
	}
	if (key_alg == DST_ALG_P256_SNOVA2454) {
		static const oqs_alginfo_t oqs_alginfo = {
			.alg_name = "p256_snova2454", 
			.key_size = DNS_KEY_P256_SNOVA2454SIZE,
			.priv_key_size = P256_SNOVA2454_PRIVATEKEYSIZE,
			.sig_size = DNS_SIG_P256_SNOVA2454SIZE,
			.tags = {
				.ntags = OQS_NTAGS,
				.private_key_tag = TAG_P256_SNOVA2454_PRIVATEKEY,
				.public_key_tag = TAG_P256_SNOVA2454_PUBLICKEY,
				.engine_tag = TAG_P256_SNOVA2454_ENGINE,
				.label_tag = TAG_P256_SNOVA2454_LABEL,
			},
		};
		return &oqs_alginfo;
	}
	return NULL;
}

static isc_result_t
raw_pub_key_to_ossl(const oqs_alginfo_t *alginfo, const unsigned char *pub_key,
		    size_t *pub_key_len, EVP_PKEY **pkey) {
	isc_result_t ret = DST_R_INVALIDPUBLICKEY;
	const char *alg_name = alginfo->alg_name;

	if (pub_key != NULL) {
		if (pub_key_len == NULL) {
			return (ret);
		}
		*pkey = EVP_PKEY_new_raw_public_key_ex(
			NULL, 
			alg_name, NULL, pub_key, *pub_key_len);
		if (*pkey == NULL) {
			ERR_print_errors_fp(stderr);
			return (dst__openssl_toresult(ret));
		}
	}
	return (ISC_R_SUCCESS);
}

static isc_result_t
raw_priv_key_to_ossl(const oqs_alginfo_t *alginfo,
		     const unsigned char *priv_key, size_t *priv_key_len,
		     const unsigned char *pub_key, size_t *pub_key_len,
		     EVP_PKEY **pkey) {
	EVP_PKEY *pk = NULL;
	EVP_PKEY_CTX *ctx = NULL;
	OSSL_PARAM_BLD *param_bld = NULL;
	OSSL_PARAM *params = NULL;
	isc_result_t ret = DST_R_INVALIDPUBLICKEY;

	if (pkey == NULL) {
		return (ISC_R_NOMEMORY);
	}
	if ((param_bld = OSSL_PARAM_BLD_new()) == NULL ||
	    !OSSL_PARAM_BLD_push_octet_string(param_bld, "priv", priv_key,
					      *priv_key_len) ||
	    !OSSL_PARAM_BLD_push_octet_string(param_bld, "pub", pub_key,
					      *pub_key_len))
	{
		return (ISC_R_NOMEMORY);
	}
	params = OSSL_PARAM_BLD_to_param(param_bld);
	if (params == NULL) {
		goto param_err;
	}
	ctx = EVP_PKEY_CTX_new_from_name(NULL, alginfo->alg_name, NULL);
	if (ctx == NULL) {
		goto ctxt_err;
	}
	if (EVP_PKEY_fromdata_init(ctx) <= 0 ||
	    EVP_PKEY_fromdata(ctx, &pk, EVP_PKEY_KEYPAIR, params) <= 0) 
	{
		goto fromdata_err;
	}
	if (pk == NULL) {
		goto fromdata_err;
	}
	*pkey = pk;
	ret = ISC_R_SUCCESS;

fromdata_err:
	EVP_PKEY_CTX_free(ctx);

ctxt_err:
	OSSL_PARAM_free(params);

param_err:
	OSSL_PARAM_BLD_free(param_bld);

	return ret;
}
static isc_result_t
openssloqs_createctx(dst_key_t *key, dst_context_t *dctx) {
	isc_buffer_t *buf = NULL;
	const oqs_alginfo_t *alginfo = openssloqs_alg_info(dctx->key->key_alg);

	UNUSED(key);

	REQUIRE(alginfo != NULL);

	isc_buffer_allocate(dctx->mctx, &buf, 64);
	dctx->ctxdata.generic = buf;

	return (ISC_R_SUCCESS);
}

static void
openssloqs_destroyctx(dst_context_t *dctx) {
	isc_buffer_t *buf = (isc_buffer_t *)dctx->ctxdata.generic;
	const oqs_alginfo_t *alginfo = openssloqs_alg_info(dctx->key->key_alg);

	REQUIRE(alginfo != NULL);

	if (buf != NULL) {
		isc_buffer_free(&buf);
	}
	dctx->ctxdata.generic = NULL;
}

static isc_result_t
openssloqs_adddata(dst_context_t *dctx, const isc_region_t *data) {
	isc_buffer_t *buf = (isc_buffer_t *)dctx->ctxdata.generic;
	isc_buffer_t *nbuf = NULL;
	isc_region_t r;
	unsigned int length;
	isc_result_t result;
	const oqs_alginfo_t *alginfo = openssloqs_alg_info(dctx->key->key_alg);

	REQUIRE(alginfo != NULL);

	result = isc_buffer_copyregion(buf, data);
	if (result == ISC_R_SUCCESS) {
		return (ISC_R_SUCCESS);
	}

	length = isc_buffer_length(buf) + data->length + 64;
	isc_buffer_allocate(dctx->mctx, &nbuf, length);
	isc_buffer_usedregion(buf, &r);
	(void)isc_buffer_copyregion(nbuf, &r);
	(void)isc_buffer_copyregion(nbuf, data);
	isc_buffer_free(&buf);
	dctx->ctxdata.generic = nbuf;

	return (ISC_R_SUCCESS);
}

static isc_result_t
openssloqs_sign(dst_context_t *dctx, isc_buffer_t *sig) {
	isc_result_t ret;
	dst_key_t *key = dctx->key;
	isc_region_t tbsreg;
	isc_region_t sigreg;
	EVP_PKEY *pkey = key->keydata.pkeypair.priv;
	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	isc_buffer_t *buf = (isc_buffer_t *)dctx->ctxdata.generic;
	size_t siglen;
	const oqs_alginfo_t *alginfo = openssloqs_alg_info(key->key_alg);

	REQUIRE(alginfo != NULL);

	if (ctx == NULL) {
		return (ISC_R_NOMEMORY);
	}

	siglen = alginfo->sig_size;
	isc_buffer_availableregion(sig, &sigreg);
	if (sigreg.length < (unsigned int)siglen) {
		DST_RET(ISC_R_NOSPACE);
	}

	isc_buffer_usedregion(buf, &tbsreg);

	if (EVP_DigestSignInit(ctx, NULL, NULL, NULL, pkey) != 1) {
		DST_RET(dst__openssl_toresult3(
			dctx->category, "EVP_DigestSignInit", ISC_R_FAILURE));
	}

	if (EVP_DigestSign(ctx, sigreg.base, &siglen, tbsreg.base, tbsreg.length) != 1)
	{
		unsigned long err = ERR_get_error(); // Retrieve the most recent error
		char err_buf[256];
		ERR_error_string(err, err_buf); // Convert error code to a human-readable string
		fprintf(stderr, "EVP_DigestSign(ctx, sigreg.base, &siglen, tbsreg.base, tbsreg.length) != 1 failed!\nSignature needs at least: %ld bytes, tbsreg.length: %d\nError msg: %s\n", siglen, tbsreg.length, err_buf);
		DST_RET(dst__openssl_toresult3(dctx->category, "EVP_DigestSign",
					       DST_R_SIGNFAILURE));
	}
	INSIST(siglen <= alginfo->sig_size);
	isc_buffer_add(sig, (unsigned int)siglen);
	ret = ISC_R_SUCCESS;

err:
	EVP_MD_CTX_free(ctx);
	isc_buffer_free(&buf);
	dctx->ctxdata.generic = NULL;

	return (ret);
}

static isc_result_t
openssloqs_verify(dst_context_t *dctx, const isc_region_t *sig) {
	isc_result_t ret;
	dst_key_t *key = dctx->key;
	int status;
	isc_region_t tbsreg;
	EVP_PKEY *pkey = key->keydata.pkeypair.pub;
	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	isc_buffer_t *buf = (isc_buffer_t *)dctx->ctxdata.generic;
	const oqs_alginfo_t *alginfo = openssloqs_alg_info(key->key_alg);

	REQUIRE(alginfo != NULL);

	if (ctx == NULL) {
		return (ISC_R_NOMEMORY);
	}

	if (sig->length > alginfo->sig_size) {
		return (DST_R_VERIFYFAILURE);
	}
	isc_buffer_usedregion(buf, &tbsreg);

	if (EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, pkey) != 1) {
		DST_RET(dst__openssl_toresult3(
			dctx->category, "EVP_DigestVerifyInit", ISC_R_FAILURE));
	}

	status = EVP_DigestVerify(ctx, sig->base, sig->length, tbsreg.base,
				  tbsreg.length);

	switch (status) {
	case 1:
		ret = ISC_R_SUCCESS;
		break;
	case 0:
		ret = dst__openssl_toresult(DST_R_VERIFYFAILURE);
		break;
	default:
		ret = dst__openssl_toresult3(dctx->category, "EVP_DigestVerify",
					     DST_R_VERIFYFAILURE);
		break;
	}

err:
	EVP_MD_CTX_free(ctx);
	isc_buffer_free(&buf);
	dctx->ctxdata.generic = NULL;

	return (ret);
}

static isc_result_t
openssloqs_generate(dst_key_t *key, int unused, void (*callback)(int)) {
	isc_result_t ret;
	EVP_PKEY *pkey = NULL;
	EVP_PKEY_CTX *ctx = NULL;
	int status;
	const oqs_alginfo_t *alginfo = openssloqs_alg_info(key->key_alg);

	UNUSED(unused);
	UNUSED(callback);

	REQUIRE(alginfo != NULL);

	ctx = EVP_PKEY_CTX_new_from_name(NULL, alginfo->alg_name, NULL);
	fprintf(stderr, "alg_name: %s\n", alginfo->alg_name);
	if (ctx == NULL) {
		return (dst__openssl_toresult2("EVP_PKEY_CTX_new_id",
					       DST_R_OPENSSLFAILURE));
	}

	status = EVP_PKEY_keygen_init(ctx);
	if (status != 1) {
		DST_RET(dst__openssl_toresult2("EVP_PKEY_keygen_init",
					       DST_R_OPENSSLFAILURE));
	}

	status = EVP_PKEY_keygen(ctx, &pkey);
	if (status != 1) {
		DST_RET(dst__openssl_toresult2("EVP_PKEY_keygen",
					       DST_R_OPENSSLFAILURE));
	}

	key->key_size = alginfo->key_size * 8;
	key->keydata.pkeypair.priv = pkey;
	key->keydata.pkeypair.pub = pkey;
	ret = ISC_R_SUCCESS;

err:
	EVP_PKEY_CTX_free(ctx);
	return (ret);
}

static isc_result_t
openssloqs_todns(const dst_key_t *key, isc_buffer_t *data) {
	EVP_PKEY *pkey = key->keydata.pkeypair.pub;
	isc_region_t r;
	size_t len;
	const oqs_alginfo_t *alginfo = openssloqs_alg_info(key->key_alg);

	REQUIRE(pkey != NULL);
	REQUIRE(alginfo != NULL);

	len = alginfo->key_size;
	isc_buffer_availableregion(data, &r);
	if (r.length < len) {
		fprintf(stderr, "r.length < len failed!\n");
		return (ISC_R_NOSPACE);
	}
	if (EVP_PKEY_get_raw_public_key(pkey, r.base, &len) != 1) {
		unsigned long err = ERR_get_error(); // Retrieve the most recent error
		char err_buf[256];
		ERR_error_string(err, err_buf); // Convert error code to a human-readable string
		fprintf(stderr, "EVP_PKEY_get_raw_public_key(pkey, r.base, &len) != 1 failed!\nPublic key needs at least: %ld bytes, r.length: %d\nError msg: %s\n", len, r.length, err_buf);

		return (dst__openssl_toresult(ISC_R_FAILURE));
	}

	isc_buffer_add(data, len);
	return (ISC_R_SUCCESS);
}

static isc_result_t
openssloqs_fromdns(dst_key_t *key, isc_buffer_t *data) {
	isc_result_t ret;
	isc_region_t r;
	size_t len;
	EVP_PKEY *pkey = NULL;
	const oqs_alginfo_t *alginfo = openssloqs_alg_info(key->key_alg);

	REQUIRE(alginfo != NULL);

	isc_buffer_remainingregion(data, &r);
	if (r.length == 0) {
		return (ISC_R_SUCCESS);
	}

	len = r.length;
	ret = raw_pub_key_to_ossl(alginfo, r.base, &len, &pkey);
	if (ret != ISC_R_SUCCESS) {
		return ret;
	}

	isc_buffer_forward(data, len);
	key->keydata.pkeypair.pub = pkey;
	key->key_size = len * 8;
	return (ISC_R_SUCCESS);
}

static isc_result_t
openssloqs_tofile(const dst_key_t *key, const char *directory) {
	isc_result_t ret;
	dst_private_t priv;
	unsigned char *pubbuf = NULL;
	unsigned char *privbuf = NULL;
	size_t publen;
	size_t privlen;
	int i;
	const oqs_alginfo_t *alginfo = openssloqs_alg_info(key->key_alg);

	REQUIRE(alginfo != NULL);

	publen = alginfo->key_size;
	privlen = alginfo->priv_key_size;
	if (key->keydata.pkeypair.pub == NULL ||
	    key->keydata.pkeypair.priv == NULL)
	{
		return (DST_R_NULLKEY);
	}

	if (key->external) {
		priv.nelements = 0;
		return (dst__privstruct_writefile(key, &priv, directory));
	}

	i = 0;

	if (dst__openssl_keypair_isprivate(key)) {
		privbuf = isc_mem_get(key->mctx, privlen);
		if (EVP_PKEY_get_raw_private_key(key->keydata.pkeypair.priv, privbuf, &privlen) != 1) {
			unsigned long err = ERR_get_error(); // Retrieve the most recent error
			char err_buf[256];
			ERR_error_string(err, err_buf); // Convert error code to a human-readable string
			fprintf(stderr, "EVP_PKEY_get_raw_private_key(key->keydata.pkeypair.priv, privbuf, &privlen) != 1 failed!\nPrivate key needs at least: %ld bytes\nError msg: %s\n", privlen, err_buf);
			DST_RET(dst__openssl_toresult(ISC_R_FAILURE));
		}
		priv.elements[i].tag = alginfo->tags.private_key_tag;
		priv.elements[i].length = privlen;
		priv.elements[i].data = privbuf;
		i++;
		pubbuf = isc_mem_get(key->mctx, publen);
		if (EVP_PKEY_get_raw_public_key(key->keydata.pkeypair.priv,
						pubbuf, &publen) != 1)
			DST_RET(dst__openssl_toresult(ISC_R_FAILURE));
		priv.elements[i].tag = alginfo->tags.public_key_tag;
		priv.elements[i].length = publen;
		priv.elements[i].data = pubbuf;
		i++;
	}
	priv.nelements = i;
	ret = dst__privstruct_writefile(key, &priv, directory);

err:
	if (privbuf != NULL) {
		isc_mem_put(key->mctx, privbuf, privlen);
	}
	if (pubbuf != NULL) {
		isc_mem_put(key->mctx, pubbuf, publen);
	}
	return (ret);
}

static isc_result_t
openssloqs_parse(dst_key_t *key, isc_lex_t *lexer, dst_key_t *pub) {
	dst_private_t priv;
	isc_result_t ret;
	int i, privkey_index, pubkey_index = -1;
	const char *engine = NULL, *label = NULL;
	EVP_PKEY *pkey = NULL, *pubpkey = NULL;
	size_t pub_len, priv_len;
	isc_mem_t *mctx = key->mctx;
	const oqs_alginfo_t *alginfo = openssloqs_alg_info(key->key_alg);

	UNUSED(engine);
	UNUSED(label);
	UNUSED(pubpkey);

	REQUIRE(alginfo != NULL);

	/* read private key file */
	ret = dst__privstruct_parse(key, key->key_alg, lexer, mctx, &priv);
	if (ret != ISC_R_SUCCESS) {
		goto err;
	}

	if (key->external) {
		if (priv.nelements != 0) {
			DST_RET(DST_R_INVALIDPRIVATEKEY);
		}
		if (pub == NULL) {
			DST_RET(DST_R_INVALIDPRIVATEKEY);
		}
		key->keydata.pkeypair.priv = pub->keydata.pkeypair.priv;
		key->keydata.pkeypair.pub = pub->keydata.pkeypair.pub;
		pub->keydata.pkeypair.priv = NULL;
		pub->keydata.pkeypair.pub = NULL;
		DST_RET(ISC_R_SUCCESS);
	}

	for (i = 0; i < priv.nelements; i++) {
		switch (priv.elements[i].tag) {
		case TAG_FALCON512_ENGINE:
		case TAG_P256_FALCON512_ENGINE:
		case TAG_RSA3072_FALCON512_ENGINE:
		case TAG_FALCON1024_ENGINE:
		case TAG_P521_FALCON1024_ENGINE:
		case TAG_MLDSA44_ENGINE:
		case TAG_P256_MLDSA44_ENGINE:
		case TAG_RSA3072_MLDSA44_ENGINE:
		case TAG_SLHDSASHA2128S_ENGINE:
		case TAG_P256_SLHDSASHA2128S_ENGINE:
		case TAG_RSA3072_SLHDSASHA2128S_ENGINE:
		case TAG_MAYO1_ENGINE:
		case TAG_P256_MAYO1_ENGINE:
		case TAG_SNOVA2454_ENGINE:
		case TAG_P256_SNOVA2454_ENGINE:
			engine = (char *)priv.elements[i].data;
			break;
		case TAG_FALCON512_LABEL:
		case TAG_P256_FALCON512_LABEL:
		case TAG_RSA3072_FALCON512_LABEL:
		case TAG_FALCON1024_LABEL:
		case TAG_P521_FALCON1024_LABEL:
		case TAG_MLDSA44_LABEL:
		case TAG_P256_MLDSA44_LABEL:
		case TAG_RSA3072_MLDSA44_LABEL:
		case TAG_SLHDSASHA2128S_LABEL:
		case TAG_P256_SLHDSASHA2128S_LABEL:
		case TAG_RSA3072_SLHDSASHA2128S_LABEL:
		case TAG_MAYO1_LABEL:
		case TAG_P256_MAYO1_LABEL:
		case TAG_SNOVA2454_LABEL:
		case TAG_P256_SNOVA2454_LABEL:
			label = (char *)priv.elements[i].data;
			break;
		case TAG_FALCON512_PRIVATEKEY:
		case TAG_P256_FALCON512_PRIVATEKEY:
		case TAG_RSA3072_FALCON512_PRIVATEKEY:
		case TAG_FALCON1024_PRIVATEKEY:
		case TAG_P521_FALCON1024_PRIVATEKEY:
		case TAG_MLDSA44_PRIVATEKEY:
		case TAG_P256_MLDSA44_PRIVATEKEY:
		case TAG_RSA3072_MLDSA44_PRIVATEKEY:
		case TAG_SLHDSASHA2128S_PRIVATEKEY:
		case TAG_P256_SLHDSASHA2128S_PRIVATEKEY:
		case TAG_RSA3072_SLHDSASHA2128S_PRIVATEKEY:
		case TAG_MAYO1_PRIVATEKEY:
		case TAG_P256_MAYO1_PRIVATEKEY:
		case TAG_SNOVA2454_PRIVATEKEY:
		case TAG_P256_SNOVA2454_PRIVATEKEY:
			privkey_index = i;
			break;
		case TAG_FALCON512_PUBLICKEY:
		case TAG_P256_FALCON512_PUBLICKEY:
		case TAG_RSA3072_FALCON512_PUBLICKEY:
		case TAG_FALCON1024_PUBLICKEY:
		case TAG_P521_FALCON1024_PUBLICKEY:
		case TAG_MLDSA44_PUBLICKEY:
		case TAG_P256_MLDSA44_PUBLICKEY:
		case TAG_RSA3072_MLDSA44_PUBLICKEY:
		case TAG_SLHDSASHA2128S_PUBLICKEY:
		case TAG_P256_SLHDSASHA2128S_PUBLICKEY:
		case TAG_RSA3072_SLHDSASHA2128S_PUBLICKEY:
		case TAG_MAYO1_PUBLICKEY:
		case TAG_P256_MAYO1_PUBLICKEY:
		case TAG_SNOVA2454_PUBLICKEY:
		case TAG_P256_SNOVA2454_PUBLICKEY:
			pubkey_index = i;
			break;
		default:
			break;
		}
	}
	if (privkey_index < 0) {
		DST_RET(DST_R_INVALIDPRIVATEKEY);
	}
	if (pubkey_index < 0) {
		DST_RET(DST_R_INVALIDPUBLICKEY);
	}
	priv_len = priv.elements[privkey_index].length;
	pub_len = priv.elements[pubkey_index].length;
	ret = raw_priv_key_to_ossl(alginfo, priv.elements[privkey_index].data,
				   &priv_len, priv.elements[pubkey_index].data,
				   &pub_len, &pkey);
	if (ret != ISC_R_SUCCESS) {
		DST_RET(ret);
	}
	//fprintf(stdout, "priv_len: %lu, alginfo->priv_key_size: %d\n", priv_len, alginfo->priv_key_size);
	//fprintf(stdout, "pub_len: %lu, alginfo->key_size: %d\n", pub_len, alginfo->key_size);
	INSIST(priv_len == alginfo->priv_key_size);
	INSIST(pub_len == alginfo->key_size);
	if (pkey == NULL) {
		DST_RET(DST_R_INVALIDPRIVATEKEY);
	}
	key->keydata.pkeypair.priv = pkey;
	key->keydata.pkeypair.pub = pkey;
	key->key_size = priv.elements[pubkey_index].length * 8;

err:
	dst__privstruct_free(&priv, mctx);
	isc_safe_memwipe(&priv, sizeof(priv));
	return (ret);
}

static dst_func_t openssloqs_functions = {
	openssloqs_createctx,
	NULL, /*%< createctx2 */
	openssloqs_destroyctx,
	openssloqs_adddata,
	openssloqs_sign,
	openssloqs_verify,
	NULL, /*%< verify2 */
	NULL, /*%< computesecret */
	dst__openssl_keypair_compare,
	NULL, /*%< paramcompare */
	openssloqs_generate,
	dst__openssl_keypair_isprivate,
	dst__openssl_keypair_destroy,
	openssloqs_todns,   // called by dst_key_todns converts a dst_key to a
			    // buffer
	openssloqs_fromdns, // called by from buffer and constructs a key from
			    // dns
	openssloqs_tofile,
	openssloqs_parse,
	NULL, /*%< cleanup */
	NULL, /*%< fromlabel */
	NULL, /*%< dump */
	NULL, /*%< restore */
};

isc_result_t
dst__openssloqs_init(dst_func_t **funcp) {
	REQUIRE(funcp != NULL);
	if (*funcp == NULL) {
		*funcp = &openssloqs_functions;
	}
	return (ISC_R_SUCCESS);
}
