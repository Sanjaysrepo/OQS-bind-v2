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

#pragma once

/*! \file dns/keyvalues.h */

/*
 * Flags field of the KEY RR rdata
 */

#define DNS_KEYFLAG_TYPEMASK 0xC000 /*%< Mask for "type" bits */
#define DNS_KEYTYPE_AUTHCONF 0x0000 /*%< Key usable for both */
#define DNS_KEYTYPE_CONFONLY 0x8000 /*%< Key usable for confidentiality */
#define DNS_KEYTYPE_AUTHONLY 0x4000 /*%< Key usable for authentication */
#define DNS_KEYTYPE_NOKEY    0xC000 /*%< No key usable for either; no key */
#define DNS_KEYTYPE_NOAUTH   DNS_KEYTYPE_CONFONLY
#define DNS_KEYTYPE_NOCONF   DNS_KEYTYPE_AUTHONLY

#define DNS_KEYFLAG_RESERVED2  0x2000 /*%< reserved - must be zero */
#define DNS_KEYFLAG_EXTENDED   0x1000 /*%< key has extended flags */
#define DNS_KEYFLAG_RESERVED4  0x0800 /*%< reserved - must be zero */
#define DNS_KEYFLAG_RESERVED5  0x0400 /*%< reserved - must be zero */
#define DNS_KEYFLAG_OWNERMASK  0x0300 /*%< these bits determine the type */
#define DNS_KEYOWNER_USER      0x0000 /*%< key is assoc. with user */
#define DNS_KEYOWNER_ENTITY    0x0200 /*%< key is assoc. with entity eg host */
#define DNS_KEYOWNER_ZONE      0x0100 /*%< key is zone key */
#define DNS_KEYOWNER_RESERVED  0x0300 /*%< reserved meaning */
#define DNS_KEYFLAG_REVOKE     0x0080 /*%< key revoked (per rfc5011) */
#define DNS_KEYFLAG_RESERVED9  0x0040 /*%< reserved - must be zero */
#define DNS_KEYFLAG_RESERVED10 0x0020 /*%< reserved - must be zero */
#define DNS_KEYFLAG_RESERVED11 0x0010 /*%< reserved - must be zero */
#define DNS_KEYFLAG_SIGNATORYMASK                  \
	0x000F /*%< key can sign RR's of same name \
		*/

#define DNS_KEYFLAG_RESERVEDMASK                         \
	(DNS_KEYFLAG_RESERVED2 | DNS_KEYFLAG_RESERVED4 | \
	 DNS_KEYFLAG_RESERVED5 | DNS_KEYFLAG_RESERVED9 | \
	 DNS_KEYFLAG_RESERVED10 | DNS_KEYFLAG_RESERVED11)
#define DNS_KEYFLAG_KSK 0x0001 /*%< key signing key */

#define DNS_KEYFLAG_RESERVEDMASK2 0xFFFF /*%< no bits defined here */

/* The Algorithm field of the KEY and SIG RR's is an integer, {1..254} */
#define DNS_KEYALG_RSAMD5	     1 /*%< RSA with MD5 */
#define DNS_KEYALG_RSA		     1 /*%< Used just for tagging */
#define DNS_KEYALG_DH_DEPRECATED     2 /*%< deprecated */
#define DNS_KEYALG_DSA		     3 /*%< DSA KEY */
#define DNS_KEYALG_NSEC3DSA	     6
#define DNS_KEYALG_DSS		     DNS_ALG_DSA
#define DNS_KEYALG_ECC		     4
#define DNS_KEYALG_RSASHA1	     5
#define DNS_KEYALG_NSEC3RSASHA1	     7
#define DNS_KEYALG_RSASHA256	     8
#define DNS_KEYALG_RSASHA512	     10
#define DNS_KEYALG_ECCGOST	     12
#define DNS_KEYALG_ECDSA256	     13
#define DNS_KEYALG_ECDSA384	     14
#define DNS_KEYALG_ED25519	     15
#define DNS_KEYALG_ED448	     16
#define DNS_KEYALG_FALCON512	     17
#define DNS_KEYALG_P256_FALCON512	     18
#define DNS_KEYALG_RSA3072_FALCON512	     19
#define DNS_KEYALG_FALCON1024	     20
#define DNS_KEYALG_P521_FALCON1024	     21
#define DNS_KEYALG_MLDSA44	     22
#define DNS_KEYALG_P256_MLDSA44 23
#define DNS_KEYALG_RSA3072_MLDSA44 24
#define DNS_KEYALG_SLHDSASHA2128S 25
#define DNS_KEYALG_P256_SLHDSASHA2128S 26
#define DNS_KEYALG_RSA3072_SLHDSASHA2128S 27
#define DNS_KEYALG_MAYO1	     28
#define DNS_KEYALG_P256_MAYO1	     29
#define DNS_KEYALG_SNOVA2454	     30
#define DNS_KEYALG_P256_SNOVA2454	     31
#define DNS_KEYALG_INDIRECT	     252
#define DNS_KEYALG_PRIVATEDNS	     253
#define DNS_KEYALG_PRIVATEOID	     254 /*%< Key begins with OID giving alg */
#define DNS_KEYALG_MAX		     255

/* Protocol values  */
#define DNS_KEYPROTO_RESERVED 0
#define DNS_KEYPROTO_TLS      1
#define DNS_KEYPROTO_EMAIL    2
#define DNS_KEYPROTO_DNSSEC   3
#define DNS_KEYPROTO_IPSEC    4
#define DNS_KEYPROTO_ANY      255

/* Signatures */
#define DNS_SIG_RSAMINBITS 512 /*%< Size of a mod or exp in bits */
#define DNS_SIG_RSAMAXBITS 2552
/* Total of binary mod and exp */
#define DNS_SIG_RSAMAXBYTES ((DNS_SIG_RSAMAXBITS + 7 / 8) * 2 + 3)
/*%< Max length of text sig block */
#define DNS_SIG_RSAMAXBASE64 (((DNS_SIG_RSAMAXBYTES + 2) / 3) * 4)
#define DNS_SIG_RSAMINSIZE   ((DNS_SIG_RSAMINBITS + 7) / 8)
#define DNS_SIG_RSAMAXSIZE   ((DNS_SIG_RSAMAXBITS + 7) / 8)

#define DNS_SIG_KEY_RSA3072MAXSIZE 384 // in bytes

#define DNS_SIG_ECDSA256SIZE 64
#define DNS_SIG_ECDSA384SIZE 96

#define DNS_KEY_ECDSA256SIZE 64
#define DNS_KEY_ECDSA384SIZE 96

#define DNS_SIG_ED25519SIZE 64
#define DNS_SIG_ED448SIZE   114

#define DNS_KEY_ED25519SIZE 32
#define DNS_KEY_ED448SIZE   57

#define DNS_SIG_FALCON512SIZE 666 // 666+86=752
#define DNS_KEY_FALCON512SIZE 897

#define DNS_SIG_P256_FALCON512SIZE 742 // 742 // 816 // 730 // why the extra 12 bytes?
#define DNS_KEY_P256_FALCON512SIZE 966 // 966// why not 961

#define DNS_SIG_RSA3072_FALCON512SIZE 666 + DNS_SIG_KEY_RSA3072MAXSIZE + 12 // 12: overhead
#define DNS_KEY_RSA3072_FALCON512SIZE 1299 // 897 + DNS_SIG_KEY_RSA3072MAXSIZE + 5  // 5: overhead

#define DNS_SIG_FALCON1024SIZE 1280  
#define DNS_KEY_FALCON1024SIZE 1793

#define DNS_SIG_P521_FALCON1024SIZE 1430 // 1424 // 1280 + (66 + 66) + 12 = 
#define DNS_KEY_P521_FALCON1024SIZE 1930 // 1793 + (66 + 66) + 5 = 

#define DNS_SIG_MLDSA44SIZE 2420
#define DNS_KEY_MLDSA44SIZE 1312

#define DNS_SIG_P256_MLDSA44SIZE 2496 // 2420 + 64 + 12
#define DNS_KEY_P256_MLDSA44SIZE 1381 // 1312 + 64 + 5

#define DNS_SIG_RSA3072_MLDSA44SIZE 2420 + DNS_SIG_KEY_RSA3072MAXSIZE + 12
#define DNS_KEY_RSA3072_MLDSA44SIZE 1714 // 1312 + DNS_SIG_KEY_RSA3072MAXSIZE + 5

#define DNS_SIG_SLHDSASHA2128SSIZE 7856 
#define DNS_KEY_SLHDSASHA2128SSIZE 32

#define DNS_SIG_P256_SLHDSASHA2128SSIZE 7932 // 7856 + 76
#define DNS_KEY_P256_SLHDSASHA2128SSIZE 101 // 32 + 69

#define DNS_SIG_RSA3072_SLHDSASHA2128SSIZE 7856 + DNS_SIG_KEY_RSA3072MAXSIZE + 12
#define DNS_KEY_RSA3072_SLHDSASHA2128SSIZE 434 //32 + DNS_SIG_KEY_RSA3072MAXSIZE + 5

#define DNS_SIG_MAYO1SIZE 454
#define DNS_KEY_MAYO1SIZE 1420

#define DNS_SIG_P256_MAYO1SIZE 530 // 454 + 76
#define DNS_KEY_P256_MAYO1SIZE 1489 // 1420 + 69

#define DNS_SIG_SNOVA2454SIZE 248
#define DNS_KEY_SNOVA2454SIZE 1016

#define DNS_SIG_P256_SNOVA2454SIZE 324 // 248 + 76 
#define DNS_KEY_P256_SNOVA2454SIZE 1085 // 1016 + 69


// returns the signature size for the given algorithm
// inefficient: should be in a loop
// requires some changes so leave like this for now
static inline unsigned get_alg_sig_size(unsigned algorithm) {
	//printf("Algorithm (SIG): %u\n", algorithm);
	if (algorithm == DNS_KEYALG_FALCON512) {
		return DNS_SIG_FALCON512SIZE;
	} 
	else if (algorithm == DNS_KEYALG_P256_FALCON512) {
		return DNS_SIG_P256_FALCON512SIZE;
	} 
	else if (algorithm == DNS_KEYALG_RSA3072_FALCON512) {
		return DNS_SIG_RSA3072_FALCON512SIZE;
	} 
	else if (algorithm == DNS_KEYALG_FALCON1024) {
		return DNS_SIG_FALCON1024SIZE;
	} 
	else if (algorithm == DNS_KEYALG_P521_FALCON1024) {
		return DNS_SIG_P521_FALCON1024SIZE;
	} 
	else if (algorithm == DNS_KEYALG_MLDSA44) {
		return DNS_SIG_MLDSA44SIZE;
	} 
	else if (algorithm == DNS_KEYALG_P256_MLDSA44) {
		return DNS_SIG_P256_MLDSA44SIZE;
	} 
	else if (algorithm == DNS_KEYALG_RSA3072_MLDSA44) {
		return DNS_SIG_RSA3072_MLDSA44SIZE;
	} 
	else if (algorithm == DNS_KEYALG_SLHDSASHA2128S) {
		return DNS_SIG_SLHDSASHA2128SSIZE;
	} 
	else if (algorithm == DNS_KEYALG_P256_SLHDSASHA2128S) {
		return DNS_SIG_P256_SLHDSASHA2128SSIZE;
	} 
	else if (algorithm == DNS_KEYALG_RSA3072_SLHDSASHA2128S) {
		return DNS_SIG_RSA3072_SLHDSASHA2128SSIZE;
	} 
	else if (algorithm == DNS_KEYALG_MAYO1) {
		return DNS_SIG_MAYO1SIZE;
	}  
	else if (algorithm == DNS_KEYALG_P256_MAYO1) {
		return DNS_SIG_P256_MAYO1SIZE;
	} 
	else if (algorithm == DNS_KEYALG_SNOVA2454) {
		return DNS_SIG_SNOVA2454SIZE;
	} 
	else if (algorithm == DNS_KEYALG_P256_SNOVA2454) {
		return DNS_SIG_P256_SNOVA2454SIZE;
	} 
    return 0;
}

// returns the public key size for the given algorithm
// inefficient: should be in a loop
// requires some changes so leave like this for now
static inline unsigned get_alg_pk_size(unsigned algorithm) {
	//printf("Algorithm (PK): %u\n", algorithm);
	if (algorithm == DNS_KEYALG_FALCON512) {
		return DNS_KEY_FALCON512SIZE;
	} 
	else if (algorithm == DNS_KEYALG_P256_FALCON512) {
		return DNS_KEY_P256_FALCON512SIZE;
	} 
	else if (algorithm == DNS_KEYALG_RSA3072_FALCON512) {
		return DNS_KEY_RSA3072_FALCON512SIZE;
	} 
	else if (algorithm == DNS_KEYALG_FALCON1024) {
		return DNS_KEY_FALCON1024SIZE;
	} 
	else if (algorithm == DNS_KEYALG_P521_FALCON1024) {
		return DNS_KEY_P521_FALCON1024SIZE;
	} 
	else if (algorithm == DNS_KEYALG_MLDSA44) {
		return DNS_KEY_MLDSA44SIZE;
	} 
	else if (algorithm == DNS_KEYALG_P256_MLDSA44) {
		return DNS_KEY_P256_MLDSA44SIZE;
	} 
	else if (algorithm == DNS_KEYALG_RSA3072_MLDSA44) {
		return DNS_KEY_RSA3072_MLDSA44SIZE;
	} 
	else if (algorithm == DNS_KEYALG_SLHDSASHA2128S) {
		return DNS_KEY_SLHDSASHA2128SSIZE;
	} 
	else if (algorithm == DNS_KEYALG_P256_SLHDSASHA2128S) {
		return DNS_KEY_P256_SLHDSASHA2128SSIZE;
	} 
	else if (algorithm == DNS_KEYALG_RSA3072_SLHDSASHA2128S) {
		return DNS_KEY_RSA3072_SLHDSASHA2128SSIZE;
	} 
	else if (algorithm == DNS_KEYALG_MAYO1) {
		return DNS_KEY_MAYO1SIZE;
	}  
	else if (algorithm == DNS_KEYALG_P256_MAYO1) {
		return DNS_KEY_P256_MAYO1SIZE;
	} 
	else if (algorithm == DNS_KEYALG_SNOVA2454) {
		return DNS_KEY_SNOVA2454SIZE;
	} 
	else if (algorithm == DNS_KEYALG_P256_SNOVA2454) {
		return DNS_KEY_P256_SNOVA2454SIZE;
	} 
    return 0;
}