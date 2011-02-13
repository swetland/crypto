/* crypto.h
 *
 * Copyright 2011 Brian Swetland. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR 
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef _CRYPTO_H_
#define _CRYPTO_H_

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned long u32;

struct rsa_public_key {
	u32 n_sz;
	u32 e_sz;
	u8 *n; /* modulus n */
	u8 *e; /* public exponent e */
};

struct rsa_private_key {
	u32 n_sz;
	u32 d_sz;
	u8 *n; /* modulus n */
	u8 *d; /* private exponent d */
};

struct rsa_signature {
	u32 s_sz;
	u32 h_sz;
	u32 left16;
	u8 *s; /* signature */
	u8 *h; /* extra hash data */
};

/* load from byte array */
int rfc4880_load_public_key(u8 *data, u32 len,
			    struct rsa_public_key **public);
int rfc4880_load_private_key(u8 *data, u32 len,
			     struct rsa_private_key **private,
			     struct rsa_public_key **public);
int rfc4880_load_signature(u8 *data, u32 len,
			   struct rsa_signature **signature);

/* read from file */
int rfc4880_open_public_key(const char *fn,
			    struct rsa_public_key **public);
int rfc4880_open_signature(const char *fn,
			   struct rsa_signature **signature);

/* verify that data[0:len] is signed by public with signature (0=verified) */
int rfc4880_verify(u8 *data, u32 len,
		   struct rsa_public_key *public,
		   struct rsa_signature *signature);

/* create signature for digest */
int rsa_sign(struct rsa_private_key *private,
	     const u8 *digest, u8 *signature_out);

/* verify digest with public key and signature (0=verified) */
int rsa_verify(struct rsa_public_key *public,
	       const u8 *digest, const u8 *signature, u32 slen);

/* useful utility */
u8 *load_file(const char *fn, u32 *sz);

#endif
