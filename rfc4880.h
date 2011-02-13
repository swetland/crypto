/* rfc4880.h
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

#ifndef _RFC4880_H_
#define _RFC4880_H_

#define SIG_BINARY_DOC				0x00
#define SIG_CANONICAL_TEXT_DOC			0x01
#define SIG_STANDALONE				0x02
#define SIG_CERTIFICATION_GENERIC		0x10
#define SIG_CERTIFICATION_PERSONA		0x11
#define SIG_CERTIFICATION_CASUAL		0x12
#define SIG_CERTIFICATION_POSITIVE		0x13
#define SIG_SUBKEY_BINDING			0x18
#define SIG_PRIKEY_BINDING			0x19
#define SIG_KEY_DIRECT				0x1F
#define SIG_KEY_REVOCATION			0x20
#define SIG_SUBKEY_REVOCATION			0x28
#define SIG_CERTIFICATION_REVOCATION		0x30
#define SIG_TIMESTAMP				0x40
#define SIG_CONFIRMATION			0x50

#define ALGO_RSA_ENCRYPT_OR_SIGN		1
#define ALGO_RSA_ENCRYPT_ONLY			2
#define ALGO_RSA_SIGN_ONLY			3
#define ALGO_ELGAMAL_ENCRYPT_ONLY		16
#define ALGO_ELLIPTIC_CURVE			18
#define ALGO_ECDSA				19
#define ALGO_DIFFIE_HELLMAN			21

#define HASH_MD5				1
#define HASH_SHA1				2
#define HASH_RIPEMD160				3
#define HASH_SHA256				8
#define HASH_SHA384				9
#define HASH_SHA512				10
#define HASH_SHA224				11

#endif
