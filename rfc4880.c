/* rfc4880.c
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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <fcntl.h>
#include <sys/stat.h>

#include "rfc4880.h"
#include "crypto.h"
#include "sha1.h"

struct mpi {
	u32 size;
	u8 *data;
};

static int parse_mpi(u8 **_data, int *_dlen, struct mpi *mpi)
{
	unsigned char *data = *_data;
	int dlen = *_dlen;

	if (dlen < 2)
		return -1;

	mpi->size = (((data[0] << 8) | data[1]) + 7) / 8;

	dlen -= 2;
	data += 2;
	if (mpi->size > dlen)
		return -1;

	mpi->data = data;
	data += mpi->size;
	dlen -= mpi->size;

	*_data = data;
	*_dlen = dlen;

	return 0;
}

static int parse_key(u8 *data, int dlen,
		     struct rsa_public_key **_public,
		     struct rsa_private_key **_private)
{
	struct rsa_public_key *public;
	struct rsa_private_key *private;
	struct mpi n, e, d, p, q, u;

	if (data[0] != 4) {
		fprintf(stderr,"unsupported key version %d\n", data[0]);
		return -1;
	}

	switch (data[5]) {
	case ALGO_RSA_ENCRYPT_OR_SIGN:
	case ALGO_RSA_ENCRYPT_ONLY:
	case ALGO_RSA_SIGN_ONLY:
		break;
	default:
		fprintf(stderr,"unsupported algorithm %d\n", data[5]);
		return -1;
	}

	data += 6;
	dlen -= 6;

	if (parse_mpi(&data, &dlen, &n))
		return -1;
	if (parse_mpi(&data, &dlen, &e))
		return -1;

	if (_private) {
		if (dlen < 1)
			return -1;
		if (data[0] != 0x00) {
			fprintf(stderr,"unsupported encrypted key\n");
			return -1;
		}
		data++;
		dlen--;
		if (parse_mpi(&data, &dlen, &d))
			return -1;
		if (parse_mpi(&data, &dlen, &p))
			return -1;
		if (parse_mpi(&data, &dlen, &q))
			return -1;
		if (parse_mpi(&data, &dlen, &u))
			return -1;
		/* checksum */
		if (dlen != 2) {
			fprintf(stderr,"missing checksum\n");
			return -1;
		}
	}

	public = malloc(sizeof(*public) + n.size + e.size);
	if (!public)
		return -1;

	public->n_sz = n.size;
	public->e_sz = e.size;
	public->n = (u8*) (public + 1);
	public->e = public->n + n.size;
	memcpy(public->n, n.data, n.size);
	memcpy(public->e, e.data, e.size);

	if (_private) {
		private = malloc(sizeof(*private) + n.size + d.size);
		if (!private) {
			free(public);
			return -1;
		}

		private->n_sz = n.size;
		private->d_sz = d.size;
		private->n = (u8*) (private + 1);
		private->d = private->n + n.size;
		memcpy(private->n, n.data, n.size);
		memcpy(private->d, d.data, d.size);

		*_private = private;
	}

	*_public = public;

	return 0;
}

static int parse_signature(u8 *data, int dlen,
			   struct rsa_signature **_signature)
{
	struct rsa_signature *signature;
	struct mpi s;
	u8 *save = data;
	unsigned extra, left16;
	unsigned n;

	if (dlen < 6)
		return -1;

	if (data[0] != 4) {
		fprintf(stderr,"cannot handle non-v4 signatures\n");
		return -1;
	}

        /* data[1] = type */
	switch (data[2]) {
	case ALGO_RSA_ENCRYPT_OR_SIGN:
	case ALGO_RSA_ENCRYPT_ONLY:
	case ALGO_RSA_SIGN_ONLY:
		break;
	default:
		fprintf(stderr,"unsupported algorithm %d\n", data[2]);
		return -1;
	}

	if (data[3] != HASH_SHA1) {
		fprintf(stderr,"unsupported hash %d\n", data[3]);
		return -1;
	}

	extra = (data[4] << 8) | data[5];

	data += 6;
	dlen -= 6;

	if (extra > dlen)
		return -1;

	data += extra;
	dlen -= extra;

	if (dlen < 2)
		return -1;

	n = (data[0] << 8) | data[1];
	data += 2;
	dlen -= 2;

	if (n > dlen)
		return -1;

	data += n;
	dlen -= n;

	if (dlen < 2)
		return -2;

	left16 = (data[0] << 8) | data[1];
	data += 2;
	dlen -= 2;

	if (parse_mpi(&data, &dlen, &s))
		return -1;

        /* add the header and footer size (both 6 bytes) */
	extra += 12;

	if (_signature) {
		signature = malloc(sizeof(*signature) + s.size + extra);
		if (!signature)
			return -1;

		signature->s_sz = s.size;
		signature->h_sz = extra;
		signature->left16 = left16;
		signature->s = (u8*) (signature + 1);
		signature->h = signature->s + s.size;
		memcpy(signature->s, s.data, s.size);
        
		extra -= 6;
		memcpy(signature->h, save, extra);
        
		/* footer per rfc4880 5.2.4 */
		signature->h[extra + 0] = 0x04;
		signature->h[extra + 1] = 0xFF;
		signature->h[extra + 2] = extra >> 24;
		signature->h[extra + 3] = extra >> 16;
		signature->h[extra + 4] = extra >> 8;
		signature->h[extra + 5] = extra;

		*_signature = signature;
	}
	return 0;
}

static int parse_rfc4880(unsigned char *data, int dlen,
			 struct rsa_public_key **public,
			 struct rsa_private_key **private,
			 struct rsa_signature **signature)
{
	while (dlen > 0) {
		unsigned char x;
		x = *data++;
		dlen--;
		unsigned plen, ptype;
		if (!(x & 0x80)) {
			fprintf(stderr,"invalid packet header %02x\n", x);
			return -1;
		}
		if (x & 0x40) {
			fprintf(stderr,"cannot decode new header %02x\n", x);
			return -1;
		}
		ptype = (x >> 2) & 15;
		switch (x & 3) {
		case 0:
			if (dlen < 1)
				return -1;
			plen = data[0];
			data++;
			dlen--;
			break;
		case 1:
			if (dlen < 2)
				return -1;
			plen = data[1] | (data[0] << 8);
			data+=2;
			dlen-=2;
			break;
		case 2:
		case 3:
			fprintf(stderr,"cannot handle length type %d\n", x & 3);
			return -1;
		}

		if (plen > dlen)
			return -1;

		switch (ptype) {
		case 2:
			if (parse_signature(data, plen, signature))
				return -1;
			break;
		case 5:
			if (parse_key(data, plen, public, private))
				return -1;
			break;
		case 6:
			if (parse_key(data, plen, public, 0))
				return -1;
			break;
		}

		dlen -= plen;
		data += plen;

		/* are we done? */
		if (public && !*public)
			continue;
		if (private && !*private)
			continue;
		if (signature && !*signature)
			continue;

		return 0;
	}

	fprintf(stderr,"missing required elements\n");
	return -1;
}

int rfc4880_load_public_key(u8 *data, u32 len,
			    struct rsa_public_key **public)
{
	return parse_rfc4880(data, len, public, 0, 0);
}


int rfc4880_load_private_key(u8 *data, u32 len,
			     struct rsa_private_key **private,
			     struct rsa_public_key **public)
{
	return parse_rfc4880(data, len, public, private, 0);
}

int rfc4880_load_signature(u8 *data, u32 len,
			   struct rsa_signature **signature)
{
	return parse_rfc4880(data, len, 0, 0, signature);
}

u8 *load_file(const char *fn, u32 *sz)
{
	struct stat s;
	u8 *data = 0;
	int fd;

	fd = open(fn, O_RDONLY);
	if (fd < 0)
		return 0;

	if (fstat(fd, &s))
		goto fail;

	data = malloc(s.st_size);
	if (!data)
		goto fail;

	if (read(fd, data, s.st_size) != s.st_size)
		goto fail;

	*sz = s.st_size;
	close(fd);
	return data;

fail:
	free(data);
	close(fd);
	return 0;
}


int rfc4880_open_public_key(const char *fn, struct rsa_public_key **public)
{
	u8 *data;
	u32 sz;
	int r;

	data = load_file(fn, &sz);
	if (!data) {
		fprintf(stderr,"failed to open '%s'\n", fn);
		return -1;
	}
	r = rfc4880_load_public_key(data, sz, public);
	free(data);
	return r;
}

int rfc4880_open_signature(const char *fn, struct rsa_signature **signature)
{
	u8 *data;
	u32 sz;
	int r;

	data = load_file(fn, &sz);
	if (!data) {
		fprintf(stderr,"failed to open '%s'\n", fn);
		return -1;
	}
	r = rfc4880_load_signature(data, sz, signature);
	free(data);
	return r;
}

int rfc4880_verify(u8 *data, u32 len,
		   struct rsa_public_key *public,
		   struct rsa_signature *signature)
{
	struct SHA_CTX ctx;
	const u8 *digest;

	SHA_init(&ctx);
	SHA_update(&ctx, data, len);
	SHA_update(&ctx, signature->h, signature->h_sz);
	digest = SHA_final(&ctx);

	return rsa_verify(public, digest, signature->s, signature->s_sz);
}
