/* rfc4880dump.c
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

void dump(const char *name, unsigned char *x, unsigned len)
{
	unsigned n;
	printf("unsigned char %s[%d] = {", name, len);

	for (n = 0; n < len; n++) {
		if ((n % 12) == 0)
			printf("\n");
		printf(" 0x%02x,", *x++);
	}
	if ((n % 12) != 1)
		printf("\n");
	printf("};\n");
}

const char *to_sig_type(unsigned char n)
{
	switch (n) {
	case 0x00: return "binary document";
	case 0x01: return "canonical text document";
	case 0x02: return "standalone signature";
	case 0x10: return "generic certification";
	case 0x11: return "persona certification";
	case 0x12: return "casual certification";
	case 0x13: return "positive certification";
	case 0x18: return "subkey binding signature";
	case 0x19: return "primary key binding signature";
	case 0x1f: return "signature directly on a key";
	case 0x20: return "key revocation signature";
	case 0x28: return "subkey revocation signature";
	case 0x30: return "certification revocation signature";
	case 0x40: return "timestamp signature";
	case 0x50: return "third-party confirmation signature";
	default: return "UNKNOWN";
	}
}

const char *to_pubkey_algo(unsigned char n)
{
	switch (n) {
	case  1: return "RSA (Encrypt or Sign)";
	case  2: return "RSA (Encrypt-Only)";
	case  3: return "RSA (Sign-Only)";
	case 16: return "Elgamal (Encrypt-Only";
	case 18: return "Elliptic Curve";
	case 19: return "ECDSA";
	case 21: return "Diffie-Hellman";
	default: return "UNKNOWN";
    }
}

const char *to_hash_algo(unsigned char n)
{
	switch (n) {
	case  1: return "MD5";
	case  2: return "SHA-1";
	case  3: return "RIPE-MD/160";
	case  8: return "SHA256";
	case  9: return "SHA384";
	case 10: return "SHA512";
	case 11: return "SHA224";
	default: return "UNKNOWN";
	}
}

int parse_mpi(unsigned char *data, int dlen)
{
	unsigned bits, bytes;
	if (dlen < 2)
		return -1;

	bits = (data[0] << 8) | data[1];

	bytes = (bits + 7) / 8;

	dlen -= 2;
	data += 2;
	if (bytes > dlen)
		return -1;

	printf("MPI (%d bits): %02x %02x %02x %02x ...\n",
	       bits, data[0], data[1], data[2], data[3]);

	return bytes;
}

int parse_key(unsigned char *data, int dlen, int secret)
{
	unsigned when;
	int r;

	if (data[0] != 4) {
		printf("cannot handle non-v4 keys\n");
		return -1;
	}
	when = (data[1]<<24)|(data[2]<<16)|(data[3]<<8)|data[4];
	printf("algo: %s\n", to_pubkey_algo(data[5]));
	data += 6;
	dlen -= 6;

	r = parse_mpi(data, dlen); /* n */
	if (r < 0)
		return -1;
	dump("rsa_n", data + 2, (((data[0]<<8)|data[1]) + 7) / 8);
	data += r + 2;
	dlen -= r + 2;

	r = parse_mpi(data, dlen); /* e */
	if (r < 0)
		return -1;
	dump("rsa_e", data + 2, (((data[0]<<8)|data[1]) + 7) / 8);
	data += r + 2;
	dlen -= r + 2;

	if (!secret)
		return 0;

	printf("S2K %02x\n", data[0]);
	dlen -= 1;
	data += 1;

	r = parse_mpi(data, dlen); /* d */
	if (r < 0)
		return -1;
	dump("rsa_d", data + 2, (((data[0]<<8)|data[1]) + 7) / 8);
	data += r + 2;
	dlen -= r + 2;
	r = parse_mpi(data, dlen); /* p */
	if (r < 0)
		return -1;
	data += r + 2;
	dlen -= r + 2;
	r = parse_mpi(data, dlen); /* q */
	if (r < 0)
		return -1;
	data += r + 2;
	dlen -= r + 2;
	r = parse_mpi(data, dlen); /* u */
	if (r < 0)
		return -1;
	data += r + 2;
	dlen -= r + 2;

        /* checksum */
	if (dlen != 2)
		return -1;

	return 0;
}

void parse_signature(unsigned char *data, int dlen)
{
	unsigned char *save = data;
	unsigned n, i;

	if (data[0] != 4) {
		printf("cannot handle non-v4 signatures\n");
		return;
	}
	printf("signature type: %s\n", to_sig_type(data[1]));
	printf("pubkey algo:    %s\n", to_pubkey_algo(data[2]));
	printf("hash algo:      %s\n", to_hash_algo(data[3]));

	data += 4;
	dlen -= 4;

	n = (data[0] << 8) | data[1];
	data += 2;
	dlen -= 2;

	printf("hashed subpacket data:");
	for (i = 0; i < n; i++)
		printf(" %02x", data[i]);
	printf("\n");
	data += n;
	dlen -= n;

	printf("bytes of header data to hash: %d\n", data - save);

	n = (data[0] << 8) | data[1];
	data += 2;
	dlen -= 2;

	printf("unhashed subpacket data:");
	for (i = 0; i < n; i++)
		printf(" %02x", data[i]);
	printf("\n");
	data += n;
	dlen -= n;

	printf("left16 signed hash: %02x%02x\n", data[0], data[1]);
	data += 2;
	dlen -= 2;

	n = (data[0] << 8) | data[1];
	data += 2;
	dlen -= 2;

	printf("signature: %d bits: %02x %02x %02x %02x ...\n", n,
	       data[0], data[1], data[2], data[3]);
}

void parse(unsigned char *data, int dlen)
{
	unsigned n;
	while (dlen > 0) {
		unsigned char x;

		x = *data++;
		dlen--;
		unsigned plen, ptype;
		if (!(x & 0x80)) {
			printf("invalid packet header %02x\n", x);
			return;
		}
		if (x & 0x40) {
			printf("cannot decode new header %02x\n", x);
			return;
		}
		ptype = (x >> 2) & 15;
		switch (x & 3) {
		case 0:
			plen = data[0];
			data++;
			dlen--;
			break;
		case 1:
			plen = data[1] | (data[0] << 8);
			data+=2;
			dlen-=2;
			break;
		case 2:
		case 3:
			printf("cannot handle length type %d\n", x & 3);
			return;
		}

		switch (ptype) {
		case 2:
			printf("\n-- signature (len %d) --\n", plen);
			parse_signature(data, plen);
			break;
		case 5:
			printf("\n-- secret key (len %d) --\n", plen);
			parse_key(data, plen, 1);
			break;
		case 6:
			printf("\n-- public key (len %d) --\n", plen);
			parse_key(data, plen, 0);
			break;
		case 13:
			printf("\n-- user id (len %d) --\n", plen);
			for (n = 0; n < plen; n++) {
				printf("%c", data[n] & 127);
			}
			printf("\n");
			break;
		case 14:
			printf("\n-- public subkey (len %d) --\n", plen);
			parse_key(data, plen, 0);
			break;
		default:
			printf("-- type %d len %d --\n", ptype, plen);
		}

		dlen -= plen;
		data += plen;
	}
}

int main(int argc, char **argv)
{
	unsigned char buf[4096];
	int len;
	len = read(0, buf, 4096);
	printf("len = %d\n", len);
	parse(buf, len);
	return 0;
}
