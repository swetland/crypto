/* verify.c
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

#include "crypto.h"

int main(int argc, char **argv)
{
    struct rsa_public_key *public = 0;
    struct rsa_signature *signature = 0;
    u8 *msg;
    u32 msgsz;

    if (argc != 4) {
        fprintf(stderr,"usage: verify <message> <signature> <pubkey>\n");
        return -1;
    }

    if ((msg = load_file(argv[1],&msgsz)) == 0) {
        fprintf(stderr,"failed to load '%s'\n", argv[1]);
        return -1;
    }
    if (rfc4880_open_signature(argv[2], &signature)) {
        fprintf(stderr,"failed to open signature\n");
        return -1;
    }
    if (rfc4880_open_public_key(argv[3], &public)) {
        fprintf(stderr,"failed to open public key\n");
        return -1;
    }
    if (rfc4880_verify(msg, msgsz, public, signature)) {
        fprintf(stderr,"FAILED\n");
        return -1;
    }

    fprintf(stderr,"VERIFIED\n");
    return 0;
}
