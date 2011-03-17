/*
 * Copyright (c) 2011 Yubico AB.
 * Copyright (c) 2011 Tollef Fog Heen <tfheen@err.no>
 * All rights reserved.
 *
 * Author : Fredrik Thulin <fredrik@yubico.com>
 * Author : Tollef Fog Heen <tfheen@err.no>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *
 *     * Redistributions in binary form must reproduce the above
 *       copyright notice, this list of conditions and the following
 *       disclaimer in the documentation and/or other materials provided
 *       with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <pwd.h>

#include "util.h"

#include <ykclient.h>
#include <ykcore.h>
#include <ykstatus.h>
#include <ykdef.h>

/* Fill buf with len bytes of random data */
int generate_random(char *buf, int len)
{
	FILE *u;
	int i, res;

	u = fopen("/dev/urandom", "r");
	if (!u) {
		return -1;
	}

	res = fread(buf, 1, (size_t) len, u);
	fclose(u);

	return (res != len);
}

int
get_user_cfgfile_path(const char *common_path, const char *filename, const char *username, char **fn)
{
	/* Getting file from user home directory, e.g. ~/.yubico/challenge, or
	 * from a system wide directory.
	 *
	 * Format is hex(challenge):hex(response):slot num
	 */
	struct passwd *p;
	char *userfile;

	if (common_path != NULL) {
		if (asprintf (&userfile, "%s/%s", common_path, filename) >= 0)
			*fn = userfile;
		return (userfile >= 0);
	}

	/* No common path provided. Construct path to user's ~/.yubico/filename */

	p = getpwnam (username);
	if (!p)
		return 0;

	if (asprintf (&userfile, "%s/.yubico/%s", p->pw_dir, filename) >= 0)
		*fn = userfile;
	return (userfile >= 0);
}

int
check_firmware_version(YK_KEY *yk, bool verbose, bool quiet)
{
	YK_STATUS *st = ykds_alloc();

	if (!yk_get_status(yk, st)) {
		free(st);
		return 0;
	}

	if (verbose) {
		printf("Firmware version %d.%d.%d\n",
		       ykds_version_major(st),
		       ykds_version_minor(st),
		       ykds_version_build(st));
		fflush(stdout);
	}

	if (ykds_version_major(st) < 2 ||
	    ykds_version_minor(st) < 2) {
		if (! quiet)
			fprintf(stderr, "Challenge-response not supported before YubiKey 2.2.\n");
		free(st);
		return 0;
	}

	free(st);
	return 1;
}

int
init_yubikey(YK_KEY **yk)
{
	if (!yk_init())
		return 0;

	if (!(*yk = yk_open_first_key()))
		return 0;

	return 1;
}

int challenge_response(YK_KEY *yk, int slot,
		       unsigned char *challenge, unsigned int len,
		       bool hmac, unsigned int flags, bool verbose,
		       unsigned char *response, int res_size, int *res_len)
{
	int yk_cmd;
	unsigned int response_len = 0;
	unsigned int expect_bytes = 0;

	if (res_size < sizeof(64 + 16))
	  return 0;
	
	memset(response, 0, sizeof(response));

	if (verbose) {
		fprintf(stderr, "Sending %i bytes %s challenge to slot %i\n", len, (hmac == true)?"HMAC":"Yubico", slot);
		//_yk_hexdump(challenge, len);
	}

	switch(slot) {
	case 1:
		yk_cmd = (hmac == true) ? SLOT_CHAL_HMAC1 : SLOT_CHAL_OTP1;
		break;
	case 2:
		yk_cmd = (hmac == true) ? SLOT_CHAL_HMAC2 : SLOT_CHAL_OTP2;
		break;
	}

	if (!yk_write_to_key(yk, yk_cmd, challenge, len))
		return 0;

	if (verbose) {
		fprintf(stderr, "Reading response...\n");
	}

	/* HMAC responses are 160 bits, Yubico 128 */
	expect_bytes = (hmac == true) ? 20 : 16;

	if (! yk_read_response_from_key(yk, slot, flags,
					response, res_size,
					expect_bytes,
					&response_len))
		return 0;

	if (hmac && response_len > 20)
		response_len = 20;
	if (! hmac && response_len > 16)
		response_len = 16;

	*res_len = response_len;

	return 1;
}
