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

/* Fill buf with len bytes of random data */
static int generate_random(char *buf, int len)
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
	/* Getting file from user home directory, i.e. ~/.yubico/challenge, or
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
