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

#include <ykclient.h>
#include <ykcore.h>
#include <ykstatus.h>
#include <ykdef.h>

int generate_random(char *buf, int len);
int get_user_cfgfile_path(const char *common_path, const char *filename, const char *username, char **fn);

int init_yubikey(YK_KEY **yk);
int check_firmware_version(YK_KEY *yk, bool verbose, bool quiet);
int challenge_response(YK_KEY *yk, int slot,
		       unsigned char *challenge, unsigned int len,
		       bool hmac, unsigned int flags, bool verbose,
		       unsigned char *response, int res_size, int *res_len);
