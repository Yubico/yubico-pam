/*
 * Copyright (c) 2011-2014 Yubico AB
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

#ifndef __PAM_YUBICO_UTIL_H_INCLUDED__
#define __PAM_YUBICO_UTIL_H_INCLUDED__

#include <stdio.h>
#include <stdint.h>
#include <pwd.h>

#define D(file, x...) do {							\
  fprintf (file, "debug: %s:%d (%s): ", __FILE__, __LINE__, __FUNCTION__);	\
  fprintf (file, x);								\
  fprintf (file, "\n");							\
} while (0)

/* Return values for authorize_user_token and authorize_user_token_ldap */
#define AUTH_NO_TOKENS -2 /* The user has no associated tokens */
#define AUTH_ERROR      0 /* Internal error when looking up associated tokens */
#define AUTH_FOUND      1 /* The requested token is associated to the user */
#define AUTH_NOT_FOUND -1 /* The requested token is not associated to the user */

int get_user_cfgfile_path(const char *common_path, const char *filename, const struct passwd *user, char **fn);
int check_user_token(const char *authfile, const char *username, const char *otp_id, int verbose, FILE *debug_file);

#if HAVE_CR
#include <ykcore.h>

/* Challenges can be 0..63 or 64 bytes long, depending on YubiKey configuration.
 * We settle for 63 bytes to have something that works with all configurations.
 */
#define CR_CHALLENGE_SIZE	63
#define CR_RESPONSE_SIZE	20
#define CR_SALT_SIZE      32

#define CR_DEFAULT_ITERATIONS 10000

struct chalresp_state {
  char challenge[CR_CHALLENGE_SIZE];
  uint8_t challenge_len;
  char response[CR_RESPONSE_SIZE];
  uint8_t response_len;
  char salt[CR_SALT_SIZE];
  uint8_t salt_len;
  uint8_t slot;
  uint32_t iterations;
};

typedef struct chalresp_state CR_STATE;

int generate_random(void *buf, int len);

int check_user_challenge_file(const char *chalresp_path, const struct passwd *user, FILE *debug_file);
int get_user_challenge_file(YK_KEY *yk, const char *chalresp_path, const struct passwd *user, char **fn, FILE *debug_file);

int load_chalresp_state(FILE *f, CR_STATE *state, bool verbose, FILE *debug_file);
int write_chalresp_state(FILE *f, CR_STATE *state);

int init_yubikey(YK_KEY **yk);
int check_firmware_version(YK_KEY *yk, bool verbose, bool quiet, FILE *debug_file);
int challenge_response(YK_KEY *yk, int slot,
		       char *challenge, unsigned int len,
		       bool hmac, bool may_block, bool verbose,
		       char *response, unsigned int res_size, unsigned int *res_len);

#endif /* HAVE_CR */

size_t filter_result_len(const char *filter, const char *user, char *output);
char *filter_printf(const char *filter, const char *user);

#endif /* __PAM_YUBICO_UTIL_H_INCLUDED__ */