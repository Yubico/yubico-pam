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

#ifndef __PAM_YUBICO_UTIL_H_INCLUDED__
#define __PAM_YUBICO_UTIL_H_INCLUDED__

#include <stdio.h>

#include <ykclient.h>


#if defined(DEBUG_PAM)
# if defined(HAVE_SECURITY__PAM_MACROS_H)
#  define DEBUG
#  include <security/_pam_macros.h>
# else
#  define D(x) do {							\
    printf ("debug: %s:%d (%s): ", __FILE__, __LINE__, __FUNCTION__);	\
    printf x;								\
    printf ("\n");							\
  } while (0)
# endif /* HAVE_SECURITY__PAM_MACROS_H */
#endif /* DEBUG_PAM */

int get_user_cfgfile_path(const char *common_path, const char *filename, const char *username, char **fn);

#if HAVE_CR

#include <ykcore.h>
#include <ykstatus.h>
#include <ykdef.h>

/* Challenges can be 0..63 or 64 bytes long, depending on YubiKey configuration.
 * We settle for 63 bytes to have something that works with all configurations.
 */
#define CR_CHALLENGE_SIZE	63
#define CR_RESPONSE_SIZE	20

struct chalresp_state {
  char challenge[CR_CHALLENGE_SIZE];
  uint8_t challenge_len;
  char response[CR_RESPONSE_SIZE];
  uint8_t response_len;
  uint8_t slot;
};

typedef struct chalresp_state CR_STATE;

int generate_random(void *buf, int len);

int get_user_challenge_file(YK_KEY *yk, const char *chalresp_path, const char *username, char **fn);

int load_chalresp_state(FILE *f, CR_STATE *state);
int write_chalresp_state(FILE *f, CR_STATE *state);

int init_yubikey(YK_KEY **yk);
int check_firmware_version(YK_KEY *yk, bool verbose, bool quiet);
int challenge_response(YK_KEY *yk, int slot,
		       char *challenge, unsigned int len,
		       bool hmac, unsigned int flags, bool verbose,
		       char *response, int res_size, unsigned int *res_len);

#endif /* HAVE_CR */

#endif /* __PAM_YUBICO_UTIL_H_INCLUDED__ */
