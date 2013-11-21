/*
 * Copyright (c) 2011-2013 Yubico AB
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
#include <unistd.h>

#include "util.h"

#if HAVE_CR
/* for yubikey_hex_decode and yubikey_hex_p */
#include <yubikey.h>
#include <ykpbkdf2.h>
#endif /* HAVE_CR */

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
  int len;

  if (common_path != NULL) {
    len = strlen(common_path) + 1 + strlen(filename) + 1;
    if ((userfile = malloc(len)) == NULL) {
      return 0;
    }
    snprintf(userfile, len, "%s/%s", common_path, filename);
    *fn = userfile;
    return 1;
  }

  /* No common path provided. Construct path to user's ~/.yubico/filename */

  p = getpwnam (username);
  if (!p)
    return 0;

  len = strlen(p->pw_dir) + 9 + strlen(filename) + 1;
  if ((userfile = malloc(len)) == NULL) {
    return 0;
  }
  snprintf(userfile, len, "%s/.yubico/%s", p->pw_dir, filename);
  *fn = userfile;
  return 1;
}

#if HAVE_CR
/* Fill buf with len bytes of random data */
int generate_random(void *buf, int len)
{
	FILE *u;
	int res;

	u = fopen("/dev/urandom", "r");
	if (!u) {
		return -1;
	}

	res = fread(buf, 1, (size_t) len, u);
	fclose(u);

	return (res != len);
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
	    (ykds_version_major(st) == 2
         && ykds_version_minor(st) < 2)) {
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
		       char *challenge, unsigned int len,
		       bool hmac, bool may_block, bool verbose,
		       char *response, unsigned int res_size, unsigned int *res_len)
{
	int yk_cmd;

  if(hmac == true) {
    *res_len = 20;
  } else {
    *res_len = 16;
  }
	if (res_size < *res_len) {
	  return 0;
  }

	memset(response, 0, res_size);

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
	default:
		return 0;
	}

  if(! yk_challenge_response(yk, yk_cmd, may_block, len,
        (unsigned char*)challenge, res_size, (unsigned char*)response)) {
    return 0;
  }


	return 1;
}

int
get_user_challenge_file(YK_KEY *yk, const char *chalresp_path, const char *username, char **fn)
{
  /* Getting file from user home directory, i.e. ~/.yubico/challenge, or
   * from a system wide directory.
   */

  /* The challenge to use is located in a file in the user's home directory,
   * which therefor can't be encrypted. If an encrypted home directory is used,
   * the option chalresp_path can be used to point to a system-wide directory.
   */

  char *filename; /* not including directory */
  int filename_malloced = 0;
  unsigned int serial = 0;
  int ret;

  if (! yk_get_serial(yk, 0, 0, &serial)) {
    D (("Failed to read serial number (serial-api-visible disabled?)."));
    if (! chalresp_path)
      filename = "challenge";
    else
      filename = (char *) username;
  } else {
    /* We have serial number */
    int len;
    /* 0xffffffff == 4294967295 == 10 digits */
    len = strlen(chalresp_path == NULL ? "challenge" : username) + 1 + 10 + 1;
    if ((filename = malloc(len)) != NULL) {
      int res = snprintf(filename, len, "%s-%i", chalresp_path == NULL ? "challenge" : username, serial);
      filename_malloced = 1;
      if (res < 0 || res > len) {
	/* Not enough space, strangely enough. */
	free(filename);
	filename = NULL;
      }
    }
  }

  if (filename == NULL)
    return 0;

  ret = get_user_cfgfile_path (chalresp_path, filename, username, fn);
  if(filename_malloced == 1) {
    free(filename);
  }
  return ret;
}

int
load_chalresp_state(FILE *f, CR_STATE *state, bool verbose)
{
  /*
   * Load the current challenge and expected response information from a file handle.
   *
   * Format is hex(challenge):hex(response):slot num
   */
  char challenge_hex[CR_CHALLENGE_SIZE * 2 + 1], response_hex[CR_RESPONSE_SIZE * 2 + 1];
  char salt_hex[CR_SALT_SIZE * 2 + 1];
  unsigned int iterations;
  int slot;
  int r;

  if (! f)
    goto out;

  /* XXX not ideal with hard coded lengths in this scan string.
   * 126 corresponds to twice the size of CR_CHALLENGE_SIZE,
   * 40 is twice the size of CR_RESPONSE_SIZE
   * (twice because we hex encode the challenge and response)
   */
  r = fscanf(f, "v2:%126[0-9a-z]:%40[0-9a-z]:%64[0-9a-z]:%d:%d", challenge_hex, response_hex, salt_hex, &iterations, &slot);
  if(r == 5) {
    if (! yubikey_hex_p(salt_hex)) {
      D(("Invalid salt hex input : %s", salt_hex));
      goto out;
    }

    if(verbose) {
      D(("Challenge: %s, hashed response: %s, salt: %s, iterations: %d, slot: %d",
            challenge_hex, response_hex, salt_hex, iterations, slot));
    }

    yubikey_hex_decode(state->salt, salt_hex, sizeof(state->salt));
    state->salt_len = strlen(salt_hex) / 2;
  } else {
    rewind(f);
    r = fscanf(f, "v1:%126[0-9a-z]:%40[0-9a-z]:%d", challenge_hex, response_hex, &slot);
    if (r != 3) {
      D(("Could not parse contents of chalresp_state file (%i)", r));
      goto out;
    }

    if (verbose) {
      D(("Challenge: %s, expected response: %s, slot: %d", challenge_hex, response_hex, slot));
    }

    iterations = CR_DEFAULT_ITERATIONS;
  }

  state->iterations = iterations;


  if (! yubikey_hex_p(challenge_hex)) {
    D(("Invalid challenge hex input : %s", challenge_hex));
    goto out;
  }

  if (! yubikey_hex_p(response_hex)) {
    D(("Invalid expected response hex input : %s", response_hex));
    goto out;
  }

  if (slot != 1 && slot != 2) {
    D(("Invalid slot input : %i", slot));
    goto out;
  }

  yubikey_hex_decode(state->challenge, challenge_hex, sizeof(state->challenge));
  state->challenge_len = strlen(challenge_hex) / 2;

  yubikey_hex_decode(state->response, response_hex, sizeof(state->response));
  state->response_len = strlen(response_hex) / 2;

  state->slot = slot;

  return 1;

 out:
  return 0;
}

int
write_chalresp_state(FILE *f, CR_STATE *state)
{
  char challenge_hex[CR_CHALLENGE_SIZE * 2 + 1], response_hex[CR_RESPONSE_SIZE * 2 + 1];
  char salt_hex[CR_SALT_SIZE * 2 + 1], hashed_hex[CR_RESPONSE_SIZE * 2 + 1];
  unsigned char salt[CR_SALT_SIZE], hash[CR_RESPONSE_SIZE];
  YK_PRF_METHOD prf_method = {20, yk_hmac_sha1};
  unsigned int iterations = CR_DEFAULT_ITERATIONS;
  int fd;

  memset(challenge_hex, 0, sizeof(challenge_hex));
  memset(response_hex, 0, sizeof(response_hex));
  memset(salt_hex, 0, sizeof(salt_hex));
  memset(hashed_hex, 0, sizeof(hashed_hex));

  yubikey_hex_encode(challenge_hex, (char *)state->challenge, state->challenge_len);
  yubikey_hex_encode(response_hex, (char *)state->response, state->response_len);

  if(state->iterations > 0) {
    iterations = state->iterations;
  }

  generate_random(salt, CR_SALT_SIZE);
  yk_pbkdf2(response_hex, salt, CR_SALT_SIZE, iterations,
      hash, CR_RESPONSE_SIZE, &prf_method);

  yubikey_hex_encode(hashed_hex, (char *)hash, CR_RESPONSE_SIZE);
  yubikey_hex_encode(salt_hex, (char *)salt, CR_SALT_SIZE);

  rewind(f);

  fd = fileno(f);
  if (fd == -1)
    goto out;

  if (ftruncate(fd, 0))
    goto out;

  fprintf(f, "v2:%s:%s:%s:%d:%d\n", challenge_hex, hashed_hex, salt_hex, iterations, state->slot);

  if (fflush(f) < 0)
    goto out;

  if (fsync(fd) < 0)
    goto out;

  return 1;
 out:
  return 0;
}
#endif /* HAVE_CR */
