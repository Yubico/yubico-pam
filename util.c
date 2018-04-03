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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <glob.h>
#include <unistd.h>

#include "util.h"

#if HAVE_CR
/* for yubikey_hex_decode and yubikey_hex_p */
#include <yubikey.h>
#include <ykpbkdf2.h>

#include <ykstatus.h>
#include <ykdef.h>
#endif /* HAVE_CR */

int
get_user_cfgfile_path(const char *common_path, const char *filename, const struct passwd *user, char **fn)
{
  /* Getting file from user home directory, e.g. ~/.yubico/challenge, or
   * from a system wide directory.
   *
   * Format is hex(challenge):hex(response):slot num
   */
  char *userfile;
  size_t len;

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

  len = strlen(user->pw_dir) + 9 + strlen(filename) + 1;
  if ((userfile = malloc(len)) == NULL) {
    return 0;
  }
  snprintf(userfile, len, "%s/.yubico/%s", user->pw_dir, filename);
  *fn = userfile;
  return 1;
}


/*
 * This function will look for users name with valid user token id.
 *
 * Returns one of AUTH_FOUND, AUTH_NOT_FOUND, AUTH_NO_TOKENS, AUTH_ERROR.
 *
 * File format is as follows:
 * <user-name>:<token_id>:<token_id>
 * <user-name>:<token_id>
 *
 */
int
check_user_token (const char *authfile,
		  const char *username,
		  const char *otp_id,
		  int verbose,
                  FILE *debug_file)
{
  char buf[1024];
  char *s_user, *s_token;
  int retval = AUTH_ERROR;
  int fd;
  struct stat st;
  FILE *opwfile;

  fd = open(authfile, O_RDONLY, 0);
  if (fd < 0) {
      if(verbose)
	  D (debug_file, "Cannot open file: %s (%s)", authfile, strerror(errno));
      return retval;
  }

  if (fstat(fd, &st) < 0) {
      if(verbose)
	  D (debug_file, "Cannot stat file: %s (%s)", authfile, strerror(errno));
      close(fd);
      return retval;
  }

  if (!S_ISREG(st.st_mode)) {
      if(verbose)
	  D (debug_file, "%s is not a regular file", authfile);
      close(fd);
      return retval;
  }

  opwfile = fdopen(fd, "r");
  if (opwfile == NULL) {
      if(verbose)
	  D (debug_file, "fdopen: %s", strerror(errno));
      close(fd);
      return retval;
  }

  retval = AUTH_NO_TOKENS;
  while (fgets (buf, 1024, opwfile))
    {
      char *saveptr = NULL;
      if (buf[strlen (buf) - 1] == '\n')
	buf[strlen (buf) - 1] = '\0';
      if (buf[0] == '#') {
          /* This is a comment and we may skip it. */
          if(verbose)
              D (debug_file, "Skipping comment line: %s", buf);
          continue;
      }
      if(verbose)
	  D (debug_file, "Authorization line: %s", buf);
      s_user = strtok_r (buf, ":", &saveptr);
      if (s_user && strcmp (username, s_user) == 0)
	{
	  if(verbose)
	      D (debug_file, "Matched user: %s", s_user);
      retval = AUTH_NOT_FOUND; /* We found at least one line for the user */
	  do
	    {
	      s_token = strtok_r (NULL, ":", &saveptr);
	      if(verbose)
		  D (debug_file, "Authorization token: %s", s_token);
	      if (s_token && otp_id && strcmp (otp_id, s_token) == 0)
		{
		  if(verbose)
		      D (debug_file, "Match user/token as %s/%s", username, otp_id);

		  fclose(opwfile);
		  return AUTH_FOUND;
		}
	    }
	  while (s_token != NULL);
	}
    }

  fclose (opwfile);

  return retval;
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
check_firmware_version(YK_KEY *yk, bool verbose, bool quiet, FILE *debug_file)
{
	YK_STATUS *st = ykds_alloc();

	if (!yk_get_status(yk, st)) {
		free(st);
		return 0;
	}

	if (verbose) {
		D(debug_file, "YubiKey Firmware version: %d.%d.%d\n",
		       ykds_version_major(st),
		       ykds_version_minor(st),
		       ykds_version_build(st));
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
		fprintf(stderr, "Sending %u bytes %s challenge to slot %i\n", len, (hmac == true)?"HMAC":"Yubico", slot);
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
check_user_challenge_file(const char *chalresp_path, const struct passwd *user, FILE *debug_file)
{
  /*
   * This function will look for users challenge files.
   *
   * Returns one of AUTH_FOUND, AUTH_NOT_FOUND, AUTH_ERROR
   */
  size_t len;
  int r;
  int ret = AUTH_NOT_FOUND;
  char *userfile = NULL;
  char *userfile_pattern = NULL;
  glob_t userfile_glob;
  const char *filename = NULL;

  if (! chalresp_path) {
    filename = "challenge";
  } else {
    filename = user->pw_name;
  }

  /* check for userfile challenge files */
  r = get_user_cfgfile_path(chalresp_path, filename, user, &userfile);
  if (!r) {
    D (debug_file, "Failed to get user cfgfile path");
    ret = AUTH_ERROR;
    goto out;
  }

  if (!access(userfile, F_OK)) {
    ret = AUTH_FOUND;
    goto out;
  }

  /* check for userfile-* challenge files */
  len = strlen(userfile) + 2 + 1;
  if ((userfile_pattern = malloc(len)) == NULL) {
    D (debug_file, "Failed to allocate memory for userfile pattern: %s", strerror(errno));
    ret = AUTH_ERROR;
    goto out;
  }
  snprintf(userfile_pattern, len, "%s-*", userfile);

  r = glob(userfile_pattern, 0, NULL, &userfile_glob);
  globfree(&userfile_glob);
  switch (r) {
    case GLOB_NOMATCH:
      /* No matches found, so continue */
      break;
    case 0:
      ret = AUTH_FOUND;
      goto out;
    default:
      D (debug_file, "Error while checking for %s challenge files: %s", userfile_pattern, strerror(errno));
      ret = AUTH_ERROR;
      goto out;
  }

out:
  free(userfile_pattern);
  free(userfile);
  return ret;
}

int
get_user_challenge_file(YK_KEY *yk, const char *chalresp_path, const struct passwd *user, char **fn, FILE *debug_file)
{
  /* Getting file from user home directory, i.e. ~/.yubico/challenge, or
   * from a system wide directory.
   */

  /* The challenge to use is located in a file in the user's home directory,
   * which therefor can't be encrypted. If an encrypted home directory is used,
   * the option chalresp_path can be used to point to a system-wide directory.
   */

  const char *filename = NULL; /* not including directory */
  char *ptr = NULL;
  unsigned int serial = 0;
  int ret;

  if (! yk_get_serial(yk, 0, 0, &serial)) {
    D (debug_file, "Failed to read serial number (serial-api-visible disabled?).");
    if (! chalresp_path)
      filename = "challenge";
    else
      filename = user->pw_name;
  } else {
    /* We have serial number */
    /* 0xffffffff == 4294967295 == 10 digits */
    size_t len = strlen(chalresp_path == NULL ? "challenge" : user->pw_name) + 1 + 10 + 1;
    if ((ptr = malloc(len)) != NULL) {
      int res = snprintf(ptr, len, "%s-%u", chalresp_path == NULL ? "challenge" : user->pw_name, serial);
      filename = ptr;
      if (res < 0 || (unsigned long)res > len) {
	/* Not enough space, strangely enough. */
	free(ptr);
	filename = NULL;
      }
    }
  }

  if (filename == NULL)
    return 0;

  ret = get_user_cfgfile_path (chalresp_path, filename, user, fn);
  if(ptr) {
    free(ptr);
  }
  return ret;
}

int
load_chalresp_state(FILE *f, CR_STATE *state, bool verbose, FILE *debug_file)
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
      D(debug_file, "Invalid salt hex input : %s", salt_hex);
      goto out;
    }

    if(verbose) {
      D(debug_file, "Challenge: %s, hashed response: %s, salt: %s, iterations: %d, slot: %d",
            challenge_hex, response_hex, salt_hex, iterations, slot);
    }

    yubikey_hex_decode(state->salt, salt_hex, sizeof(state->salt));
    state->salt_len = strlen(salt_hex) / 2;
  } else {
    rewind(f);
    r = fscanf(f, "v1:%126[0-9a-z]:%40[0-9a-z]:%d", challenge_hex, response_hex, &slot);
    if (r != 3) {
      D(debug_file, "Could not parse contents of chalresp_state file (%i)", r);
      goto out;
    }

    if (verbose) {
      D(debug_file, "Challenge: %s, expected response: %s, slot: %d", challenge_hex, response_hex, slot);
    }

    iterations = CR_DEFAULT_ITERATIONS;
  }

  state->iterations = iterations;


  if (! yubikey_hex_p(challenge_hex)) {
    D(debug_file, "Invalid challenge hex input : %s", challenge_hex);
    goto out;
  }

  if (! yubikey_hex_p(response_hex)) {
    D(debug_file, "Invalid expected response hex input : %s", response_hex);
    goto out;
  }

  if (slot != 1 && slot != 2) {
    D(debug_file, "Invalid slot input : %i", slot);
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

  fprintf(f, "v2:%s:%s:%s:%u:%d\n", challenge_hex, hashed_hex, salt_hex, iterations, state->slot);

  if (fflush(f) < 0)
    goto out;

  if (fsync(fd) < 0)
    goto out;

  return 1;
 out:
  return 0;
}
#endif /* HAVE_CR */

size_t filter_result_len(const char *filter, const char *user, char *output) {
  const char *part = NULL;
  size_t result = 0;
  do
    {
      size_t len;
      part = strstr(filter, "%u");
      if(part)
        len = part - filter;
      else
        len = strlen(filter);
      if (output)
        {
          strncpy(output, filter, len);
          output += len;
        }
      result += len;
      filter += len + 2;
      if(part)
        {
          if(output)
            {
              strncpy(output, user, strlen(user));
              output += strlen(user);
            }
          result += strlen(user);
        }
    }
  while(part);

  if(output)
    *output = '\0';
  return(result + 1);
}

char *filter_printf(const char *filter, const char *user) {
  char *result = malloc(filter_result_len(filter, user, NULL));
  filter_result_len(filter, user, result);
  return result;
}
