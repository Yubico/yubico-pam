/*
 * Copyright (c) 2011 Yubico AB.
 * All rights reserved.
 *
 * Author : Fredrik Thulin <fredrik@yubico.com>
 *
 * Based on ykchalresp.c from yubikey-personalization.
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
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#include <string.h>
#include <errno.h>

#include <ykpers.h>

#undef DEBUG_PAM
#include "util.h"

#define ACTION_ADD_HMAC_CHALRESP	"add_hmac_chalresp"

const char *usage =
  "Usage: ykpamcfg [options]\n"
  "\n"
  "Options :\n"
  "\n"
  "\t-1           Send challenge to slot 1. This is the default.\n"
  "\t-2           Send challenge to slot 2.\n"
  "\t-A action    What to do.\n"
  "\n"
  "\t-v           verbose\n"
  "\t-h           help (this text)\n"
  "\n"
  "Actions :\n"
  "\n"
  "\t" ACTION_ADD_HMAC_CHALRESP "\tAdds a challenge-response state file for a connected YubiKey (default)\n"
  "\n"
  "\n"
  ;
const char *optstring = "12A:vh";

static void
report_yk_error()
{
  if (ykp_errno)
    fprintf(stderr, "Yubikey personalization error: %s\n",
	    ykp_strerror(ykp_errno));
  if (yk_errno) {
    if (yk_errno == YK_EUSBERR) {
      fprintf(stderr, "USB error: %s\n",
	      yk_usb_strerror());
    } else {
      fprintf(stderr, "Yubikey core error: %s\n",
	      yk_strerror(yk_errno));
    }
  }
}

int
parse_args(int argc, char **argv,
	   int *slot, bool *verbose,
	   char **action,
	   int *exit_code)
{
  int c;

  while((c = getopt(argc, argv, optstring)) != -1) {
    switch (c) {
    case '1':
      *slot = 1;
      break;
    case '2':
      *slot = 2;
      break;
    case 'A':
      *action = optarg;
      break;
    case 'v':
      *verbose = true;
      break;
    case 'h':
    default:
      fputs(usage, stderr);
    *exit_code = 0;
    return 0;
    }
  }

  return 1;
}

int
do_add_hmac_chalresp(YK_KEY *yk, uint8_t slot, bool verbose, char *output_dir, int *exit_code)
{
  char buf[CR_RESPONSE_SIZE + 16];
  CR_STATE state;
  unsigned int flags = 0;
  int ret = 0;
  unsigned int response_len;
  char *fn;
  struct passwd *p;
  FILE *f = NULL;

  state.slot = slot;
  flags |= YK_FLAG_MAYBLOCK;
  *exit_code = 1;

  p = getpwuid (getuid ());

  if (! p) {
    fprintf (stderr, "Who am I???");
    goto out;
  }

  if (! get_user_challenge_file(yk, output_dir, p->pw_name, &fn)) {
    fprintf (stderr, "Failed getting chalresp state filename\n");
    goto out;
  }

  if (generate_random(state.challenge, CR_CHALLENGE_SIZE)) {
    fprintf (stderr, "FAILED getting %i bytes of random data\n", CR_CHALLENGE_SIZE);
    goto out;
  }
  state.challenge_len = CR_CHALLENGE_SIZE;

  if (! challenge_response(yk, state.slot, state.challenge, CR_CHALLENGE_SIZE,
			   true, flags, verbose,
			   buf, sizeof(buf), &response_len))
    goto out;

  if (response_len > sizeof (state.response)) {
    fprintf (stderr, "Got too long response ??? (%i/%i)", response_len, sizeof(state.response));
    goto out;
  }
  memcpy (state.response, buf, response_len);
  state.response_len = response_len;

  f = fopen (fn, "w");
  if (! f) {
    fprintf (stderr, "Failed opening '%s' for writing : %s\n", fn, strerror (errno));
    goto out;
  }

  if (! write_chalresp_state (f, &state))
    goto out;

  printf ("Stored initial challenge and expected response in '%s'.\n", fn);

  *exit_code = 0;
  ret = 1;

 out:
  if (f)
    fclose (f);

  return ret;
}

int
main(int argc, char **argv)
{
  YK_KEY *yk = NULL;
  bool error = true;
  int exit_code = 0;

  /* Options */
  bool verbose = false;
  char *action = ACTION_ADD_HMAC_CHALRESP;
  int slot = 1;

  ykp_errno = 0;
  yk_errno = 0;

  if (! parse_args(argc, argv,
		   &slot, &verbose,
		   &action,
		   &exit_code))
    goto err;

  exit_code = 1;

  if (! strcmp(action, ACTION_ADD_HMAC_CHALRESP)) {
    /*
     * Set up challenge-response login authentication
     */
    if (! init_yubikey (&yk))
      goto err;

    if (! check_firmware_version(yk, verbose, false))
      goto err;

    if (! do_add_hmac_chalresp (yk, slot, verbose, NULL, &exit_code))
      goto err;
  } else {
    fprintf (stderr, "Unknown action '%s'\n", action);
    goto err;
  }

  exit_code = 0;
  error = false;

 err:
  if (error || exit_code != 0) {
    report_yk_error ();
  }

  if (yk && !yk_close_key (yk)) {
    report_yk_error ();
    exit_code = 2;
  }

  if (!yk_release ()) {
    report_yk_error ();
    exit_code = 2;
  }

  exit (exit_code);
}
