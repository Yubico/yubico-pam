/*
 * Copyright (c) 2011-2014 Yubico AB
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
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <ykpers.h>

#undef DEBUG_PAM
#include "util.h"

#define ACTION_ADD_HMAC_CHALRESP	"add_hmac_chalresp"
#define ACTION_MAX_LEN			1024

const char *usage =
  "Usage: ykpamcfg [options]\n"
  "\n"
  "Options :\n"
  "\n"
  "\t-1           Send challenge to slot 1. This is the default.\n"
  "\t-2           Send challenge to slot 2.\n"
  "\t-A action    What to do.\n"
  "\t-p path      Specify an output path for the challenge file.\n"
  "\t-i iters     Number of iterations to use for pbkdf2 (defaults to 10000)\n"
  "\n"
  "\t-v           Increase verbosity\n"
  "\t-V           Show version and exit\n"
  "\t-h           Show help (this text) and exit\n"
  "\n"
  "Actions :\n"
  "\n"
  "\t" ACTION_ADD_HMAC_CHALRESP "\tAdds a challenge-response state file for a connected YubiKey (default)\n"
  "\n"
  "\n"
  ;
const char *optstring = "12A:p:i:vVh";

static void
report_yk_error(void)
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

static int
parse_args(int argc, char **argv,
	   int *slot, bool *verbose,
	   char **action, char **output_dir,
     unsigned int *iterations)
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
      strncpy(*action, optarg, ACTION_MAX_LEN);
      break;
    case 'p':
      *output_dir = optarg;
      break;
    case 'i':
      {
	char *endptr;
	*iterations = strtoul(optarg, &endptr, 10);
	if(*endptr != '\0') {
	  fprintf(stderr, "iterations must be numeric, %s isn't.\n", optarg);
	  exit(1);
	}
      }
      break;
    case 'v':
      *verbose = true;
      break;
    case 'V':
      printf("%s\n", VERSION);
      exit(0);
    case 'h':
    default:
      fputs(usage, stderr);
      exit(0);
    }
  }

  return 1;
}

static int
do_add_hmac_chalresp(YK_KEY *yk, uint8_t slot, bool verbose, char *output_dir, unsigned int iterations, int *exit_code)
{
  char buf[CR_RESPONSE_SIZE + 16];
  CR_STATE state;
  int ret = 0;
  unsigned int response_len;
  char *fn;
  struct passwd *p;
  FILE *f = NULL;
  struct stat st;

  state.iterations = iterations;
  state.slot = slot;
  *exit_code = 1;

  p = getpwuid (getuid ());
  
  if (! p) {
    fprintf (stderr, "Who am I???");
    goto out;
  }

 /*
  * Create default output directory for the user
  */
  
  if (!output_dir){
      char fullpath[256];
      snprintf(fullpath, 256,"%s/.yubico",p->pw_dir);
      
      //check if directory exists     
      if (stat(fullpath,&st)!=0 ){     
	if(mkdir(fullpath, S_IRWXU)==-1){
	  fprintf(stderr, "Failed creating directory '%s' :%s\n",
		  fullpath, strerror(errno));
	}
	if(verbose){
	  printf("Directory %s created successfully.\n", fullpath);
	}
      }
      else{
	if(!S_ISDIR(st.st_mode)){
	  fprintf(stderr, "Destination %s already exist and is not a directory.\n",
		  fullpath);
	  goto out;
	  }
      }
  }

  if (! get_user_challenge_file(yk, output_dir, p, &fn)) {
    fprintf (stderr, "Failed getting chalresp state filename\n");
    goto out;
  }

  if (stat(fn, &st) == 0) {
    fprintf(stderr, "File %s already exists, refusing to overwrite.\n", fn);
    goto out;
  }

  if (generate_random(state.challenge, CR_CHALLENGE_SIZE)) {
    fprintf (stderr, "FAILED getting %i bytes of random data\n", CR_CHALLENGE_SIZE);
    goto out;
  }
  state.challenge_len = CR_CHALLENGE_SIZE;

  if (! challenge_response(yk, state.slot, state.challenge, CR_CHALLENGE_SIZE,
			   true, true, verbose,
			   buf, sizeof(buf), &response_len))
    goto out;

  /* Make sure we get different responses for different challenges
     There is a firmware bug in YubiKey 2.2 that makes it issue same
     response for all challenges unless HMAC_LT64 is set. */
  {
    char buf2[CR_RESPONSE_SIZE + 16];
    char challenge[CR_CHALLENGE_SIZE];

    if (generate_random(challenge, CR_CHALLENGE_SIZE)) {
      fprintf (stderr, "FAILED getting %i bytes of random data\n", CR_CHALLENGE_SIZE);
      goto out;
    }
    if (! challenge_response(yk, state.slot, challenge, CR_CHALLENGE_SIZE,
          true, true, verbose,
          buf2, sizeof(buf2), &response_len))
      goto out;

    if (memcmp(buf, buf2, response_len) == 0) {
      fprintf (stderr, "FAILED YubiKey is outputting the same response for different challenges."
          "Make sure you configure the key with the option HMAC_LT64.\n");
      goto out;
    }
  }

  if (response_len > sizeof (state.response)) {
    fprintf (stderr, "Got too long response ??? (%u/%lu)", response_len, (unsigned long) sizeof(state.response));
    goto out;
  }
  memcpy (state.response, buf, response_len);
  state.response_len = response_len;

  umask(077);

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
  char action[ACTION_MAX_LEN];
  char *ptr = action;
  char *output_dir = NULL;
  int slot = 1;
  unsigned int iterations = CR_DEFAULT_ITERATIONS;

  ykp_errno = 0;
  yk_errno = 0;

  strcpy (action, ACTION_ADD_HMAC_CHALRESP);

  if (! parse_args(argc, argv,
		   &slot, &verbose,
		   &ptr, &output_dir,
       &iterations))
    goto err;

  exit_code = 1;

  if (! strncmp(action, ACTION_ADD_HMAC_CHALRESP, ACTION_MAX_LEN)) {
    /*
     * Set up challenge-response login authentication
     */
    if (! init_yubikey (&yk))
      goto err;

    if (! check_firmware_version(yk, verbose, false))
      goto err;    

    if (! do_add_hmac_chalresp (yk, slot, verbose, output_dir, iterations, &exit_code))
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
