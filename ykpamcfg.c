/*
 * Copyright (c) 2011-2012 Yubico AB
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
#include <sys/stat.h>
#include <sys/types.h>
#include <signal.h>
#include <termios.h>

#include <ykpers.h>

#undef DEBUG_PAM
#include "util.h"

#define ACTION_ADD_HMAC_CHALRESP	"add_hmac_chalresp"
#define ACTION_ADD_SAVED_PASSWORD	"add_saved_password"

const char *usage =
  "Usage: ykpamcfg [options]\n"
  "\n"
  "Options :\n"
  "\n"
  "\t-1           Send challenge to slot 1. This is the default.\n"
  "\t-2           Send challenge to slot 2.\n"
  "\t-A action    What to do.\n"
  "\t-p path      Specify an output path for the challenge file.\n"
  "\n"
  "\t-v           verbose\n"
  "\t-h           help (this text)\n"
  "\n"
  "Actions :\n"
  "\n"
  "\t" ACTION_ADD_HMAC_CHALRESP "\tAdds a challenge-response state file for a connected YubiKey (default)\n"
  "\t" ACTION_ADD_SAVED_PASSWORD "\tAdds a file containig a challenge and AUTHTOKEN encrypted with the response\n"
  "\n"
  "\n"
  ;
const char *optstring = "12A:p:vh";

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

static struct termios save_ts;

static void set_echo(int on);

static void
restore_echo(int sig)
{
  set_echo(1);
  raise(sig);
}

static void
set_echo(int on)
{
  struct termios ts;

  if (on) {
    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &save_ts) == -1) {
      perror("tcsetattr");
    }
    signal(SIGINT, SIG_DFL);
  } else {
    if (tcgetattr(STDIN_FILENO, &ts) == -1) {
      perror("tcgetattr");
      return;
    }
    save_ts = ts;
    signal(SIGINT, restore_echo);
    ts.c_lflag &= ~ECHO;
    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &ts) == -1) {
      perror("tcsetattr");
    }
  }
}

int
parse_args(int argc, char **argv,
	   int *slot, bool *verbose,
	   char **action, char **output_dir,
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
    case 'p':
      *output_dir = optarg;
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

static int
save_response(CR_STATE *state, char *buf, unsigned int response_len)
{
  if (response_len > sizeof (state->response)) {
    fprintf (stderr, "Got too long response ??? (%u/%lu)",
             response_len, (unsigned long) sizeof(state->response));
    return 0;
  }
  memcpy (state->response, buf, response_len);
  state->response_len = response_len;
  return 1;
}

static int
save_encrypted_string(CR_STATE *state, char *buf, unsigned int response_len)
{
  char str1[CR_RESPONSE_SIZE+2];
  char str2[CR_RESPONSE_SIZE+2];
  char *p;
  int i, is_tty;

  if (response_len > sizeof (state->response)) {
    fprintf (stderr, "Got too long response ??? (%u/%lu)",
             response_len, (unsigned long) sizeof(state->response));
    return 0;
  }
  memset(str1,0,sizeof(str1));
  memset(str2,0,sizeof(str2));
  is_tty = isatty(STDIN_FILENO);
  if (is_tty) {
    set_echo(0);
    printf("Enter secret (up to %i chars): ", response_len); fflush(stdout);
  }
  do {
    if (fgets(str1, response_len, stdin) == NULL) return 0;
  } while (str1[0] == '\n');
  if (is_tty) {
    printf("\nReenter secret to check      : "); fflush(stdout);
    do {
      if (fgets(str2, response_len, stdin) == NULL) return 0;
    } while (str2[0] == '\n');
    printf("\n");
    set_echo(1);
    if (strcmp(str1, str2)) {
      fprintf (stderr, "Inputs do not match\n");
      return 0;
    }
  }
  if (*(p=str1+strlen(str1)-1) == '\n') *p = '\0';
  if (strlen(str1) > response_len) {
    fprintf (stderr, "Input too long, only %i permitted\n", response_len);
    return 0;
  }
  /* Because we limit the size of data by the size of the key, there is no   */
  /* need in fancy encryption algorithms. We use One Time Pad (literally).   */
  for (i = 0; i < response_len; i++)
    state->response[i] = buf[i] ^ str1[i];
  state->response_len = response_len;
  return 1;
}

int
update_userfile(YK_KEY *yk, uint8_t slot, bool verbose, char *output_dir,
                int *exit_code, char *suffix,
                int (*update_state)(CR_STATE *state, char *buf,
                                unsigned int response_len))
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

 /*
  * Create default output directory for the user
  */
  
  if (!output_dir){
      const char *pathname = p->pw_dir; 
      char fullpath[256];
      snprintf(fullpath, 256,"%s/.yubico",p->pw_dir);
      struct stat st;
      
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

  if (! get_user_challenge_file(yk, output_dir, p->pw_name, suffix, &fn)) {
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

  /* Make sure we get different responses for different challenges
     There is a firmware bug in YubiKey 2.2 that makes it issue same
     response for all challenges unless HMAC_LT64 is set. */
  {
    char buf2[CR_RESPONSE_SIZE + 16];
    char challenge[CR_CHALLENGE_SIZE];
    CR_STATE state2;

    if (generate_random(challenge, CR_CHALLENGE_SIZE)) {
      fprintf (stderr, "FAILED getting %i bytes of random data\n", CR_CHALLENGE_SIZE);
      goto out;
    }
    if (! challenge_response(yk, state.slot, challenge, CR_CHALLENGE_SIZE,
          true, flags, verbose,
          buf2, sizeof(buf2), &response_len))
      goto out;

    if (memcmp(buf, buf2, response_len) == 0) {
      fprintf (stderr, "FAILED YubiKey is outputting the same response for different challenges."
          "Make sure you configure the key with the option HMAC_LT64.\n");
      goto out;
    }
  }

  if (! (*update_state)(&state, buf, response_len)) {
    fprintf (stderr, "No updated state, not writing\n");
    goto out;
  }

  f = fopen (fn, "w");
  if (! f) {
    fprintf (stderr, "Failed opening '%s' for writing : %s\n", fn, strerror (errno));
    goto out;
  }

  if (! write_chalresp_state (f, &state))
    goto out;

  printf ("Stored initial state in '%s'.\n", fn);

  *exit_code = 0;
  ret = 1;

 out:
  if (f)
    fclose (f);

  return ret;
}

int
do_add_hmac_chalresp(YK_KEY *yk, uint8_t slot, bool verbose, char *output_dir, int *exit_code)
{
  return update_userfile(yk, slot, verbose, output_dir, exit_code,
                         "", save_response);
}

int
do_add_saved_password(YK_KEY *yk, uint8_t slot, bool verbose, char *output_dir, int *exit_code)
{
  return update_userfile(yk, slot, verbose, output_dir, exit_code,
                         "-pwd", save_encrypted_string);
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
  char *output_dir = NULL;
  int slot = 1;

  ykp_errno = 0;
  yk_errno = 0;

  if (! parse_args(argc, argv,
		   &slot, &verbose,
		   &action, &output_dir,
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

    if (! do_add_hmac_chalresp (yk, slot, verbose, output_dir, &exit_code))
      goto err;
  } else if (! strcmp(action, ACTION_ADD_SAVED_PASSWORD)) {
    /*
     * Set up file with encrypted saved password
     */
    if (! init_yubikey (&yk))
      goto err;

    if (! check_firmware_version(yk, verbose, false))
      goto err;    

    if (! do_add_saved_password (yk, slot, verbose, output_dir, &exit_code))
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
