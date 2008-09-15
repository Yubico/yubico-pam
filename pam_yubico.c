/*
 * Copyright 2007, 2008 Simon Josefsson.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, and the entire permission notice in its entirety,
 *    including the disclaimer of warranties.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 *
 * ALTERNATIVELY, this product may be distributed under the terms of
 * the GNU Public License, in which case the provisions of the GPL are
 * required INSTEAD OF the above restrictions.  (This clause is
 * necessary due to a potential bad interaction between the GPL and
 * the restrictions contained in a BSD-style copyright.)
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ctype.h>

/* Libtool defines PIC for shared objects */
#ifndef PIC
#define PAM_STATIC
#endif

/* These #defines must be present according to PAM documentation. */
#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_SESSION
#define PAM_SM_PASSWORD

#ifdef HAVE_SECURITY_PAM_APPL_H
#include <security/pam_appl.h>
#endif
#ifdef HAVE_SECURITY_PAM_MODULES_H
#include <security/pam_modules.h>
#endif

#if defined(DEBUG_PAM) && defined(HAVE_SECURITY__PAM_MACROS_H)
#define DEBUG
#include <security/_pam_macros.h>
#else
#define D(x)			/* nothing */
#endif

#include <libykclient.h>

#ifndef PAM_EXTERN
#ifdef PAM_STATIC
#define PAM_EXTERN static
#else
#define PAM_EXTERN extern
#endif
#endif

#include <sys/types.h>
#include <pwd.h>

#define TOKEN_LEN 44
#define TOKEN_ID_LEN 12

/*
 * This function will look for users name with valid user token id. It
 * will returns 0 for failure and 1 for success.
 *
 * File format is as follows:
 * <user-name>:<token_id>:<token_id>
 * <user-name>:<token_id>
 *
 */
static int
check_user_token (const char *authfile,
		  const char *username, const char *usertoken)
{
  static char buf[1024];
  char *s_user, *s_token;
  int retval = 0;
  FILE *opwfile;

  opwfile = fopen (authfile, "r");
  if (opwfile == NULL)
    {
      D ((" %s file does not exists.", authfile));
      return retval;
    }

  while (fgets (buf, 1024, opwfile))
    {
      if (!strncmp (buf, username, strlen (username)))
	{
	  buf[strlen (buf) - 1] = '\0';
	  D (("Got user record :: %s", buf));
	  s_user = strtok (buf, ":");
	  s_token = strtok (NULL, ":");
	  while (s_token != NULL)
	    {
	      if (!strncmp (usertoken, s_token, strlen (usertoken)))
		{
		  D (("Token Found :: %s", s_token));
		  retval = 1;
		  break;
		}
	      s_token = strtok (NULL, ":");
	    }
	  break;
	}
    }
  fclose (opwfile);

  return retval;
}

/*
 * This F'n will get the configuration file name either from argument
 * list or from user home directory
 */
static int
validate_user_token (const char *authfile,
		     const char *username, const char *usertoken)
{
  int retval = 0;

  if (NULL != authfile)
    {
      /* Administrator had configured the file and specified is name
         as an argument for this module.
       */
      retval = check_user_token (authfile, username, usertoken);
    }
  else
    {
      /* Getting file from user home directory
         ..... i.e. ~/.yubico/authorized_yubikeys
       */
      struct passwd *p;
      char *home_dir = NULL;

      p = getpwnam (username);
      if (p != NULL)
	{
	  home_dir = (char *) malloc (strlen (p->pw_dir) + 29);
	  if (NULL != home_dir)
	    {
	      strcpy (home_dir, p->pw_dir);
	      strcat (home_dir, "/.yubico/authorized_yubikeys");
	    }
	}

      retval = check_user_token (home_dir, username, usertoken);
      if (NULL != home_dir)
	{
	  free (home_dir);
	}
    }

  return retval;
}

PAM_EXTERN int
pam_sm_authenticate (pam_handle_t * pamh,
		     int flags, int argc, const char **argv)
{
  int retval, rc;
  const char *user = NULL;
  const char *password = NULL;
  char *auth_file = NULL;
  const char *token_otp[TOKEN_LEN + 1] = { 0 };
  const char *token_id[TOKEN_ID_LEN + 1] = { 0 };
  char *token_otp_with_password = NULL;
  char *token_password = NULL;
  char *url_template = NULL;
  int password_len = 0;
  int valid_token = 0;
  int i;
  struct pam_conv *conv;
  struct pam_message *pmsg[1], msg[1];
  struct pam_response *resp;
  int nargs = 1;
  int id = -1;
  int debug = 0;
  int alwaysok = 0;
  yubikey_client_t ykc;

  for (i = 0; i < argc; i++)
    {
      if (strncmp (argv[i], "id=", 3) == 0)
	sscanf (argv[i], "id=%d", &id);
      if (strcmp (argv[i], "debug") == 0)
	debug = 1;
      if (strcmp (argv[i], "alwaysok") == 0)
	alwaysok = 1;
      if (strncmp (argv[i], "authfile=", 9) == 0)
	auth_file = (char *) argv[i] + 9;
      if (strncmp (argv[i], "url=", 4) == 0)
	url_template = (char *) argv[i] + 4;
    }

  if (debug)
    {
      D (("called."));
      D (("flags %d argc %d", flags, argc));
      for (i = 0; i < argc; i++)
	D (("argv[%d]=%s", i, argv[i]));
      D (("id=%d", id));
      D (("debug=%d", debug));
      D (("alwaysok=%d", alwaysok));
      D (("authfile=%s", auth_file));
    }

  retval = pam_get_user (pamh, &user, NULL);
  if (retval != PAM_SUCCESS)
    {
      if (debug)
	D (("get user returned error: %s", pam_strerror (pamh, retval)));
      goto done;
    }
  if (debug)
    D (("get user returned: %s", user));

  retval = pam_get_item (pamh, PAM_AUTHTOK, (const void **) &password);
  if (retval != PAM_SUCCESS)
    {
      if (debug)
	D (("get password returned error: %s", pam_strerror (pamh, retval)));
      goto done;
    }
  if (debug)
    D (("get password returned: %s", password));

  if (password == NULL)
    {
      retval = pam_get_item (pamh, PAM_CONV, (const void **) &conv);
      if (retval != PAM_SUCCESS)
	{
	  if (debug)
	    D (("get conv returned error: %s", pam_strerror (pamh, retval)));
	  goto done;
	}

      pmsg[0] = &msg[0];
      asprintf ((char **) &msg[0].msg, "Yubikey for `%s': ", user);
      msg[0].msg_style = PAM_PROMPT_ECHO_OFF;
      resp = NULL;

      retval = conv->conv (nargs, (const struct pam_message **) pmsg,
			   &resp, conv->appdata_ptr);

      free ((char *) msg[0].msg);

      if (retval != PAM_SUCCESS)
	{
	  if (debug)
	    D (("conv returned error: %s", pam_strerror (pamh, retval)));
	  goto done;
	}

      if (debug)
	D (("conv returned: %s", resp->resp));

      password = resp->resp;

      retval = pam_set_item (pamh, PAM_AUTHTOK, password);
      if (retval != PAM_SUCCESS)
	{
	  if (debug)
	    D (("set_item returned error: %s", pam_strerror (pamh, retval)));
	  goto done;
	}
    }

  ykc = yubikey_client_init ();
  if (!ykc)
    {
      if (debug)
	D (("yubikey_client_init() failed"));
      retval = PAM_AUTHINFO_UNAVAIL;
      goto done;
    }

  yubikey_client_set_info (ykc, id, 0, NULL);

  if (url_template)
    yubikey_client_set_url_template (ykc, url_template);

  /* user will enter there system paasword followed by generated OTP */
  token_otp_with_password = (char *) password;
  password_len = strlen (token_otp_with_password);

  /* Getting Token value and SSH password */
  strncpy ((char *) token_otp,
	   token_otp_with_password + (password_len - TOKEN_LEN), TOKEN_LEN);
  token_password = malloc ((password_len - TOKEN_LEN) + 1);

  if (token_password != NULL)
    {
      strncpy (token_password, token_otp_with_password,
	       (password_len - TOKEN_LEN));
      token_password[(password_len - TOKEN_LEN)] = 0;
      password = token_password;
    }
  strncpy ((char *) token_id,
	   token_otp_with_password + (password_len - TOKEN_LEN),
	   TOKEN_ID_LEN);

  if (debug)
    {
      D ((" Token is : %s and password is %s ", token_otp, password));
      D ((" Token ID is: %s ", token_id));
    }

  /* validate the user with supplied token id */
  valid_token =
    validate_user_token (auth_file, (const char *) user,
			 (const char *) token_id);

  if (password != NULL)
    {
      retval = pam_set_item (pamh, PAM_AUTHTOK, password);
      if (retval != PAM_SUCCESS)
	{
	  if (debug)
	    D (("set_item returned error: %s", pam_strerror (pamh, retval)));
	  goto done;
	}
    }

  if (valid_token == 0)
    {
      if (debug)
	D (("Invalid Token for user "));
      retval = PAM_SERVICE_ERR;
      goto done;
    }

  rc = yubikey_client_request (ykc, (const char *) token_otp);

  if (token_password != NULL)
    free (token_password);

  if (debug)
    D (("libyubikey-client return value (%d): %s", rc,
	yubikey_client_strerror (rc)));

  if (rc != YUBIKEY_CLIENT_OK)
    {
      retval = PAM_SERVICE_ERR;
      goto done;
    }

  yubikey_client_done (&ykc);

  retval = PAM_SUCCESS;

done:
  if (alwaysok && retval != PAM_SUCCESS)
    {
      if (debug)
	D (("alwaysok needed (otherwise return with %d)", retval));
      retval = PAM_SUCCESS;
    }
  pam_set_data (pamh, "yubico_setcred_return", (void *) retval, NULL);
  if (debug)
    D (("done. [%s]", pam_strerror (pamh, retval)));

  return retval;
}

PAM_EXTERN int
pam_sm_setcred (pam_handle_t * pamh, int flags, int argc, const char **argv)
{
  int retval;
  int auth_retval;

  D (("called."));

  /* TODO: ? */

  retval = pam_get_data (pamh, "yubico_setcred_return",
			 (const void **) &auth_retval);
  if (retval != PAM_SUCCESS)
    return PAM_CRED_UNAVAIL;

  switch (auth_retval)
    {
    case PAM_SUCCESS:
      retval = PAM_SUCCESS;
      break;

    case PAM_USER_UNKNOWN:
      retval = PAM_USER_UNKNOWN;
      break;

    case PAM_AUTH_ERR:
    default:
      retval = PAM_CRED_ERR;
      break;
    }

  D (("done. [%s]", pam_strerror (pamh, retval)));

  return retval;
}

PAM_EXTERN int
pam_sm_acct_mgmt (pam_handle_t * pamh, int flags, int argc, const char **argv)
{
  int retval;

  D (("called."));

  /* TODO: ? */
  retval = PAM_SUCCESS;

  D (("done. [%s]", pam_strerror (pamh, retval)));

  return retval;
}

PAM_EXTERN int
pam_sm_open_session (pam_handle_t * pamh,
		     int flags, int argc, const char **argv)
{
  int retval;

  D (("called."));

  /* TODO: ? */
  retval = PAM_SUCCESS;

  D (("done. [%s]", pam_strerror (pamh, retval)));

  return retval;
}

PAM_EXTERN int
pam_sm_close_session (pam_handle_t * pamh,
		      int flags, int argc, const char **argv)
{
  int retval;

  D (("called."));

  /* TODO: ? */
  retval = PAM_SUCCESS;

  D (("done. [%s]", pam_strerror (pamh, retval)));

  return retval;
}

PAM_EXTERN int
pam_sm_chauthtok (pam_handle_t * pamh, int flags, int argc, const char **argv)
{
  int retval;

  D (("called."));

  /* TODO: ? */
  retval = PAM_SUCCESS;

  D (("done. [%s]", pam_strerror (pamh, retval)));

  return retval;
}

#ifdef PAM_STATIC

struct pam_module _pam_yubico_modstruct = {
  "pam_yubico",
  pam_sm_authenticate,
  pam_sm_setcred,
  pam_sm_acct_mgmt,
  pam_sm_open_session,
  pam_sm_close_session,
  pam_sm_chauthtok
};

#endif
