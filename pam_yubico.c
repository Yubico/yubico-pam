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

PAM_EXTERN int
pam_sm_authenticate (pam_handle_t * pamh,
		     int flags, int argc, const char** argv)
{
  int retval, rc;
  const char *user = NULL;
  const char *password = NULL;
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

      retval = pam_set_item(pamh, PAM_AUTHTOK, password);
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

  rc = yubikey_client_request (ykc, password);
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
