/* Written by Simon Josefsson <simon@yubico.com>.
 * Copyright (c) 2006, 2007, 2008, 2009 Yubico AB
 * All rights reserved.
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
# endif
#endif

#include <libykclient.h>

#ifdef HAVE_LIBLDAP
#include <ldap.h>
#define PORT_NUMBER  LDAP_PORT
#endif


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

/*
 * This function will look in ldap id the token correspond to the
 * requested user. It will returns 0 for failure and 1 for success.
 *
 * For the moment ldaps is not supported. ldap serve can be on a
 * remote host.
 *
 * You need the following parameters in you pam config:
 * ldapsever=
 * ldapdn=
 * user_attr=
 * yubi_attr=
 *
 */
static int
validate_user_token_ldap (const char *ldapserver,
			  const char *ldapdn, const char *user_attr,
			  const char *yubi_attr, const char *user,
			  const char *token_id)
{

  int retval = 0;
#ifdef HAVE_LIBLDAP
  LDAP *ld;
  LDAPMessage *result, *e;
  BerElement *ber;
  char *a;
  char **vals;
  int i, rc;
  /* FIXME: dont' use hard coded buffers here. */
  char find[256] = "";
  char sr[128] = "(";
  char sep[2] = ",";
  char eq[2] = "=";
  char sren[4] = "=*)";



  strcat (find, user_attr);
  strcat (find, eq);
  strcat (find, user);
  strcat (find, sep);
  strcat (find, ldapdn);

  strcat (sr, yubi_attr);
  strcat (sr, sren);

  /* Get a handle to an LDAP connection. */
  if ((ld = ldap_init (ldapserver, PORT_NUMBER)) == NULL)
    {
      D (("ldap_init"));
      return (0);
    }

  /* Bind anonymously to the LDAP server. */
  rc = ldap_simple_bind_s (ld, NULL, NULL);
  if (rc != LDAP_SUCCESS)
    {
      D (("ldap_simple_bind_s: %s", ldap_err2string (rc)));
      return (0);
    }

  /* Search for the entry. */
  D (("ldap-dn: %s", find));
  D (("ldap-filter: %s", sr));

  if ((rc = ldap_search_ext_s (ld, find, LDAP_SCOPE_BASE,
			       sr, NULL, 0, NULL, NULL, LDAP_NO_LIMIT,
			       LDAP_NO_LIMIT, &result)) != LDAP_SUCCESS)
    {
      D (("ldap_search_ext_s: %s", ldap_err2string (rc)));

      return (0);
    }

  e = ldap_first_entry (ld, result);
  if (e != NULL)
    {

      /* Iterate through each attribute in the entry. */
      for (a = ldap_first_attribute (ld, e, &ber);
	   a != NULL; a = ldap_next_attribute (ld, e, ber))
	{
	  if ((vals = ldap_get_values (ld, e, a)) != NULL)
	    {
	      for (i = 0; vals[i] != NULL; i++)
		{
		  if (!strncmp (token_id, vals[i], strlen (token_id)))
		    {
		      D (("Token Found :: %s", vals[i]));
		      retval = 1;
		    }
		}
	      ldap_value_free (vals);
	    }
	  ldap_memfree (a);
	}
      if (ber != NULL)
	{
	  ber_free (ber, 0);
	}

    }

  ldap_msgfree (result);
  ldap_unbind (ld);
#else
  D (("Trying to use LDAP, but this function is not compiled in pam_yubico!!"));
  D (("Install libldap-dev and then recompile pam_yubico."));
#endif
  return retval;
}

struct cfg
{
  int client_id;
  int debug;
  int alwaysok;
  int try_first_pass;
  int use_first_pass;
  char *auth_file;
  char *url;
  char *ldapserver;
  char *ldapdn;
  char *user_attr;
  char *yubi_attr;
};

static void
parse_cfg (int flags, int argc, const char **argv, struct cfg *cfg)
{
  int i;

  cfg->client_id = -1;
  cfg->debug = 0;
  cfg->alwaysok = 0;
  cfg->try_first_pass = 0;
  cfg->use_first_pass = 0;
  cfg->auth_file = NULL;
  cfg->url = NULL;
  cfg->ldapserver = NULL;
  cfg->ldapdn = NULL;
  cfg->user_attr = NULL;
  cfg->yubi_attr = NULL;

  for (i = 0; i < argc; i++)
    {
      if (strncmp (argv[i], "id=", 3) == 0)
	sscanf (argv[i], "id=%d", &cfg->client_id);
      if (strcmp (argv[i], "debug") == 0)
	cfg->debug = 1;
      if (strcmp (argv[i], "alwaysok") == 0)
	cfg->alwaysok = 1;
      if (strcmp (argv[i], "try_first_pass") == 0)
	cfg->try_first_pass = 1;
      if (strcmp (argv[i], "use_first_pass") == 0)
	cfg->use_first_pass = 1;
      if (strncmp (argv[i], "authfile=", 9) == 0)
	cfg->auth_file = (char *) argv[i] + 9;
      if (strncmp (argv[i], "url=", 4) == 0)
	cfg->url = (char *) argv[i] + 4;
      if (strncmp (argv[i], "ldapserver=", 11) == 0)
	cfg->ldapserver = (char *) argv[i] + 11;
      if (strncmp (argv[i], "ldapdn=", 7) == 0)
	cfg->ldapdn = (char *) argv[i] + 7;
      if (strncmp (argv[i], "user_attr=", 10) == 0)
	cfg->user_attr = (char *) argv[i] + 10;
      if (strncmp (argv[i], "yubi_attr=", 10) == 0)
	cfg->yubi_attr = (char *) argv[i] + 10;
    }

  if (cfg->debug)
    {
      D (("called."));
      D (("flags %d argc %d", flags, argc));
      for (i = 0; i < argc; i++)
	D (("argv[%d]=%s", i, argv[i]));
      D (("id=%d", cfg->client_id));
      D (("debug=%d", cfg->debug));
      D (("alwaysok=%d", cfg->alwaysok));
      D (("try_first_pass=%d", cfg->try_first_pass));
      D (("use_first_pass=%d", cfg->use_first_pass));
      D (("authfile=%s", cfg->auth_file ? cfg->auth_file : "(null)"));
      D (("ldapserver=%s", cfg->ldapserver ? cfg->ldapserver : "(null)"));
      D (("ldapdn=%s", cfg->ldapdn ? cfg->ldapdn : "(null)"));
      D (("user_attr=%s", cfg->user_attr ? cfg->user_attr : "(null)"));
      D (("yubi_attr=%s", cfg->yubi_attr ? cfg->yubi_attr : "(null)"));
    }
}

#define DBG(x) if (cfg.debug) { D(x); }

PAM_EXTERN int
pam_sm_authenticate (pam_handle_t * pamh,
		     int flags, int argc, const char **argv)
{
  int retval, rc;
  const char *user = NULL;
  const char *password = NULL;
  const char *token_otp[TOKEN_LEN + 1] = { 0 };
  const char *token_id[TOKEN_ID_LEN + 1] = { 0 };
  char *token_otp_with_password = NULL;
  char *token_password = NULL;
  int password_len = 0;
  int valid_token = 0;
  int i;
  struct pam_conv *conv;
  struct pam_message *pmsg[1], msg[1];
  struct pam_response *resp;
  int nargs = 1;
  yubikey_client_t ykc = NULL;
  struct cfg cfg;

  parse_cfg (flags, argc, argv, &cfg);

  retval = pam_get_user (pamh, &user, NULL);
  if (retval != PAM_SUCCESS)
    {
      DBG (("get user returned error: %s", pam_strerror (pamh, retval)));
      goto done;
    }
  DBG (("get user returned: %s", user));

  if (cfg.try_first_pass || cfg.use_first_pass)
    {
      retval = pam_get_item (pamh, PAM_AUTHTOK, (const void **) &password);
      if (retval != PAM_SUCCESS)
	{
	  DBG (("get password returned error: %s",
	      pam_strerror (pamh, retval)));
	  goto done;
	}
      DBG (("get password returned: %s", password));
    }

  if (cfg.use_first_pass && password == NULL)
    {
      DBG (("use_first_pass set and no password, giving up"));
      retval = PAM_AUTH_ERR;
      goto done;
    }

  ykc = yubikey_client_init ();
  if (!ykc)
    {
      DBG (("yubikey_client_init() failed"));
      retval = PAM_AUTHINFO_UNAVAIL;
      goto done;
    }

  yubikey_client_set_info (ykc, cfg.client_id, 0, NULL);
  if (cfg.url)
    yubikey_client_set_url_template (ykc, cfg.url);

  if (password == NULL)
    {
      retval = pam_get_item (pamh, PAM_CONV, (const void **) &conv);
      if (retval != PAM_SUCCESS)
	{
	  DBG (("get conv returned error: %s", pam_strerror (pamh, retval)));
	  goto done;
	}

      pmsg[0] = &msg[0];
      {
	const char *query_template = "Yubikey for `%s': ";
	size_t len = strlen (query_template) + strlen (user);
	size_t wrote;

	msg[0].msg = malloc (len);
	if (!msg[0].msg)
	  {
	    retval = PAM_BUF_ERR;
	    goto done;
	  }

	wrote = snprintf ((char *) msg[0].msg, len, query_template, user);
	if (wrote < 0 || wrote >= len)
	  {
	    retval = PAM_BUF_ERR;
	    goto done;
	  }
      }
      msg[0].msg_style = PAM_PROMPT_ECHO_OFF;
      resp = NULL;

      retval = conv->conv (nargs, (const struct pam_message **) pmsg,
			   &resp, conv->appdata_ptr);

      free ((char *) msg[0].msg);

      if (retval != PAM_SUCCESS)
	{
	  DBG (("conv returned error: %s", pam_strerror (pamh, retval)));
	  goto done;
	}

      DBG (("conv returned: %s", resp->resp));

      password = resp->resp;

      retval = pam_set_item (pamh, PAM_AUTHTOK, password);
      if (retval != PAM_SUCCESS)
	{
	  DBG (("set_item returned error: %s", pam_strerror (pamh, retval)));
	  goto done;
	}
    }

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

  DBG ((" Token is : %s and password is %s ", token_otp, password));
  DBG ((" Token ID is: %s ", token_id));

  /* validate the user with supplied token id */
  if (cfg.ldapserver != NULL)
    {
      valid_token = validate_user_token_ldap ((const char *) cfg.ldapserver,
					      (const char *) cfg.ldapdn,
					      (const char *) cfg.user_attr,
					      (const char *) cfg.yubi_attr,
					      (const char *) user,
					      (const char *) token_id);
    }
  else
    {
      valid_token = validate_user_token (cfg.auth_file, (const char *) user,
					 (const char *) token_id);
    }
  if (password != NULL)
    {
      retval = pam_set_item (pamh, PAM_AUTHTOK, password);
      if (retval != PAM_SUCCESS)
	{
	  DBG (("set_item returned error: %s", pam_strerror (pamh, retval)));
	  goto done;
	}
    }

  if (valid_token == 0)
    {
      DBG (("Invalid Token for user "));
      retval = PAM_SERVICE_ERR;
      goto done;
    }

  rc = yubikey_client_request (ykc, (const char *) token_otp);

  DBG (("libyubikey-client return value (%d): %s", rc,
	yubikey_client_strerror (rc)));

  if (token_password != NULL)
    free (token_password);

  if (rc != YUBIKEY_CLIENT_OK)
    {
      retval = PAM_SERVICE_ERR;
      goto done;
    }

  retval = PAM_SUCCESS;

done:
  if (ykc)
    yubikey_client_done (&ykc);
  if (cfg.alwaysok && retval != PAM_SUCCESS)
    {
      DBG (("alwaysok needed (otherwise return with %d)", retval));
      retval = PAM_SUCCESS;
    }
  DBG (("done. [%s]", pam_strerror (pamh, retval)));
  pam_set_data (pamh, "yubico_setcred_return", &retval, NULL);

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
			 &auth_retval);
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
