/* Written by Simon Josefsson <simon@yubico.com>.
 * Copyright (c) 2006, 2007, 2008, 2009, 2010, 2011 Yubico AB
 * Copyright (c) 2011 Tollef Fog Heen <tfheen@err.no>
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
#include <syslog.h>

#include "util.h"

/* Libtool defines PIC for shared objects */
#ifndef PIC
#define PAM_STATIC
#endif

/* These #defines must be present according to PAM documentation. */
#define PAM_SM_AUTH

#ifdef HAVE_SECURITY_PAM_APPL_H
#include <security/pam_appl.h>
#endif
#ifdef HAVE_SECURITY_PAM_MODULES_H
#include <security/pam_modules.h>
#endif

#ifdef HAVE_LIBLDAP
/* Some functions like ldap_init, ldap_simple_bind_s, ldap_unbind are
   deprecated but still available. We will drop support for 'ldapserver'
   (in favour of 'ldap_uri' and update to using the new functions instead
   soon.
*/
#define LDAP_DEPRECATED 1

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

#define TOKEN_OTP_LEN 32
#define MAX_TOKEN_ID_LEN 16
#define DEFAULT_TOKEN_ID_LEN 12

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
		  const char *username,
		  const char *otp_id)
{
  char buf[1024];
  char *s_user, *s_token;
  int retval = 0;
  FILE *opwfile;

  opwfile = fopen (authfile, "r");
  if (opwfile == NULL)
    {
      D (("Cannot open file: %s", authfile));
      return retval;
    }

  while (fgets (buf, 1024, opwfile))
    {
      if (buf[strlen (buf) - 1] == '\n')
	buf[strlen (buf) - 1] = '\0';
      D (("Authorization line: %s", buf));
      s_user = strtok (buf, ":");
      if (s_user && strcmp (username, s_user) == 0)
	{
	  D (("Matched user: %s", s_user));
	  do
	    {
	      s_token = strtok (NULL, ":");
	      D (("Authorization token: %s", s_token));
	      if (s_token && strcmp (otp_id, s_token) == 0)
		{
		  D (("Match user/token as %s/%s", username, otp_id));
		  fclose (opwfile);
		  return 1;
		}
	    }
	  while (s_token != NULL);
	}
    }

  fclose (opwfile);

  return 0;
}

/*
 * Authorize authenticated OTP_ID for login as USERNAME using
 * AUTHFILE.  Return 0 on failures, otherwise success.
 */
static int
authorize_user_token (const char *authfile,
		      const char *username,
		      const char *otp_id)
{
  int retval;

  if (authfile)
    {
      /* Administrator had configured the file and specified is name
         as an argument for this module.
       */
      retval = check_user_token (authfile, username, otp_id);
    }
  else
    {
      char *userfile = NULL;

      /* Getting file from user home directory
         ..... i.e. ~/.yubico/authorized_yubikeys
       */
      if (! get_user_cfgfile_path (NULL, "authorized_yubikeys", username, &userfile))
	return 0;

      retval = check_user_token (userfile, username, otp_id);

      free (userfile);
    }

  return retval;
#undef USERFILE
}

/*
 * This function will look in ldap id the token correspond to the
 * requested user. It will returns 0 for failure and 1 for success.
 *
 * For the moment ldaps is not supported. ldap serve can be on a
 * remote host.
 *
 * You need the following parameters in you pam config:
 * ldapserver=  OR ldap_uri=
 * ldapdn=
 * user_attr=
 * yubi_attr=
 *
 */
static int
authorize_user_token_ldap (const char *ldap_uri,
			   const char *ldapserver,
			   const char *ldapdn,
			   const char *user_attr,
			   const char *yubi_attr,
			   const char *user,
			   const char *token_id)
{

  D(("called"));
  int retval = 0;
  int protocol;
#ifdef HAVE_LIBLDAP
  LDAP *ld = NULL;
  LDAPMessage *result = NULL, *e;
  BerElement *ber;
  char *a;
  char *attrs[2] = {NULL, NULL};

  struct berval **vals;
  int i, rc;

  char *find = NULL, *sr = NULL;

  if (user_attr == NULL) {
    D (("Trying to look up user to YubiKey mapping in LDAP, but user_attr not set!"));
    return 0;
  }
  if (yubi_attr == NULL) {
    D (("Trying to look up user to YubiKey mapping in LDAP, but yubi_attr not set!"));
    return 0;
  }
  if (ldapdn == NULL) {
    D (("Trying to look up user to YubiKey mapping in LDAP, but ldapdn not set!"));
    return 0;
  }

  /* Get a handle to an LDAP connection. */
  if (ldap_uri)
    {
      rc = ldap_initialize (&ld,ldap_uri);
      if (rc != LDAP_SUCCESS)
	{
	  D (("ldap_init: %s", ldap_err2string (rc)));
	  retval = 0;
	  goto done;
	}
    }
  else
    {
      if ((ld = ldap_init (ldapserver, PORT_NUMBER)) == NULL)
	{
	  D (("ldap_init"));
	  retval = 0;
	  goto done;
	}
    }

  /* LDAPv2 is historical -- RFC3494. */
  protocol = LDAP_VERSION3;
  ldap_set_option (ld, LDAP_OPT_PROTOCOL_VERSION, &protocol);

  /* Bind anonymously to the LDAP server. */
  rc = ldap_simple_bind_s (ld, NULL, NULL);
  if (rc != LDAP_SUCCESS)
    {
      D (("ldap_simple_bind_s: %s", ldap_err2string (rc)));
      retval = 0;
      goto done;
    }

  /* Allocation of memory for search strings depending on input size */
  find = malloc((strlen(user_attr)+strlen(ldapdn)+strlen(user)+3)*sizeof(char));

  sprintf (find, "%s=%s,%s", user_attr, user, ldapdn);

  attrs[0] = (char *) yubi_attr;

  D(("LDAP : look up object '%s', ask for attribute '%s'", find, yubi_attr));

  /* Search for the entry. */
  if ((rc = ldap_search_ext_s (ld, find, LDAP_SCOPE_BASE,
			       NULL, attrs, 0, NULL, NULL, LDAP_NO_LIMIT,
			       LDAP_NO_LIMIT, &result)) != LDAP_SUCCESS)
    {
      D (("ldap_search_ext_s: %s", ldap_err2string (rc)));

      retval = 0;
      goto done;
    }

  e = ldap_first_entry (ld, result);
  if (e == NULL)
    {
      D (("No result from LDAP search"));
    }
  else
    {
      /* Iterate through each returned attribute. */
      for (a = ldap_first_attribute (ld, e, &ber);
	   a != NULL; a = ldap_next_attribute (ld, e, ber))
	{
	  if ((vals = ldap_get_values_len (ld, e, a)) != NULL)
	    {
	      /* Compare each value for the attribute against the token id. */
	      for (i = 0; vals[i] != NULL; i++)
		{
		  if (!strncmp (token_id, vals[i]->bv_val, strlen (token_id)))
		    {
		      D (("Token Found :: %s", vals[i]->bv_val));
		      retval = 1;
		    }
		  else
		    {
		      D (("No match : (%s) %s != %s", a, vals[i]->bv_val, token_id));
		    }
		}
	      ldap_value_free_len (vals);
	    }
	  ldap_memfree (a);
	}
      if (ber != NULL)
	  ber_free (ber, 0);
    }

 done:
  if (result != NULL)
    ldap_msgfree (result);
  if (ld != NULL)
    ldap_unbind (ld);

  /* free memory allocated for search strings */
  if (find != NULL)
    free(find);
  if (sr != NULL)
    free(sr);

#else
  D (("Trying to use LDAP, but this function is not compiled in pam_yubico!!"));
  D (("Install libldap-dev and then recompile pam_yubico."));
#endif
  return retval;
}

enum key_mode {
  CHRESP,
  CLIENT
};

struct cfg
{
  int client_id;
  char *client_key;
  int debug;
  int alwaysok;
  int verbose_otp;
  int try_first_pass;
  int use_first_pass;
  char *auth_file;
  char *capath;
  char *url;
  char *ldapserver;
  char *ldap_uri;
  char *ldapdn;
  char *user_attr;
  char *yubi_attr;
  int token_id_length;
  enum key_mode mode;
  char *chalresp_path;
};

static int
display_error(pam_handle_t *pamh, char *message) {
  struct pam_conv *conv;
  struct pam_message *pmsg[1], msg[1];
  struct pam_response *resp = NULL;
  int retval;

  retval = pam_get_item (pamh, PAM_CONV, (const void **) &conv);
  if (retval != PAM_SUCCESS) {
    D(("get conv returned error: %s", pam_strerror (pamh, retval)));
    return retval;
  }

  pmsg[0] = &msg[0];
  msg[0].msg = message;
  msg[0].msg_style = PAM_ERROR_MSG;
  retval = conv->conv(1, (const struct pam_message **) pmsg,
		      &resp, conv->appdata_ptr);

  if (retval != PAM_SUCCESS) {
    D(("conv returned error: %s", pam_strerror (pamh, retval)));
    return retval;
  }

  D(("conv returned: '%s'", resp->resp));
  return retval;
}

static int
do_challenge_response(pam_handle_t *pamh, struct cfg *cfg, const char *username)
{
  char *userfile = NULL, *tmpfile = NULL;
  FILE *f = NULL;
  unsigned char buf[CR_RESPONSE_SIZE + 16], response_hex[CR_RESPONSE_SIZE * 2 + 1];
  int ret;

  unsigned int flags = 0;
  unsigned int response_len = 0;
  unsigned int expect_bytes = 0;
  YK_KEY *yk = NULL;
  CR_STATE state;

  int len;
  char *errstr = NULL;

  ret = PAM_AUTH_ERR;
  flags |= YK_FLAG_MAYBLOCK;

  if (! init_yubikey(&yk)) {
    D(("Failed initializing YubiKey"));
    goto out;
  }

  if (! check_firmware_version(yk, false, true)) {
    D(("YubiKey does not support Challenge-Response (version 2.2 required)"));
    goto out;
  }


  if (! get_user_challenge_file (yk, cfg->chalresp_path, username, &userfile)) {
    D(("Failed getting user challenge file for user %s", username));
    goto out;
  }

  D(("Loading challenge from file %s", userfile));

  /* XXX should drop root privileges before opening file in user's home directory */
  f = fopen(userfile, "r");

  if (! load_chalresp_state(f, &state))
    goto out;

  if (fclose(f) < 0) {
    f = NULL;
    goto out;
  }

  if (! challenge_response(yk, state.slot, state.challenge, state.challenge_len,
			   true, flags, false,
			   buf, sizeof(buf), &response_len)) {
    D(("Challenge-response FAILED"));
    goto out;
  }

  /*
   * Check YubiKey response against the expected response
   */

  yubikey_hex_encode(response_hex, (char *)buf, response_len);

  if (memcmp(buf, state.response, response_len) == 0) {
    ret = PAM_SUCCESS;
  } else {
    D(("Unexpected C/R response : %s", response_hex));
    goto out;
  }

  D(("Got the expected response, generating new challenge (%i bytes).", CR_CHALLENGE_SIZE));

  errstr = "Error generating new challenge, please check syslog or contact your system administrator";
  if (generate_random(state.challenge, sizeof(state.challenge))) {
    D(("Failed generating new challenge!"));
    goto out;
  }

  errstr = "Error communicating with Yubikey, please check syslog or contact your system administrator";
  if (! challenge_response(yk, state.slot, state.challenge, CR_CHALLENGE_SIZE,
			   true, flags, false,
			   buf, sizeof(buf), &response_len)) {
    D(("Second challenge-response FAILED"));
    goto out;
  }

  /* the yk_* functions leave 'junk' in errno */
  errno = 0;

  /*
   * Write the challenge and response we will expect the next time to the state file.
   */
  if (response_len > sizeof(state.response)) {
    D(("Got too long response ??? (%i/%i)", response_len, sizeof(state.response)));
    goto out;
  }
  memcpy (state.response, buf, response_len);
  state.response_len = response_len;

  /* Write out the new file */
  tmpfile = malloc(strlen(userfile) + 1 + 4);
  if (! tmpfile)
    goto out;
  strcpy(tmpfile, userfile);
  strcat(tmpfile, ".tmp");

  f = fopen(tmpfile, "w");
  if (! f)
    goto out;

  errstr = "Error updating Yubikey challenge, please check syslog or contact your system administrator";
  if (! write_chalresp_state (f, &state))
    goto out;
  if (fclose(f) < 0) {
    f = NULL;
    goto out;
  }
  f = NULL;
  if (rename(tmpfile, userfile) < 0) {
    goto out;
  }

  D(("Challenge-response success!"));
  errstr = NULL;

 out:
  if (yk_errno) {
    if (yk_errno == YK_EUSBERR) {
      syslog(LOG_ERR, "USB error: %s", yk_usb_strerror());
    } else {
      syslog(LOG_ERR, "Yubikey core error: %s", yk_strerror(yk_errno));
    }
  }

  if (errstr)
    display_error(pamh, errstr);

  if (errno) {
    syslog(LOG_ERR, "Challenge response failed: %s", strerror(errno));
  }

  if (yk)
    yk_close_key(yk);
  yk_release();

  if (f)
    fclose(f);

  free(userfile);
  free(tmpfile);
  return ret;
}
#undef USERFILE

static void
parse_cfg (int flags, int argc, const char **argv, struct cfg *cfg)
{
  int i;

  cfg->client_id = -1;
  cfg->client_key = NULL;
  cfg->debug = 0;
  cfg->alwaysok = 0;
  cfg->verbose_otp = 0;
  cfg->try_first_pass = 0;
  cfg->use_first_pass = 0;
  cfg->auth_file = NULL;
  cfg->capath = NULL;
  cfg->url = NULL;
  cfg->ldapserver = NULL;
  cfg->ldap_uri = NULL;
  cfg->ldapdn = NULL;
  cfg->user_attr = NULL;
  cfg->yubi_attr = NULL;
  cfg->token_id_length = DEFAULT_TOKEN_ID_LEN;
  cfg->mode = CLIENT;
  cfg->chalresp_path = NULL;

  for (i = 0; i < argc; i++)
    {
      if (strncmp (argv[i], "id=", 3) == 0)
	sscanf (argv[i], "id=%d", &cfg->client_id);
      if (strncmp (argv[i], "key=", 4) == 0)
	cfg->client_key = (char *) argv[i] + 4;
      if (strcmp (argv[i], "debug") == 0)
	cfg->debug = 1;
      if (strcmp (argv[i], "alwaysok") == 0)
	cfg->alwaysok = 1;
      if (strcmp (argv[i], "verbose_otp") == 0)
	cfg->verbose_otp = 1;
      if (strcmp (argv[i], "try_first_pass") == 0)
	cfg->try_first_pass = 1;
      if (strcmp (argv[i], "use_first_pass") == 0)
	cfg->use_first_pass = 1;
      if (strncmp (argv[i], "authfile=", 9) == 0)
	cfg->auth_file = (char *) argv[i] + 9;
      if (strncmp (argv[i], "capath=", 7) == 0)
	cfg->capath = (char *) argv[i] + 7;
      if (strncmp (argv[i], "url=", 4) == 0)
	cfg->url = (char *) argv[i] + 4;
      if (strncmp (argv[i], "ldapserver=", 11) == 0)
	cfg->ldapserver = (char *) argv[i] + 11;
      if (strncmp (argv[i], "ldap_uri=", 9) == 0)
	cfg->ldap_uri = (char *) argv[i] + 9;
      if (strncmp (argv[i], "ldapdn=", 7) == 0)
	cfg->ldapdn = (char *) argv[i] + 7;
      if (strncmp (argv[i], "user_attr=", 10) == 0)
	cfg->user_attr = (char *) argv[i] + 10;
      if (strncmp (argv[i], "yubi_attr=", 10) == 0)
	cfg->yubi_attr = (char *) argv[i] + 10;
      if (strncmp (argv[i], "token_id_length=", 16) == 0)
	sscanf (argv[i], "token_id_length=%d", &cfg->token_id_length);
      if (strcmp (argv[i], "mode=challenge-response") == 0)
	cfg->mode = CHRESP;
      if (strcmp (argv[i], "mode=client") == 0)
	cfg->mode = CLIENT;
      if (strncmp (argv[i], "chalresp_path=", 14) == 0)
	cfg->chalresp_path = (char *) argv[i] + 14;
    }

  if (cfg->debug)
    {
      D (("called."));
      D (("flags %d argc %d", flags, argc));
      for (i = 0; i < argc; i++)
	D (("argv[%d]=%s", i, argv[i]));
      D (("id=%d", cfg->client_id));
      D (("key=%s", cfg->client_key ? cfg->client_key : "(null)"));
      D (("debug=%d", cfg->debug));
      D (("alwaysok=%d", cfg->alwaysok));
      D (("verbose_otp=%d", cfg->verbose_otp));
      D (("try_first_pass=%d", cfg->try_first_pass));
      D (("use_first_pass=%d", cfg->use_first_pass));
      D (("authfile=%s", cfg->auth_file ? cfg->auth_file : "(null)"));
      D (("ldapserver=%s", cfg->ldapserver ? cfg->ldapserver : "(null)"));
      D (("ldap_uri=%s", cfg->ldap_uri ? cfg->ldap_uri : "(null)"));
      D (("ldapdn=%s", cfg->ldapdn ? cfg->ldapdn : "(null)"));
      D (("user_attr=%s", cfg->user_attr ? cfg->user_attr : "(null)"));
      D (("yubi_attr=%s", cfg->yubi_attr ? cfg->yubi_attr : "(null)"));
      D (("url=%s", cfg->url ? cfg->url : "(null)"));
      D (("capath=%s", cfg->capath ? cfg->capath : "(null)"));
      D (("token_id_length=%d", cfg->token_id_length));
      D (("mode=%s", cfg->mode == CLIENT ? "client" : "chresp" ));
      D (("chalresp_path=%d", cfg->chalresp_path));
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
  char otp[MAX_TOKEN_ID_LEN + TOKEN_OTP_LEN + 1] = { 0 };
  char otp_id[MAX_TOKEN_ID_LEN + 1] = { 0 };
  int password_len = 0;
  int skip_bytes = 0;
  int valid_token = 0;
  struct pam_conv *conv;
  struct pam_message *pmsg[1], msg[1];
  struct pam_response *resp;
  int nargs = 1;
  ykclient_t *ykc = NULL;
  struct cfg cfg;

  parse_cfg (flags, argc, argv, &cfg);

  retval = pam_get_user (pamh, &user, NULL);
  if (retval != PAM_SUCCESS)
    {
      DBG (("get user returned error: %s", pam_strerror (pamh, retval)));
      goto done;
    }
  DBG (("get user returned: %s", user));

  if (cfg.mode == CHRESP) {
    return do_challenge_response(pamh, &cfg, user);
  }

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

  rc = ykclient_init (&ykc);
  if (rc != YKCLIENT_OK)
    {
      DBG (("ykclient_init() failed (%d): %s", rc, ykclient_strerror (rc)));
      retval = PAM_AUTHINFO_UNAVAIL;
      goto done;
    }

  rc = ykclient_set_client_b64 (ykc, cfg.client_id, cfg.client_key);
  if (rc != YKCLIENT_OK)
    {
      DBG (("ykclient_set_client_b64() failed (%d): %s",
	    rc, ykclient_strerror (rc)));
      retval = PAM_AUTHINFO_UNAVAIL;
      goto done;
    }

  if (cfg.capath)
    ykclient_set_ca_path (ykc, cfg.capath);

  if (cfg.url)
    ykclient_set_url_template (ykc, cfg.url);

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
      msg[0].msg_style = cfg.verbose_otp ? PAM_PROMPT_ECHO_ON : PAM_PROMPT_ECHO_OFF;
      resp = NULL;

      retval = conv->conv (nargs, (const struct pam_message **) pmsg,
			   &resp, conv->appdata_ptr);

      free ((char *) msg[0].msg);

      if (retval != PAM_SUCCESS)
	{
	  DBG (("conv returned error: %s", pam_strerror (pamh, retval)));
	  goto done;
	}

      if (resp->resp == NULL)
	{
	  DBG (("conv returned NULL passwd?"));
	  goto done;
	}

      DBG (("conv returned %i bytes", strlen(resp->resp)));

      password = resp->resp;
    }

  password_len = strlen (password);
  if (password_len < (cfg.token_id_length + TOKEN_OTP_LEN))
    {
      DBG (("OTP too short to be considered : %i < %i", password_len, (cfg.token_id_length + TOKEN_OTP_LEN)));
      retval = PAM_AUTH_ERR;
      goto done;
    }

  /* In case the input was systempassword+YubiKeyOTP, we want to skip over
     "systempassword" when copying the token_id and OTP to separate buffers */
  skip_bytes = password_len - (cfg.token_id_length + TOKEN_OTP_LEN);

  DBG (("Skipping first %i bytes. Length is %i, token_id set to %i and token OTP always %i.",
	skip_bytes, password_len, cfg.token_id_length, TOKEN_OTP_LEN));

  /* Copy full YubiKey output (public ID + OTP) into otp */
  strncpy (otp, password + skip_bytes, sizeof (otp) - 1);
  /* Copy only public ID into otp_id. Destination buffer is zeroed. */
  strncpy (otp_id, password + skip_bytes, cfg.token_id_length);

  DBG (("OTP: %s ID: %s ", otp, otp_id));

  /* user entered their system password followed by generated OTP? */
  if (password_len > TOKEN_OTP_LEN + cfg.token_id_length)
    {
      char *onlypasswd = strdup (password);

      onlypasswd[password_len - (TOKEN_OTP_LEN + cfg.token_id_length)] = '\0';

      DBG (("Extracted a probable system password entered before the OTP - "
	    "setting item PAM_AUTHTOK"));

      retval = pam_set_item (pamh, PAM_AUTHTOK, onlypasswd);
      free (onlypasswd);
      if (retval != PAM_SUCCESS)
	{
	  DBG (("set_item returned error: %s", pam_strerror (pamh, retval)));
	  goto done;
	}
    }
  else
    password = NULL;

  rc = ykclient_request (ykc, otp);

  DBG (("ykclient return value (%d): %s", rc,
	ykclient_strerror (rc)));

  switch (rc)
    {
    case YKCLIENT_OK:
      break;

    case YKCLIENT_BAD_OTP:
    case YKCLIENT_REPLAYED_OTP:
      retval = PAM_AUTH_ERR;
      goto done;

    default:
      retval = PAM_AUTHINFO_UNAVAIL;
      goto done;
    }

  /* authorize the user with supplied token id */
  if (cfg.ldapserver != NULL || cfg.ldap_uri != NULL)
    valid_token = authorize_user_token_ldap (cfg.ldap_uri, cfg.ldapserver,
					     cfg.ldapdn, cfg.user_attr,
					     cfg.yubi_attr, user, otp_id);
  else
    valid_token = authorize_user_token (cfg.auth_file, user, otp_id);

  if (valid_token == 0)
    {
      DBG (("Yubikey not authorized to login as user"));
      retval = PAM_AUTHINFO_UNAVAIL;
      goto done;
    }

  retval = PAM_SUCCESS;

done:
  if (ykc)
    ykclient_done (&ykc);
  if (cfg.alwaysok && retval != PAM_SUCCESS)
    {
      DBG (("alwaysok needed (otherwise return with %d)", retval));
      retval = PAM_SUCCESS;
    }
  DBG (("done. [%s]", pam_strerror (pamh, retval)));
  pam_set_data (pamh, "yubico_setcred_return", (void*) (intptr_t) retval, NULL);

  return retval;
}

PAM_EXTERN int
pam_sm_setcred (pam_handle_t * pamh, int flags, int argc, const char **argv)
{
  return PAM_SUCCESS;
}

#ifdef PAM_STATIC

struct pam_module _pam_yubico_modstruct = {
  "pam_yubico",
  pam_sm_authenticate,
  pam_sm_setcred,
  NULL,
  NULL,
  NULL,
  NULL
};

#endif
