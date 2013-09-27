/* Written by Simon Josefsson <simon@yubico.com>.
 * Copyright (c) 2006-2013 Yubico AB
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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <pwd.h>

#include "util.h"
#include "drop_privs.h"

#if HAVE_CR
/* for yubikey_hex_decode and yubikey_hex_p */
#include <yubikey.h>
#include <ykpbkdf2.h>
#endif /* HAVE_CR */

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
  char *yubi_attr_prefix;
  int token_id_length;
  enum key_mode mode;
  char *chalresp_path;
};

#ifdef DBG
#undef DBG
#endif
#define DBG(x) if (cfg->debug) { D(x); }

/*
 * This function will look for users name with valid user token id. It
 * will returns -2 if the user is unknown, -1 if the token do not match the user line, 0 for internal failure and 1 for success.
 *
 * File format is as follows:
 * <user-name>:<token_id>:<token_id>
 * <user-name>:<token_id>
 *
 */
static int
check_user_token (struct cfg *cfg,
		  const char *authfile,
		  const char *username,
		  const char *otp_id)
{
  char buf[1024];
  char *s_user, *s_token;
  int retval = 0;
  int fd;
  struct stat st;
  FILE *opwfile;

  fd = open(authfile, O_RDONLY, 0);
  if (fd < 0) {
      DBG (("Cannot open file: %s (%s)", authfile, strerror(errno)));
      return retval;
  }

  if (fstat(fd, &st) < 0) {
      DBG (("Cannot stat file: %s (%s)", authfile, strerror(errno)));
      close(fd);
      return retval;
  }

  if (!S_ISREG(st.st_mode)) {
      DBG (("%s is not a regular file", authfile));
      close(fd);
      return retval;
  }

  opwfile = fdopen(fd, "r");
  if (opwfile == NULL) {
      DBG (("fdopen: %s", strerror(errno)));
      close(fd);
      return retval;
  }

  retval = -2;
  while (fgets (buf, 1024, opwfile))
    {
      if (buf[strlen (buf) - 1] == '\n')
	buf[strlen (buf) - 1] = '\0';
      DBG (("Authorization line: %s", buf));
      s_user = strtok (buf, ":");
      if (s_user && strcmp (username, s_user) == 0)
	{
	  DBG (("Matched user: %s", s_user));
      retval = -1; //We found at least one line for the user
	  do
	    {
	      s_token = strtok (NULL, ":");
	      DBG (("Authorization token: %s", s_token));
	      if (s_token && strcmp (otp_id, s_token) == 0)
		{
		  DBG (("Match user/token as %s/%s", username, otp_id));
		  fclose (opwfile);
		  return 1;
		}
	    }
	  while (s_token != NULL);
	}
    }

  fclose (opwfile);

  return retval;
}

/*
 * Authorize authenticated OTP_ID for login as USERNAME using
 * AUTHFILE.  Return -2 if the user is unknown, -1 if the OTP_ID does not match,  0 on internal failures, otherwise success.
 */
static int
authorize_user_token (struct cfg *cfg,
		      const char *username,
		      const char *otp_id,
		      pam_handle_t *pamh)
{
  int retval;

  if (cfg->auth_file)
    {
      /* Administrator had configured the file and specified is name
         as an argument for this module.
       */
      DBG (("Using system-wide auth_file %s", cfg->auth_file));
      retval = check_user_token (cfg, cfg->auth_file, username, otp_id);
    }
  else
    {
      char *userfile = NULL;
      struct passwd *p;
      PAM_MODUTIL_DEF_PRIVS(privs);

      p = getpwnam (username);
      if (p == NULL) {
	DBG (("getpwnam: %s", strerror(errno)));
	return 0;
      }

      /* Getting file from user home directory
         ..... i.e. ~/.yubico/authorized_yubikeys
       */
      if (! get_user_cfgfile_path (NULL, "authorized_yubikeys", username, &userfile)) {
	D (("Failed figuring out per-user cfgfile"));
	return 0;
      }

      DBG (("Dropping privileges"));
      if(pam_modutil_drop_priv(pamh, &privs, p)) {
        DBG (("could not drop privileges"));
	retval = 0;
	goto free_out;
      }

      retval = check_user_token (cfg, userfile, username, otp_id);

      if(pam_modutil_regain_priv(pamh, &privs)) {
        DBG (("could not restore privileges"));
        retval = 0;
        goto free_out;
      }

free_out:
      free (userfile);
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
 * ldapserver=  OR ldap_uri=
 * ldapdn=
 * user_attr=
 * yubi_attr=
 *
 */
static int
authorize_user_token_ldap (struct cfg *cfg,
			   const char *user,
			   const char *token_id)
{
  int retval = 0;
  int protocol;
#ifdef HAVE_LIBLDAP
  int yubi_attr_prefix_len = 0;
  LDAP *ld = NULL;
  LDAPMessage *result = NULL, *e;
  BerElement *ber;
  char *a;
  char *attrs[2] = {NULL, NULL};

  struct berval **vals;
  int i, rc;

  char *find = NULL;
#endif
  DBG(("called"));
#ifdef HAVE_LIBLDAP

  if (cfg->user_attr == NULL) {
    DBG (("Trying to look up user to YubiKey mapping in LDAP, but user_attr not set!"));
    return 0;
  }
  if (cfg->yubi_attr == NULL) {
    DBG (("Trying to look up user to YubiKey mapping in LDAP, but yubi_attr not set!"));
    return 0;
  }
  if (cfg->ldapdn == NULL) {
    DBG (("Trying to look up user to YubiKey mapping in LDAP, but ldapdn not set!"));
    return 0;
  }

  /* Get a handle to an LDAP connection. */
  if (cfg->ldap_uri)
    {
      rc = ldap_initialize (&ld, cfg->ldap_uri);
      if (rc != LDAP_SUCCESS)
	{
	  DBG (("ldap_init: %s", ldap_err2string (rc)));
	  retval = 0;
	  goto done;
	}
    }
  else
    {
      if ((ld = ldap_init (cfg->ldapserver, PORT_NUMBER)) == NULL)
	{
	  DBG (("ldap_init"));
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
      DBG (("ldap_simple_bind_s: %s", ldap_err2string (rc)));
      retval = 0;
      goto done;
    }

  /* Allocation of memory for search strings depending on input size */
  i = (strlen(cfg->user_attr) + strlen(cfg->ldapdn) + strlen(user) + 3) * sizeof(char);
  if ((find = malloc(i)) == NULL) {
    DBG (("Failed allocating %i bytes", i));
    retval = 0;
    goto done;
  }

  sprintf (find, "%s=%s,%s", cfg->user_attr, user, cfg->ldapdn);

  attrs[0] = (char *) cfg->yubi_attr;

  DBG(("LDAP : look up object '%s', ask for attribute '%s'", find, cfg->yubi_attr));

  /* Search for the entry. */
  if ((rc = ldap_search_ext_s (ld, find, LDAP_SCOPE_BASE,
			       NULL, attrs, 0, NULL, NULL, LDAP_NO_LIMIT,
			       LDAP_NO_LIMIT, &result)) != LDAP_SUCCESS)
    {
      DBG (("ldap_search_ext_s: %s", ldap_err2string (rc)));

      retval = 0;
      goto done;
    }

  e = ldap_first_entry (ld, result);
  if (e == NULL)
    {
      DBG (("No result from LDAP search"));
      retval = -2;
    }
  else
    {
      retval = -1;
      /* Iterate through each returned attribute. */
      for (a = ldap_first_attribute (ld, e, &ber);
	   a != NULL; a = ldap_next_attribute (ld, e, ber))
	{
	  if ((vals = ldap_get_values_len (ld, e, a)) != NULL)
	    {
	      DBG(("LDAP : Found %i values - checking if any of them match '%s%s'",
		   ldap_count_values_len(vals),
		   cfg->yubi_attr_prefix ? cfg->yubi_attr_prefix : "",
		   token_id));

	      yubi_attr_prefix_len = cfg->yubi_attr_prefix ? strlen(cfg->yubi_attr_prefix) : 0;

	      /* Compare each value for the attribute against the token id. */
	      for (i = 0; vals[i] != NULL; i++)
		{
		  /* Only values containing this prefix are considered. */
		  if ((!cfg->yubi_attr_prefix || !strncmp (cfg->yubi_attr_prefix, vals[i]->bv_val, yubi_attr_prefix_len)))
		    {
		      if(!strncmp (token_id, vals[i]->bv_val + yubi_attr_prefix_len, strlen (token_id)))
		        {
		          DBG (("Token Found :: %s", vals[i]->bv_val));
		          retval = 1;
		        }
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

#else
  DBG (("Trying to use LDAP, but this function is not compiled in pam_yubico!!"));
  DBG (("Install libldap-dev and then recompile pam_yubico."));
#endif
  return retval;
}

#if HAVE_CR
static int
display_error(pam_handle_t *pamh, const char *message) {
  struct pam_conv *conv;
  const struct pam_message *pmsg[1];
  struct pam_message msg[1];
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
  retval = conv->conv(1, pmsg, &resp, conv->appdata_ptr);

  if (retval != PAM_SUCCESS) {
    D(("conv returned error: %s", pam_strerror (pamh, retval)));
    return retval;
  }

  D(("conv returned: '%s'", resp->resp));
  return retval;
}
#endif /* HAVE_CR */

#if HAVE_CR
static int
do_challenge_response(pam_handle_t *pamh, struct cfg *cfg, const char *username)
{
  char *userfile = NULL, *tmpfile = NULL;
  FILE *f = NULL;
  char buf[CR_RESPONSE_SIZE + 16], response_hex[CR_RESPONSE_SIZE * 2 + 1];
  int ret, fd;

  unsigned int response_len = 0;
  YK_KEY *yk = NULL;
  CR_STATE state;

  const char *errstr = NULL;

  struct passwd *p;
  struct stat st;

  /* we must declare two sepparate privs structures as they can't be reused */
  PAM_MODUTIL_DEF_PRIVS(privs);
  PAM_MODUTIL_DEF_PRIVS(privs2);

  ret = PAM_AUTH_ERR;

  if (! init_yubikey(&yk)) {
    DBG(("Failed initializing YubiKey"));
    goto out;
  }

  if (! check_firmware_version(yk, false, true)) {
    DBG(("YubiKey does not support Challenge-Response (version 2.2 required)"));
    goto out;
  }


  if (! get_user_challenge_file (yk, cfg->chalresp_path, username, &userfile)) {
    DBG(("Failed getting user challenge file for user %s", username));
    goto out;
  }

  DBG(("Loading challenge from file %s", userfile));

  p = getpwnam (username);
  if (p == NULL) {
      DBG (("getpwnam: %s", strerror(errno)));
      goto out;
  }

  /* Drop privileges before opening user file. */
  if (pam_modutil_drop_priv(pamh, &privs, p)) {
      DBG (("could not drop privileges"));
      goto out;
  }

  fd = open(userfile, O_RDONLY, 0);
  if (fd < 0) {
      DBG (("Cannot open file: %s (%s)", userfile, strerror(errno)));
      goto restpriv_out;
  }

  if (fstat(fd, &st) < 0) {
      DBG (("Cannot stat file: %s (%s)", userfile, strerror(errno)));
      close(fd);
      goto restpriv_out;
  }

  if (!S_ISREG(st.st_mode)) {
      DBG (("%s is not a regular file", userfile));
      close(fd);
      goto restpriv_out;
  }

  f = fdopen(fd, "r");
  if (f == NULL) {
      DBG (("fdopen: %s", strerror(errno)));
      close(fd);
      goto restpriv_out;
  }

  if (! load_chalresp_state(f, &state, cfg->debug))
    goto restpriv_out;

  if (fclose(f) < 0) {
    f = NULL;
    goto restpriv_out;
  }
  f = NULL;

  if (pam_modutil_regain_priv(pamh, &privs)) {
      DBG (("could not restore privileges"));
      goto out;
  }

  if (! challenge_response(yk, state.slot, state.challenge, state.challenge_len,
			   true, true, false,
			   buf, sizeof(buf), &response_len)) {
    DBG(("Challenge-response FAILED"));
    goto out;
  }

  /*
   * Check YubiKey response against the expected response
   */

  yubikey_hex_encode(response_hex, buf, response_len);
  if(state.salt_len > 0) { // the expected response has gone through pbkdf2
    YK_PRF_METHOD prf_method = {20, yk_hmac_sha1};
    yk_pbkdf2(response_hex, (unsigned char*)state.salt, state.salt_len, state.iterations,
        (unsigned char*)buf, response_len, &prf_method);
  }

  if (memcmp(buf, state.response, state.response_len) == 0) {
    ret = PAM_SUCCESS;
  } else {
    DBG(("Unexpected C/R response : %s", response_hex));
    goto out;
  }

  DBG(("Got the expected response, generating new challenge (%i bytes).", CR_CHALLENGE_SIZE));

  errstr = "Error generating new challenge, please check syslog or contact your system administrator";
  if (generate_random(state.challenge, sizeof(state.challenge))) {
    DBG(("Failed generating new challenge!"));
    goto out;
  }

  errstr = "Error communicating with Yubikey, please check syslog or contact your system administrator";
  if (! challenge_response(yk, state.slot, state.challenge, CR_CHALLENGE_SIZE,
			   true, true, false,
			   buf, sizeof(buf), &response_len)) {
    DBG(("Second challenge-response FAILED"));
    goto out;
  }

  /* There is a bug that makes the YubiKey 2.2 send the same response for all challenges
     unless HMAC_LT64 is set, check for that here */
  if (memcmp(buf, state.response, state.response_len) == 0) {
    errstr = "Same response for second challenge, YubiKey should be reconfigured with the option HMAC_LT64";
    goto out;
  }

  /* the yk_* functions leave 'junk' in errno */
  errno = 0;

  /*
   * Write the challenge and response we will expect the next time to the state file.
   */
  if (response_len > sizeof(state.response)) {
    DBG(("Got too long response ??? (%u/%lu)", response_len, (unsigned long) sizeof(state.response)));
    goto out;
  }
  memcpy (state.response, buf, response_len);
  state.response_len = response_len;

  /* point to the fresh privs structure.. */
  privs = privs2;
  /* Drop privileges before creating new challenge file. */
  if (pam_modutil_drop_priv(pamh, &privs, p)) {
      DBG (("could not drop privileges"));
      goto out;
  }

  /* Write out the new file */
  tmpfile = malloc(strlen(userfile) + 1 + 4);
  if (! tmpfile)
    goto restpriv_out;
  strcpy(tmpfile, userfile);
  strcat(tmpfile, ".tmp");

  fd = open(tmpfile, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
  if (fd < 0) {
      DBG (("Cannot open file: %s (%s)", tmpfile, strerror(errno)));
      goto restpriv_out;
  }

  f = fdopen(fd, "w");
  if (! f) {
    close(fd);
    goto restpriv_out;
  }

  errstr = "Error updating Yubikey challenge, please check syslog or contact your system administrator";
  if (! write_chalresp_state (f, &state))
    goto out;
  if (fclose(f) < 0) {
    f = NULL;
    goto restpriv_out;
  }
  f = NULL;
  if (rename(tmpfile, userfile) < 0) {
    goto restpriv_out;
  }

  if (pam_modutil_regain_priv(pamh, &privs)) {
      DBG (("could not restore privileges"));
      goto out;
  }

  DBG(("Challenge-response success!"));
  errstr = NULL;
  errno = 0;
  goto out;

restpriv_out:
  if (pam_modutil_regain_priv(pamh, &privs)) {
      DBG (("could not restore privileges"));
  }

 out:
  if (yk_errno) {
    if (yk_errno == YK_EUSBERR) {
      syslog(LOG_ERR, "USB error: %s", yk_usb_strerror());
      DBG(("USB error: %s", yk_usb_strerror()));
    } else {
      syslog(LOG_ERR, "Yubikey core error: %s", yk_strerror(yk_errno));
      DBG(("Yubikey core error: %s", yk_strerror(yk_errno)));
    }
  }

  if (errstr)
    display_error(pamh, errstr);

  if (errno) {
    syslog(LOG_ERR, "Challenge response failed: %s", strerror(errno));
    DBG(("Challenge response failed: %s", strerror(errno)));
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
#endif /* HAVE_CR */

static void
parse_cfg (int flags, int argc, const char **argv, struct cfg *cfg)
{
  int i;

  memset (cfg, 0, sizeof(struct cfg));
  cfg->client_id = -1;
  cfg->token_id_length = DEFAULT_TOKEN_ID_LEN;
  cfg->mode = CLIENT;

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
      if (strncmp (argv[i], "yubi_attr_prefix=", 17) == 0)
	cfg->yubi_attr_prefix = (char *) argv[i] + 17;
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
      D (("yubi_attr_prefix=%s", cfg->yubi_attr_prefix ? cfg->yubi_attr_prefix : "(null)"));
      D (("url=%s", cfg->url ? cfg->url : "(null)"));
      D (("capath=%s", cfg->capath ? cfg->capath : "(null)"));
      D (("token_id_length=%d", cfg->token_id_length));
      D (("mode=%s", cfg->mode == CLIENT ? "client" : "chresp" ));
      D (("chalresp_path=%s", cfg->chalresp_path ? cfg->chalresp_path : "(null)"));
    }
}

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
  const struct pam_message *pmsg[1];
  struct pam_message msg[1];
  struct pam_response *resp;
  int nargs = 1;
  ykclient_t *ykc = NULL;
  struct cfg cfg_st;
  struct cfg *cfg = &cfg_st; /* for DBG macro */

  parse_cfg (flags, argc, argv, cfg);

  if (cfg->token_id_length > MAX_TOKEN_ID_LEN)
  {
    DBG (("configuration error: token_id_length too long. Maximum acceptable value : %d", MAX_TOKEN_ID_LEN));
    retval = PAM_AUTHINFO_UNAVAIL;
    goto done;
  }

  retval = pam_get_user (pamh, &user, NULL);
  if (retval != PAM_SUCCESS)
    {
      DBG (("get user returned error: %s", pam_strerror (pamh, retval)));
      goto done;
    }
  DBG (("get user returned: %s", user));

  if (cfg->mode == CHRESP) {
#if HAVE_CR
    return do_challenge_response(pamh, cfg, user);
#else
    DBG (("no support for challenge/response"));
    retval = PAM_AUTH_ERR;
    goto done;
#endif
  }

  if (cfg->try_first_pass || cfg->use_first_pass)
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

  if (cfg->use_first_pass && password == NULL)
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

  rc = ykclient_set_client_b64 (ykc, cfg->client_id, cfg->client_key);
  if (rc != YKCLIENT_OK)
    {
      DBG (("ykclient_set_client_b64() failed (%d): %s",
	    rc, ykclient_strerror (rc)));
      retval = PAM_AUTHINFO_UNAVAIL;
      goto done;
    }

  if (cfg->client_key)
    ykclient_set_verify_signature (ykc, 1);

  if (cfg->capath)
    ykclient_set_ca_path (ykc, cfg->capath);

  if (cfg->url)
    ykclient_set_url_template (ykc, cfg->url);

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
#define QUERY_TEMPLATE "YubiKey for `%s': "
	size_t len = strlen (QUERY_TEMPLATE) + strlen (user);
	int wrote;

	msg[0].msg = malloc (len);
	if (!msg[0].msg)
	  {
	    retval = PAM_BUF_ERR;
	    goto done;
	  }

	wrote = snprintf ((char *) msg[0].msg, len, QUERY_TEMPLATE, user);
	if (wrote < 0 || wrote >= len)
	  {
	    retval = PAM_BUF_ERR;
	    goto done;
	  }
      }
      msg[0].msg_style = cfg->verbose_otp ? PAM_PROMPT_ECHO_ON : PAM_PROMPT_ECHO_OFF;
      resp = NULL;

      retval = conv->conv (nargs, pmsg, &resp, conv->appdata_ptr);

      free ((char *) msg[0].msg);

      if (retval != PAM_SUCCESS)
	{
	  DBG (("conv returned error: %s", pam_strerror (pamh, retval)));
	  goto done;
	}

      if (resp->resp == NULL)
	{
	  DBG (("conv returned NULL passwd?"));
	  retval = PAM_AUTH_ERR;
	  goto done;
	}

      DBG (("conv returned %lu bytes", (unsigned long) strlen(resp->resp)));

      password = resp->resp;
    }

  password_len = strlen (password);
  if (password_len < (cfg->token_id_length + TOKEN_OTP_LEN))
    {
      DBG (("OTP too short to be considered : %i < %i", password_len, (cfg->token_id_length + TOKEN_OTP_LEN)));
      retval = PAM_AUTH_ERR;
      goto done;
    }

  /* In case the input was systempassword+YubiKeyOTP, we want to skip over
     "systempassword" when copying the token_id and OTP to separate buffers */
  skip_bytes = password_len - (cfg->token_id_length + TOKEN_OTP_LEN);

  DBG (("Skipping first %i bytes. Length is %i, token_id set to %i and token OTP always %i.",
	skip_bytes, password_len, cfg->token_id_length, TOKEN_OTP_LEN));

  /* Copy full YubiKey output (public ID + OTP) into otp */
  strncpy (otp, password + skip_bytes, sizeof (otp) - 1);
  /* Copy only public ID into otp_id. Destination buffer is zeroed. */
  strncpy (otp_id, password + skip_bytes, cfg->token_id_length);

  DBG (("OTP: %s ID: %s ", otp, otp_id));

  /* user entered their system password followed by generated OTP? */
  if (password_len > TOKEN_OTP_LEN + cfg->token_id_length)
    {
      char *onlypasswd = strdup (password);

      if (! onlypasswd) {
	retval = PAM_BUF_ERR;
	goto done;
      }

      onlypasswd[password_len - (TOKEN_OTP_LEN + cfg->token_id_length)] = '\0';

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
  if (cfg->ldapserver != NULL || cfg->ldap_uri != NULL)
    valid_token = authorize_user_token_ldap (cfg, user, otp_id);
  else
    valid_token = authorize_user_token (cfg, user, otp_id, pamh);

  switch(valid_token)
    {
    case 1:
      retval = PAM_SUCCESS;
      break;
    case 0:
      DBG (("Internal error while validating user"));
      retval = PAM_AUTHINFO_UNAVAIL;
      break;
    case -1:
      DBG (("Unauthorized token for this user"));
      retval = PAM_AUTH_ERR;
      break;
    case -2:
      DBG (("Unknown user"));
      retval = PAM_USER_UNKNOWN;
      break;
    default:
      DBG (("Unhandled value for token-user validation"))
      retval = PAM_AUTHINFO_UNAVAIL;
    }

done:
  if (ykc)
    ykclient_done (&ykc);
  if (cfg->alwaysok && retval != PAM_SUCCESS)
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
