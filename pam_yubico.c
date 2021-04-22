/* Written by Simon Josefsson <simon@yubico.com>.
 * Copyright (c) 2006-2019 Yubico AB
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

#define _GNU_SOURCE

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

#include "util.h"
#include "drop_privs.h"
#include "ykbzero.h"

#include <ykclient.h>

#if HAVE_CR
/* for yubikey_hex_encode */
#include <yubikey.h>
/* for yubikey pbkdf2*/
#include <ykpbkdf2.h>
#include <ykpers-version.h>
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

#define TOKEN_OTP_LEN 32u
#define MAX_TOKEN_ID_LEN 16u
#define DEFAULT_TOKEN_ID_LEN 12u

#define TMPFILE_SUFFIX ".XXXXXX"

enum key_mode {
  CHRESP,
  CLIENT
};

struct cfg
{
  unsigned int client_id;
  const char *client_key;
  int debug;
  int alwaysok;
  int verbose_otp;
  int try_first_pass;
  int use_first_pass;
  int always_prompt;
  int nullok;
  int ldap_starttls;
  int ldap_bind_as_user;
  const char *auth_file;
  const char *capath;
  const char *cainfo;
  const char *proxy;
  const char *url;
  const char *urllist;
  const char *ldapserver;
  const char *ldap_uri;
  int ldap_connection_timeout;
  const char *ldap_bind_user;
  const char *ldap_bind_password;
  const char *ldap_filter;
  const char *ldap_cacertfile;
  const char *ldapdn;
  const char *ldap_clientcertfile;
  const char *ldap_clientkeyfile;
  const char *user_attr;
  const char *yubi_attr;
  const char *yubi_attr_prefix;
  const char *mysql_server;
  int mysql_port;
  const char *mysql_user;
  const char *mysql_password;
  const char *mysql_database;

  unsigned int token_id_length;
  enum key_mode mode;
  const char *chalresp_path;
  FILE *debug_file;
};

#ifdef DBG
#undef DBG
#endif
#define DBG(x...) if (cfg->debug) { D(cfg->debug_file, x); }

/* Helper to free memory used by pam_set_data */
static void
setcred_free (pam_handle_t *pamh, void *ptr, int err)
{
  free (ptr);
}

/*
 * Authorize authenticated OTP_ID for login as USERNAME using AUTHFILE.
 *
 * Returns one of AUTH_FOUND, AUTH_NOT_FOUND, AUTH_NO_TOKENS, AUTH_ERROR.
 */
static int
authorize_user_token (struct cfg *cfg,
		      const char *username,
		      const char *otp_id,
		      pam_handle_t *pamh)
{
  int retval = AUTH_ERROR;
  if (cfg->mysql_server)
    {
#ifdef HAVE_MYSQL
      /* Administrator had configured the database and specified is name
        as an argument for this module.
      */
      DBG ("Using Mariadb or Mysql Database");
      retval = check_user_token_mysql(cfg->mysql_server, cfg->mysql_port, cfg->mysql_user, cfg->mysql_password, cfg->mysql_database, username, otp_id, cfg->debug, cfg->debug_file);
#else
      DBG (("Trying to use MYSQL, but this function is not compiled in pam_yubico!!"));
#endif
    }
  else if (cfg->auth_file)
    {
      /* Administrator had configured the file and specified is name
         as an argument for this module.
       */
      DBG ("Using system-wide auth_file %s", cfg->auth_file);
      retval = check_user_token (cfg->auth_file, username, otp_id, cfg->debug, cfg->debug_file);
    }
  else
    {
      char *userfile = NULL;
      struct passwd pass, *p;
      char buf[1024];
      size_t buflen = sizeof(buf);
      int pwres;
      PAM_MODUTIL_DEF_PRIVS(privs);
      struct stat st;

      pwres = getpwnam_r (username, &pass, buf, buflen, &p);
      if (p == NULL) {
        if (pwres == 0) {
          DBG ("User '%s' not found", username);
        } else {
          DBG ("getpwnam_r: %s", strerror(pwres));
        }
        return AUTH_ERROR;
      }

      /* Getting file from user home directory
         ..... i.e. ~/.yubico/authorized_yubikeys
       */
      if (! get_user_cfgfile_path (NULL, "authorized_yubikeys", p, &userfile)) {
	DBG ("Failed to figure out per-user cfgfile");
	return AUTH_ERROR;
      }

      DBG ("Dropping privileges");
      if(pam_modutil_drop_priv(pamh, &privs, p)) {
        DBG ("could not drop privileges");
        goto free_out;
      }

      if (lstat (userfile, &st) != 0 && errno == ENOENT) {
        retval = AUTH_NO_TOKENS;
      } else {
        retval = check_user_token (userfile, username, otp_id, cfg->debug, cfg->debug_file);
      }

      if(pam_modutil_regain_priv(pamh, &privs)) {
        DBG ("could not restore privileges");
        goto free_out;
      }

free_out:
      free (userfile);
    }

  return retval;
}

/*
 * This function will look in ldap id the token correspond to the
 * requested user.
 *
 * ldaps is only supported for ldap_uri based connections.
 * ldap_cacertfile usually needs to be set for this to work.
 *
 * ldap serve can be on a remote host.
 *
 * You need the following parameters in you pam config:
 * ldapserver=  OR ldap_uri=
 * ldapdn=
 * user_attr=
 * yubi_attr=
 *
 * If using ldap_uri, you can specify multiple failover hosts
 * eg.
 * ldap_uri=ldaps://host1.fqdn.example.com,ldaps://host2.fqdn.example.com
 *
 * Returns one of AUTH_FOUND, AUTH_NOT_FOUND, AUTH_NO_TOKENS, AUTH_ERROR.
 */
static int
authorize_user_token_ldap (struct cfg *cfg,
			   const char *user,
			   const char *token_id,
			   pam_handle_t *pamh)
{
  int retval = AUTH_ERROR;
#ifdef HAVE_LIBLDAP
  /* LDAPv2 is historical -- RFC3494. */
  int protocol = LDAP_VERSION3;
  size_t yubi_attr_prefix_len = 0;
  LDAP *ld = NULL;
  LDAPMessage *result = NULL, *e;
  BerElement *ber;
  char *attr_name;
  char *attrs[2] = {NULL, NULL};

  struct berval **vals;
  int rc;
  size_t i;
  int j;

  char *filter = NULL;
  char *find = NULL;
  int scope = LDAP_SCOPE_BASE;
#endif
  DBG(("called"));
#ifdef HAVE_LIBLDAP
  if (cfg->yubi_attr == NULL) {
    DBG (("Trying to look up user to YubiKey mapping in LDAP, but yubi_attr not set!"));
    return 0;
  }
  if (cfg->user_attr && cfg->ldapdn == NULL) {
    DBG (("Trying to look up user to YubiKey mapping in LDAP, user_attr set but ldapdn not set!"));
    return 0;
  }

  /* Get a handle to an LDAP connection. */
  if (cfg->ldap_uri)
    {
      rc = ldap_initialize (&ld, cfg->ldap_uri);
      if (rc != LDAP_SUCCESS)
	{
	  DBG ("ldap_initialize: %s", ldap_err2string (rc));
	  goto done;
	}
    }
  else
    {
      if ((ld = ldap_init (cfg->ldapserver, PORT_NUMBER)) == NULL)
	{
	  DBG ("ldap_init");
	  goto done;
	}
    }

  ldap_set_option(ld, LDAP_OPT_REFERRALS, LDAP_OPT_OFF);
  ldap_set_option (ld, LDAP_OPT_PROTOCOL_VERSION, &protocol);

  if(cfg->ldap_connection_timeout > 0) {
    struct timeval network_timeout;
    network_timeout.tv_usec = 0;
    network_timeout.tv_sec = cfg->ldap_connection_timeout;
    ldap_set_option(ld, LDAP_OPT_NETWORK_TIMEOUT, &network_timeout);
  }

  if (cfg->ldap_uri && cfg->ldap_cacertfile) {
    /* Set CA CERTFILE. This makes ldaps work when using ldap_uri */
    ldap_set_option (0, LDAP_OPT_X_TLS_CACERTFILE, cfg->ldap_cacertfile);
  }

  if (cfg->ldap_clientcertfile && cfg->ldap_clientkeyfile) {
    rc = ldap_set_option (NULL, LDAP_OPT_X_TLS_CERTFILE, cfg->ldap_clientcertfile);
    if (rc != LDAP_SUCCESS) {
      DBG ("tls_certfile: %s", ldap_err2string (rc));
      goto done;
    }
    rc = ldap_set_option (NULL, LDAP_OPT_X_TLS_KEYFILE, cfg->ldap_clientkeyfile);
    if (rc != LDAP_SUCCESS) {
      DBG ("tls_keyfile: %s", ldap_err2string (rc));
      goto done;
    }
  }

  if (cfg->ldap_starttls) {
    rc = ldap_start_tls_s (ld, NULL, NULL);
    if (rc != LDAP_SUCCESS) {
      DBG ("ldap_start_tls: %s", ldap_err2string (rc));
      goto done;
    }
  }

  /* Allocation of memory for search strings depending on input size */
  if (cfg->user_attr && cfg->yubi_attr && cfg->ldapdn) {
    i = (strlen(cfg->user_attr) + strlen(cfg->ldapdn) + strlen(user) + 3) * sizeof(char);
    if ((find = malloc(i)) == NULL) {
      DBG ("Failed allocating %zu bytes", i);
      goto done;
    }
    j = snprintf (find, i, "%s=%s,%s", cfg->user_attr, user, cfg->ldapdn);
    if (j < 0 || j >= i) {
      DBG ("Failed to format string");
      goto done;
    }
    filter = NULL;
  } else if (cfg->ldapdn) {
    find = strdup(cfg->ldapdn); /* allow free later */
  }

  /* Bind to the LDAP server. */
  if (cfg->ldap_bind_as_user && cfg->user_attr && cfg->yubi_attr && cfg->ldapdn) {
    /* Bind as the user logging in with their password they provided to PAM */
    const char *bind_password = NULL;
    rc = pam_get_item (pamh, PAM_AUTHTOK, (const void **) &bind_password);
    if (rc != PAM_SUCCESS) {
      DBG ("pam_get_item failed to retrieve password: %s", pam_strerror (pamh, rc));
      goto done;
    }
    DBG ("try bind as user with: %s", find);
    rc = ldap_simple_bind_s (ld, find, bind_password);
  } else if (cfg->ldap_bind_user && cfg->ldap_bind_password) {
    /* Bind with a provided username and password */
    DBG ("try bind with: %s:[%s]", cfg->ldap_bind_user, cfg->ldap_bind_password);
    rc = ldap_simple_bind_s (ld, cfg->ldap_bind_user, cfg->ldap_bind_password);
  } else {
    DBG ("try anonymous bind");
    rc = ldap_simple_bind_s (ld, NULL, NULL);
  }
  if (rc != LDAP_SUCCESS)
    {
      DBG ("ldap_simple_bind_s: %s", ldap_err2string (rc));
      goto done;
    }

  if (cfg->ldap_filter) {
    filter = filter_printf(cfg->ldap_filter, user);
    scope = LDAP_SCOPE_SUBTREE;
  }
  attrs[0] = (char *) cfg->yubi_attr;

  DBG("LDAP : look up object base='%s' filter='%s', ask for attribute '%s'", find,
      filter ? filter:"(null)", cfg->yubi_attr);

  /* Search for the entry. */
  if ((rc = ldap_search_ext_s (ld, find, scope,
			       filter, attrs, 0, NULL, NULL, LDAP_NO_LIMIT,
			       LDAP_NO_LIMIT, &result)) != LDAP_SUCCESS)
    {
      DBG ("ldap_search_ext_s: %s", ldap_err2string (rc));

      goto done;
    }

  /* Start looing for tokens */
  retval = AUTH_NO_TOKENS;

  e = ldap_first_entry (ld, result);
  if (e == NULL)
    {
      DBG (("No result from LDAP search"));
    }
  else
    {
      /* Iterate through each returned attribute. */
      for (attr_name = ldap_first_attribute (ld, e, &ber);
	   attr_name != NULL; attr_name = ldap_next_attribute (ld, e, ber))
	{
	  if (strcmp(attr_name, cfg->yubi_attr) != 0) {
	      DBG("Ignored non-requested attribute: %s", attr_name);
	      continue;
	  }
	  if ((vals = ldap_get_values_len (ld, e, attr_name)) != NULL)
	    {
	      yubi_attr_prefix_len = cfg->yubi_attr_prefix ? strlen(cfg->yubi_attr_prefix) : 0;

	      DBG("LDAP : Found %i values for %s - checking if any of them match '%s:%s'",
	          ldap_count_values_len(vals),
	          attr_name,
	          cfg->yubi_attr_prefix ? cfg->yubi_attr_prefix : "",
	          token_id ? token_id : "(null)");

	      /* Compare each value for the attribute against the token id. */
	      for (i = 0; vals[i] != NULL; i++)
		{
		  DBG("LDAP : Checking value %zu: %s:%s",
		      i + 1,
		      cfg->yubi_attr_prefix ? cfg->yubi_attr_prefix : "",
		      vals[i]->bv_val);

		  /* Only values containing this prefix are considered. */
		  if ((!cfg->yubi_attr_prefix || !strncmp (cfg->yubi_attr_prefix, vals[i]->bv_val, yubi_attr_prefix_len)))
		    {
		      /* We have found at least one possible token ID so change the default return value to AUTH_NOT_FOUND */
		      if (retval == AUTH_NO_TOKENS)
		        {
		          retval = AUTH_NOT_FOUND;
		        }
		      if(token_id && !strncmp(token_id, vals[i]->bv_val + yubi_attr_prefix_len, cfg->token_id_length))
		        {
		          DBG ("Token found :: %s", vals[i]->bv_val);
		          retval = AUTH_FOUND;
		        }
		    }
		}
	      ldap_value_free_len (vals);
	    }
	  ldap_memfree (attr_name);
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
  if (filter != NULL)
    free(filter);

#else
  DBG (("Trying to use LDAP, but this function is not compiled in pam_yubico!!"));
  DBG (("Install libldap-dev and then recompile pam_yubico."));
#endif
  return retval;
}

#if HAVE_CR
static int
display_error(pam_handle_t *pamh, const char *message, struct cfg *cfg) {
  struct pam_conv *conv;
  const struct pam_message *pmsg[1];
  struct pam_message msg[1];
  struct pam_response *resp = NULL;
  int retval;

  retval = pam_get_item (pamh, PAM_CONV, (const void **) &conv);
  if (retval != PAM_SUCCESS) {
    DBG("get conv returned error: %s", pam_strerror (pamh, retval));
    return retval;
  }

  if(!conv || !conv->conv){
    DBG("conv() function invalid");
    return PAM_CONV_ERR;
  }
  pmsg[0] = &msg[0];
  msg[0].msg = (char *) message; /* on some systems, pam_message.msg isn't const */
  msg[0].msg_style = PAM_ERROR_MSG;
  retval = conv->conv(1, pmsg, &resp, conv->appdata_ptr);

  if (retval != PAM_SUCCESS) {
    DBG("conv returned error: %s", pam_strerror (pamh, retval));
    return retval;
  }

  if (resp)
    {
      DBG("conv returned: '%s'", resp->resp);
      if (resp->resp)
        free (resp->resp);
      free (resp);
    }
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

  struct passwd pass, *p;
  char pwbuf[1024];
  size_t pwbuflen = sizeof(pwbuf);
  int pwres;

  struct stat st;

  /* we must declare two sepparate privs structures as they can't be reused */
  PAM_MODUTIL_DEF_PRIVS(privs);
  PAM_MODUTIL_DEF_PRIVS(privs2);

  ret = PAM_AUTH_ERR;

  pwres = getpwnam_r (username, &pass, pwbuf, pwbuflen, &p);
  if (p == NULL) {
      if (pwres == 0) {
          DBG ("User '%s' not found", username);
      } else {
          DBG ("getpwnam_r: %s", strerror(pwres));
      }
      goto out;
  }

  DBG("Checking for user challenge files");
  switch(check_user_challenge_file(cfg->chalresp_path, p, cfg->debug_file)) {
    case AUTH_FOUND:
      DBG("Challenge files found");
      break;
    case AUTH_NOT_FOUND:
      DBG("No challenge files found");
      if (cfg->nullok) {
        ret = PAM_IGNORE;
      } else {
        ret = PAM_USER_UNKNOWN;
      }
      goto out;
    case AUTH_ERROR:
      DBG ("Internal error while looking for user challenge files");
      ret = PAM_AUTHINFO_UNAVAIL;
      goto out;
    default:
      DBG ("Unhandled value while looking for user challenge files");
      ret = PAM_AUTHINFO_UNAVAIL;
      goto out;
  }

  if (! init_yubikey(&yk)) {
    DBG("Failed to initialize YubiKey");
    goto out;
  }

  if (! check_firmware_version(yk, cfg->debug, true, cfg->debug_file)) {
    DBG("YubiKey does not support Challenge-Response (version 2.2 required)");
    goto out;
  }

  if (! get_user_challenge_file (yk, cfg->chalresp_path, p, &userfile, cfg->debug_file)) {
    DBG("Failed to get user challenge file for user %s", username);
    goto out;
  }

  DBG("Loading challenge from file %s", userfile);

  /* Drop privileges before opening user file (if we're not using system-wide dir). */
  if (!cfg->chalresp_path) {
    if (pam_modutil_drop_priv(pamh, &privs, p)) {
      DBG ("Could not drop privileges");
      goto out;
    }
  }

  fd = open(userfile, O_RDONLY | O_CLOEXEC, 0);
  if (fd < 0) {
      DBG ("Cannot open file: %s (%s)", userfile, strerror(errno));
      goto restpriv_out;
  }

  if (fstat(fd, &st) < 0) {
      DBG ("Cannot stat file: %s (%s)", userfile, strerror(errno));
      close(fd);
      goto restpriv_out;
  }

  if (!S_ISREG(st.st_mode)) {
      DBG ("%s is not a regular file", userfile);
      close(fd);
      goto restpriv_out;
  }

  f = fdopen(fd, "r");
  if (f == NULL) {
      DBG ("fdopen: %s", strerror(errno));
      close(fd);
      goto restpriv_out;
  }

  if (! load_chalresp_state(f, &state, cfg->debug, cfg->debug_file))
    goto restpriv_out;

  if (fclose(f) < 0) {
    f = NULL;
    goto restpriv_out;
  }
  f = NULL;

  if (!cfg->chalresp_path) {
    if (pam_modutil_regain_priv(pamh, &privs)) {
      DBG ("Could not restore privileges");
      goto out;
    }
  }

  if (! challenge_response(yk, state.slot, state.challenge, state.challenge_len,
			   true, true, false,
			   buf, sizeof(buf), &response_len)) {
    DBG("Challenge-response failed");
    goto out;
  }

  /*
   * Check YubiKey response against the expected response
   */

  yubikey_hex_encode(response_hex, buf, response_len);
  if(state.salt_len > 0) { /* the expected response has gone through pbkdf2 */
    YK_PRF_METHOD prf_method = {20, yk_hmac_sha1};
    yk_pbkdf2(response_hex, (unsigned char*)state.salt, state.salt_len, state.iterations,
        (unsigned char*)buf, response_len, &prf_method);
  }

  if (memcmp(buf, state.response, state.response_len) == 0) {
    ret = PAM_SUCCESS;
  } else {
    DBG("Unexpected response: %s", response_hex);
    goto out;
  }

  DBG("Got the expected response, generating new challenge (%u bytes).", CR_CHALLENGE_SIZE);

  errstr = "Error generating new challenge, please check syslog or contact your system administrator";
  if (generate_random(state.challenge, sizeof(state.challenge))) {
    DBG("Failed to generate new challenge!");
    goto out;
  }

  errstr = "Error communicating with YubiKey, please check syslog or contact your system administrator";
  if (! challenge_response(yk, state.slot, state.challenge, CR_CHALLENGE_SIZE,
			   true, true, false,
			   buf, sizeof(buf), &response_len)) {
    DBG("Second challenge-response failed");
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
  errstr = "Error updating YubiKey challenge, please check syslog or contact your system administrator";
  if (response_len > sizeof(state.response)) {
    DBG("Got too long response ??? (%u/%zu)", response_len, sizeof(state.response));
    goto out;
  }
  memcpy (state.response, buf, response_len);
  state.response_len = response_len;

  /* point to the fresh privs structure.. */
  privs = privs2;
  /* Drop privileges before creating new challenge file. */
  if (!cfg->chalresp_path) {
    if (pam_modutil_drop_priv(pamh, &privs, p)) {
        DBG ("Could not drop privileges");
        goto out;
    }
  }

  /* Write out the new file */
  tmpfile = malloc(strlen(userfile) + 1 + strlen(TMPFILE_SUFFIX));
  if (! tmpfile)
    goto restpriv_out;
  strcpy(tmpfile, userfile);
  strcat(tmpfile, TMPFILE_SUFFIX);

  fd = mkostemp(tmpfile, O_CLOEXEC);
  if (fd < 0) {
      DBG ("Cannot open file: %s (%s)", tmpfile, strerror(errno));
      goto restpriv_out;
  }

  if (fchmod (fd, st.st_mode) != 0) {
      DBG ("Could not set correct file permissions");
      goto restpriv_out;
  }
  if (fchown (fd, st.st_uid, st.st_gid) != 0) {
      DBG ("Could not set correct file ownership");
      goto restpriv_out;
  }

  f = fdopen(fd, "w");
  if (! f) {
    close(fd);
    goto restpriv_out;
  }

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

  DBG(("Challenge-response success!"));
  errstr = NULL;
  errno = 0;
  yk_errno = 0;

restpriv_out:
  if (!cfg->chalresp_path) {
    if (pam_modutil_regain_priv(pamh, &privs)) {
        DBG (("Could not restore privileges"));
    }
  }

 out:
  if (yk_errno) {
    if (yk_errno == YK_EUSBERR) {
      syslog(LOG_ERR, "USB error: %s", yk_usb_strerror());
      DBG("USB error: %s", yk_usb_strerror());
    } else {
      syslog(LOG_ERR, "YubiKey core error: %s", yk_strerror(yk_errno));
      DBG("YubiKey core error: %s", yk_strerror(yk_errno));
    }
  }

  if (errstr)
    display_error(pamh, errstr, cfg);

  if (errno) {
    syslog(LOG_ERR, "Challenge-response failed: %s", strerror(errno));
    DBG("Challenge-response failed: %s", strerror(errno));
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
  struct stat st;
  FILE *file = NULL;
  int fd = -1;
  int i;

  memset (cfg, 0, sizeof(struct cfg));
  cfg->client_id = 0;
  cfg->token_id_length = DEFAULT_TOKEN_ID_LEN;
  cfg->mode = CLIENT;
  cfg->debug_file = stdout;

  for (i = 0; i < argc; i++)
    {
      if (strncmp (argv[i], "id=", 3) == 0)
	sscanf (argv[i], "id=%u", &cfg->client_id);
      if (strncmp (argv[i], "key=", 4) == 0)
	cfg->client_key = argv[i] + 4;
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
      if (strcmp (argv[i], "always_prompt") == 0)
	cfg->always_prompt = 1;
      if (strcmp (argv[i], "nullok") == 0)
	cfg->nullok = 1;
      if (strcmp (argv[i], "ldap_starttls") == 0)
	cfg->ldap_starttls = 1;
      if (strcmp (argv[i], "ldap_bind_as_user") == 0)
	cfg->ldap_bind_as_user = 1;
      if (strncmp (argv[i], "authfile=", 9) == 0)
	cfg->auth_file = argv[i] + 9;
      if (strncmp (argv[i], "capath=", 7) == 0)
	cfg->capath = argv[i] + 7;
      if (strncmp (argv[i], "cainfo=", 7) == 0)
        cfg->cainfo = argv[i] + 7;
      if (strncmp (argv[i], "proxy=", 6) == 0)
	cfg->proxy = argv[i] + 6;
      if (strncmp (argv[i], "url=", 4) == 0)
	cfg->url = argv[i] + 4;
      if (strncmp (argv[i], "urllist=", 8) == 0)
	cfg->urllist = argv[i] + 8;
      if (strncmp (argv[i], "ldapserver=", 11) == 0)
	cfg->ldapserver = argv[i] + 11;
      if (strncmp (argv[i], "ldap_uri=", 9) == 0)
	cfg->ldap_uri = argv[i] + 9;
      if (strncmp (argv[i], "ldap_connection_timeout=", 24) == 0)
	sscanf (argv[i], "ldap_connection_timeout=%u", &cfg->ldap_connection_timeout);
      if (strncmp (argv[i], "ldap_bind_user=", 15) == 0)
	cfg->ldap_bind_user = argv[i] + 15;
      if (strncmp (argv[i], "ldap_bind_password=", 19) == 0)
	cfg->ldap_bind_password = argv[i] + 19;
      if (strncmp (argv[i], "ldap_filter=", 12) == 0)
	cfg->ldap_filter = argv[i] + 12;
      if (strncmp (argv[i], "ldap_cacertfile=", 16) == 0)
        cfg->ldap_cacertfile = argv[i] + 16;
      if (strncmp (argv[i], "ldap_clientcertfile=", 20) == 0)
        cfg->ldap_clientcertfile = argv[i] + 20;
      if (strncmp (argv[i], "ldap_clientkeyfile=", 19) == 0)
        cfg->ldap_clientkeyfile = argv[i] + 19;
      if (strncmp (argv[i], "ldapdn=", 7) == 0)
	cfg->ldapdn = argv[i] + 7;
      if (strncmp (argv[i], "user_attr=", 10) == 0)
	cfg->user_attr = argv[i] + 10;
      if (strncmp (argv[i], "yubi_attr=", 10) == 0)
	cfg->yubi_attr = argv[i] + 10;
      if (strncmp (argv[i], "yubi_attr_prefix=", 17) == 0)
	cfg->yubi_attr_prefix = argv[i] + 17;
      if (strncmp (argv[i], "token_id_length=", 16) == 0)
	sscanf (argv[i], "token_id_length=%u", &cfg->token_id_length);
      if (strcmp (argv[i], "mode=challenge-response") == 0)
	cfg->mode = CHRESP;
      if (strcmp (argv[i], "mode=client") == 0)
	cfg->mode = CLIENT;
      if (strncmp (argv[i], "chalresp_path=", 14) == 0)
	cfg->chalresp_path = argv[i] + 14;
      if (strncmp (argv[i], "mysql_server=", 13) == 0)
	cfg->mysql_server = argv[i] + 13;
      if (strncmp (argv[i], "mysql_port=", 11) == 0)
	sscanf (argv[i], "mysql_port=%u", &cfg->mysql_port);
      if (strncmp (argv[i], "mysql_user=", 11) == 0)
	cfg->mysql_user = argv[i] + 11;
      if (strncmp (argv[i], "mysql_password=", 15) == 0)
	cfg->mysql_password = argv[i] + 15;
      if (strncmp (argv[i], "mysql_database=", 15) == 0)
	cfg->mysql_database = argv[i] + 15;

      if (strncmp (argv[i], "debug_file=", 11) == 0)
        {
          const char *filename = argv[i] + 11;
          if(strncmp (filename, "stdout", 6) == 0)
            {
              cfg->debug_file = stdout;
            }
          else if(strncmp (filename, "stderr", 6) == 0)
            {
              cfg->debug_file = stderr;
            }
          else
            {
              fd = open(filename, O_WRONLY | O_APPEND | O_CLOEXEC | O_NOFOLLOW | O_NOCTTY);
              if (fd >= 0 && (fstat(fd, &st) == 0) && S_ISREG(st.st_mode))
                {
                  file = fdopen(fd, "a");
                  if(file != NULL)
                    {
                      cfg->debug_file = file;
                      file = NULL;
                      fd = -1;
                    }
                }
            }
        }
    }

  DBG ("called.");
  DBG ("flags %d argc %d", flags, argc);
  for (i = 0; i < argc; i++)
    DBG ("argv[%d]=%s", i, argv[i]);
  DBG ("id=%u", cfg->client_id);
  DBG ("key=%s", cfg->client_key ? cfg->client_key : "(null)");
  DBG ("debug=%d", cfg->debug);
  DBG ("debug_file=%d", fileno(cfg->debug_file));
  DBG ("alwaysok=%d", cfg->alwaysok);
  DBG ("verbose_otp=%d", cfg->verbose_otp);
  DBG ("try_first_pass=%d", cfg->try_first_pass);
  DBG ("use_first_pass=%d", cfg->use_first_pass);
  DBG ("always_prompt=%d", cfg->always_prompt);
  DBG ("nullok=%d", cfg->nullok);
  DBG ("ldap_starttls=%d", cfg->ldap_starttls);
  DBG ("ldap_bind_as_user=%d", cfg->ldap_bind_as_user);
  DBG ("authfile=%s", cfg->auth_file ? cfg->auth_file : "(null)");
  DBG ("ldapserver=%s", cfg->ldapserver ? cfg->ldapserver : "(null)");
  DBG ("ldap_uri=%s", cfg->ldap_uri ? cfg->ldap_uri : "(null)");
  DBG ("ldap_connection_timeout=%d", cfg->ldap_connection_timeout);
  DBG ("ldap_bind_user=%s", cfg->ldap_bind_user ? cfg->ldap_bind_user : "(null)");
  DBG ("ldap_bind_password=%s", cfg->ldap_bind_password ? cfg->ldap_bind_password : "(null)");
  DBG ("ldap_filter=%s", cfg->ldap_filter ? cfg->ldap_filter : "(null)");
  DBG ("ldap_cacertfile=%s", cfg->ldap_cacertfile ? cfg->ldap_cacertfile : "(null)");
  DBG ("ldapdn=%s", cfg->ldapdn ? cfg->ldapdn : "(null)");
  DBG ("ldap_clientcertfile=%s", cfg->ldap_clientcertfile ? cfg->ldap_clientcertfile : "(null)");
  DBG ("ldap_clientkeyfile=%s", cfg->ldap_clientkeyfile ? cfg->ldap_clientkeyfile : "(null)");
  DBG ("user_attr=%s", cfg->user_attr ? cfg->user_attr : "(null)");
  DBG ("yubi_attr=%s", cfg->yubi_attr ? cfg->yubi_attr : "(null)");
  DBG ("yubi_attr_prefix=%s", cfg->yubi_attr_prefix ? cfg->yubi_attr_prefix : "(null)");
  DBG ("url=%s", cfg->url ? cfg->url : "(null)");
  DBG ("urllist=%s", cfg->urllist ? cfg->urllist : "(null)");
  DBG ("capath=%s", cfg->capath ? cfg->capath : "(null)");
  DBG ("cainfo=%s", cfg->cainfo ? cfg->cainfo : "(null)");
  DBG ("proxy=%s", cfg->proxy ? cfg->proxy : "(null)");
  DBG ("token_id_length=%u", cfg->token_id_length);
  DBG ("mode=%s", cfg->mode == CLIENT ? "client" : "chresp" );
  DBG ("chalresp_path=%s", cfg->chalresp_path ? cfg->chalresp_path : "(null)");
  DBG ("mysql_server=%s", cfg->mysql_server ? cfg->mysql_server : "(null)");
  DBG ("mysql_port=%d", cfg->mysql_port);
  DBG ("mysql_user=%s", cfg->mysql_user ? cfg->mysql_user : "(null)");
  DBG ("mysql_database=%s", cfg->mysql_database ? cfg->mysql_database : "(null)");

  if (fd != -1)
    close(fd);

  if (file != NULL)
    fclose(file);
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
  size_t password_len = 0;
  int skip_bytes = 0;
  int valid_token = 0;
  struct pam_conv *conv;
  const struct pam_message *pmsg[1];
  struct pam_message msg[1] = {{0}};
  struct pam_response *resp = NULL;
  int nargs = 1;
  ykclient_t *ykc = NULL;
  struct cfg cfg_st;
  struct cfg *cfg = &cfg_st; /* for DBG macro */
  size_t templates = 0;
  char *urls[10];
  char *tmpurl = NULL;
  char *onlypasswd = NULL;

  parse_cfg (flags, argc, argv, cfg);

  DBG ("pam_yubico version: %s", VERSION);

  if (cfg->token_id_length > MAX_TOKEN_ID_LEN)
  {
    DBG ("Configuration error: token_id_length too long. Maximum acceptable value : %u", MAX_TOKEN_ID_LEN);
    retval = PAM_AUTHINFO_UNAVAIL;
    goto done;
  }

  retval = pam_get_user (pamh, &user, NULL);
  if (retval != PAM_SUCCESS)
    {
      DBG ("get user returned error: %s", pam_strerror (pamh, retval));
      goto done;
    }
  DBG ("get user returned: %s", user);

  if (cfg->mode == CHRESP) {
#if HAVE_CR
    DBG ("libykpers version: %s", ykpers_check_version(NULL));
    retval = do_challenge_response(pamh, cfg, user);
#else
    DBG ("no support for challenge-response");
    retval = PAM_AUTH_ERR;
#endif
    goto done;
  }

  if (cfg->try_first_pass || cfg->use_first_pass)
    {
      retval = pam_get_item (pamh, PAM_AUTHTOK, (const void **) &password);
      if (retval != PAM_SUCCESS)
	{
	  DBG ("get password returned error: %s",
	      pam_strerror (pamh, retval));
	  goto done;
	}
      DBG ("get password returned: /* not logged */");
    }

  if (cfg->use_first_pass && password == NULL)
    {
      DBG ("use_first_pass set and no password, giving up");
      retval = PAM_AUTH_ERR;
      goto done;
    }

  if(ykclient_global_init() != YKCLIENT_OK)
    {
      DBG ("Failed to initlaize ykclient library");
      retval = PAM_AUTHINFO_UNAVAIL;
      goto done;
    }
  rc = ykclient_init (&ykc);
  if (rc != YKCLIENT_OK)
    {
      DBG ("ykclient_init() failed (%d): %s", rc, ykclient_strerror (rc));
      retval = PAM_AUTHINFO_UNAVAIL;
      goto done;
    }

  rc = ykclient_set_client_b64 (ykc, cfg->client_id, cfg->client_key);
  if (rc != YKCLIENT_OK)
    {
      DBG ("ykclient_set_client_b64() failed (%d): %s",
	    rc, ykclient_strerror (rc));
      retval = PAM_AUTHINFO_UNAVAIL;
      goto done;
    }

  if (cfg->client_key)
    ykclient_set_verify_signature (ykc, 1);

  if (cfg->capath)
    ykclient_set_ca_path (ykc, cfg->capath);

  if (cfg->cainfo)
    ykclient_set_ca_info (ykc, cfg->cainfo);

  if (cfg->proxy)
    ykclient_set_proxy (ykc, cfg->proxy);

  if (cfg->url)
    {
      rc = ykclient_set_url_template (ykc, cfg->url);
      if (rc != YKCLIENT_OK)
	{
	  DBG ("ykclient_set_url_template() failed (%d): %s",
		rc, ykclient_strerror (rc));
	  retval = PAM_AUTHINFO_UNAVAIL;
	  goto done;
	}
    }

  if (cfg->urllist)
    {
      char *saveptr = NULL;
      char *part = NULL;
      tmpurl = strdup(cfg->urllist);

      while ((part = strtok_r(templates == 0 ? tmpurl : NULL, ";", &saveptr)))
	{
	  if(templates == 10)
	    {
	      DBG ("maximum 10 urls supported in list.");
	      retval = PAM_AUTHINFO_UNAVAIL;
	      goto done;
	    }
	  urls[templates] = strdup(part);
	  templates++;
	}
      rc = ykclient_set_url_bases (ykc, templates, (const char **)urls);
      if (rc != YKCLIENT_OK)
	{
	  DBG ("ykclient_set_url_bases() failed (%d): %s",
		rc, ykclient_strerror (rc));
	  retval = PAM_AUTHINFO_UNAVAIL;
	  goto done;
	}
    }
  /* check if the user has at least one associated token id */
  /* we set otp_id to NULL so that no matches will ever be found
   * but AUTH_NO_TOKENS will be returned if there are no tokens for the user */
  if (!cfg->always_prompt) {
    if (cfg->ldapserver != NULL || cfg->ldap_uri != NULL)
      valid_token = authorize_user_token_ldap (cfg, user, NULL, pamh);
    else
      valid_token = authorize_user_token (cfg, user, NULL, pamh);

    switch(valid_token)
      {
      case AUTH_ERROR:
        DBG ("Internal error while looking for user tokens");
        retval = PAM_AUTHINFO_UNAVAIL;
        goto done;
      case AUTH_NOT_FOUND:
        /* User has associated tokens, so continue */
        DBG ("Tokens found for user");
        break;
      case AUTH_NO_TOKENS:
        DBG ("No tokens found for user");
        if (cfg->nullok) {
          retval = PAM_IGNORE;
        } else {
          retval = PAM_USER_UNKNOWN;
        }
        goto done;
      default:
        DBG ("Unhandled value while looking for user tokens");
        retval = PAM_AUTHINFO_UNAVAIL;
        goto done;
      }
  }

  if (password == NULL)
    {
      retval = pam_get_item (pamh, PAM_CONV, (const void **) &conv);
      if (retval != PAM_SUCCESS)
	{
	  DBG ("get conv returned error: %s", pam_strerror (pamh, retval));
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

      retval = conv->conv (nargs, pmsg, &resp, conv->appdata_ptr);

      if (retval != PAM_SUCCESS)
	{
	  DBG ("conv returned error: %s", pam_strerror (pamh, retval));
	  goto done;
	}

      if (resp->resp == NULL)
	{
	  DBG ("conv returned NULL passwd?");
	  retval = PAM_AUTH_ERR;
	  goto done;
	}

      DBG ("conv returned %zu bytes", strlen(resp->resp));

      password = resp->resp;
    }

  password_len = strlen (password);

  /* In case the input was systempassword+OTP, we want to skip over
     "systempassword" when copying the token_id and OTP to separate buffers */
  if(password_len > cfg->token_id_length + TOKEN_OTP_LEN)
    {
      skip_bytes = password_len - (cfg->token_id_length + TOKEN_OTP_LEN);
    }

  DBG ("Skipping first %i bytes. Length is %zu, token_id set to %u and token OTP always %u.",
	skip_bytes, password_len, cfg->token_id_length, TOKEN_OTP_LEN);

  /* Copy full YubiKey output (public ID + OTP) into otp */
  strncpy (otp, password + skip_bytes, sizeof (otp) - 1);
  /* Copy only public ID into otp_id. Destination buffer is zeroed. */
  strncpy (otp_id, password + skip_bytes, cfg->token_id_length);

  /* user entered their system password followed by generated OTP? */
  if (password_len > TOKEN_OTP_LEN + cfg->token_id_length)
    {
      onlypasswd = strdup (password);

      if (! onlypasswd) {
	retval = PAM_BUF_ERR;
	goto done;
      }

      onlypasswd[password_len - (TOKEN_OTP_LEN + cfg->token_id_length)] = '\0';

      DBG ("Extracted a probable system password entered before the OTP - "
	    "setting item PAM_AUTHTOK");

      retval = pam_set_item (pamh, PAM_AUTHTOK, onlypasswd);
      if (retval != PAM_SUCCESS)
	{
	  DBG ("set_item returned error: %s", pam_strerror (pamh, retval));
	  goto done;
	}
    }
  else
    password = NULL;

  /* authorize the user with supplied token id */
  if (cfg->ldapserver != NULL || cfg->ldap_uri != NULL)
    valid_token = authorize_user_token_ldap (cfg, user, otp_id, pamh);
  else
    valid_token = authorize_user_token (cfg, user, otp_id, pamh);

  switch(valid_token)
    {
    case AUTH_FOUND:
      DBG ("OTP: %s ID: %s ", otp, otp_id);
      DBG ("Token is associated to the user. Validating the OTP...");
      rc = ykclient_request (ykc, otp);
      DBG ("ykclient return value (%d): %s", rc, ykclient_strerror (rc));
      DBG ("ykclient URL used: %s", ykclient_get_last_url(ykc));

      switch (rc)
      {
        case YKCLIENT_OK:
          retval = PAM_SUCCESS;
          break;

        case YKCLIENT_BAD_OTP:
        case YKCLIENT_REPLAYED_OTP:
          retval = PAM_AUTH_ERR;
          break;

        default:
          retval = PAM_AUTHINFO_UNAVAIL;
          break;
      }
      break;
    case AUTH_ERROR:
      DBG ("Internal error while looking for user tokens");
      retval = PAM_AUTHINFO_UNAVAIL;
      break;
    case AUTH_NOT_FOUND:
      DBG ("Unauthorized token for this user");
      retval = PAM_AUTH_ERR;
      break;
    case AUTH_NO_TOKENS:
      DBG ("No tokens found for user");
      if (cfg->nullok) {
        retval = PAM_IGNORE;
      } else {
        retval = PAM_USER_UNKNOWN;
      }
      break;
    default:
      DBG ("Unhandled value for token-user validation");
      retval = PAM_AUTHINFO_UNAVAIL;
      break;
    }

done:
  if (onlypasswd)
    {
      insecure_memzero(onlypasswd, strlen(onlypasswd));
      free(onlypasswd);
    }
  insecure_memzero(otp, sizeof(otp));
  insecure_memzero(otp_id, sizeof(otp_id));
  if (templates > 0)
    {
      size_t i;
      for(i = 0; i < templates; i++)
        {
	  free(urls[i]);
        }
    }
  if (tmpurl)
    free(tmpurl);
  if (ykc)
    {
      ykclient_done (&ykc);
      ykclient_global_done();
    }
  if (cfg->alwaysok && retval != PAM_SUCCESS)
    {
      DBG ("alwaysok needed (otherwise return with %d)", retval);
      retval = PAM_SUCCESS;
    }
  DBG ("done. [%s]", pam_strerror (pamh, retval));

  int* pretval = malloc (sizeof(int));
  if (pretval)
    {
      *pretval = retval;
      if (pam_set_data (pamh, "yubico_setcred_return", (void*)pretval,
	   setcred_free) != PAM_SUCCESS)
        {
          DBG ("pam_set_data failed setting setcred_return: %d", retval);
        }
    }
  else
    {
	DBG ("Failed allocating memory for setcred_return status");
    }

  if (resp)
    {
      if (resp->resp)
        free (resp->resp);
      free (resp);
    }

  if(msg[0].msg)
    {
      free((char*)msg[0].msg);
    }

  if(cfg->debug_file != stderr && cfg->debug_file != stdout)
    {
      fclose(cfg->debug_file);
    }

  return retval;
}

PAM_EXTERN int
pam_sm_setcred (
    pam_handle_t *pamh __attribute__((unused)), int flags __attribute__((unused)),
    int argc __attribute__((unused)), const char *argv[] __attribute__((unused)))
{
  return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
  struct cfg cfg_st;
  struct cfg *cfg = &cfg_st; /* for DBG macro */
  int retval = PAM_AUTH_ERR;
  const void *pretval = NULL;
  int rc = pam_get_data (pamh, "yubico_setcred_return", &pretval);

  parse_cfg (flags, argc, argv, cfg);
  if (rc == PAM_SUCCESS && pretval && *(const int *)pretval == PAM_SUCCESS) {
    DBG ("pam_sm_acct_mgmt returning PAM_SUCCESS");
    retval = PAM_SUCCESS;
  } else {
    DBG ("pam_sm_acct_mgmt returning PAM_AUTH_ERR:%d", rc);
    retval = PAM_AUTH_ERR;
  }

  if(cfg->debug_file != stderr && cfg->debug_file != stdout) {
    fclose(cfg->debug_file);
  }

  return retval;
}

PAM_EXTERN int
pam_sm_open_session(
    pam_handle_t *pamh __attribute__((unused)), int flags __attribute__((unused)),
    int argc __attribute__((unused)), const char *argv[] __attribute__((unused)))
{

  return (PAM_SUCCESS);
}

PAM_EXTERN int
pam_sm_close_session(
    pam_handle_t *pamh __attribute__((unused)), int flags __attribute__((unused)),
    int argc __attribute__((unused)), const char *argv[] __attribute__((unused)))
{
  return (PAM_SUCCESS);
}

PAM_EXTERN int
pam_sm_chauthtok(
    pam_handle_t *pamh __attribute__((unused)), int flags __attribute__((unused)),
    int argc __attribute__((unused)), const char *argv[] __attribute__((unused)))
{
  return (PAM_SERVICE_ERR);
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
