/* Written by Simon Josefsson <simon@yubico.com>.
 * Copyright (c) 2007-2014 Yubico AB
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

#include <assert.h>

#include "../virt_ykclient.h"
#include "../virt_ldap.h"
#include "../virt_pam.h"
#define DEBUG_PAM
#include "../util.h"

int test_ldap_initialize(LDAP **ldpm, const char *uri) {
  return LDAP_SUCCESS;
}

LDAP *test_ldap_init(const char *host, int port) {
  static int dummy;
  return (LDAP*)&dummy;
}

char *test_ldap_err2string( int err ) {
  return ldap_err2string(err);
}

int test_ldap_set_option(LDAP *ld, int option, const void *invalue) {
  return LDAP_SUCCESS;
}

int test_ldap_simple_bind_s(LDAP *ld, const char *who, const char *passwd) {
  if (!strcmp(who, "administrator@ad.adviser.com") && !strcmp(passwd, "Ip^U95VHGtX*42h3")) {
    return LDAP_SUCCESS;
  }
  return LDAP_OPERATIONS_ERROR;
}

int test_ldap_search_ext_s(LDAP *ld, const char *base, int scope, const char *filter, char *attrs[], int attrsonly,
                      LDAPControl **serverctrls, LDAPControl **clientctrls, struct timeval *timeout,
                      int sizelimit, LDAPMessage **res) {
  static int test_msg;
  *res = (LDAPMessage *)&test_msg;
  return LDAP_SUCCESS;
}

LDAPMessage *test_ldap_first_entry(LDAP *ld, LDAPMessage *result) {
  //D(("test_ldap_first_entry"));
  return result;
}

char *test_ldap_first_attribute(LDAP *ld, LDAPMessage *entry, BerElement **berptr) {
  //D(("test_ldap_first_attribute"));
  return "pager";
}

char *test_ldap_next_attribute(LDAP *ld, LDAPMessage *entry, BerElement *ber) {
  //D(("test_ldap_next_attribute"));
  return 0;
}

struct berval **test_ldap_get_values_len(LDAP *ld, LDAPMessage *entry, const char *attr) {
  //D(("test_ldap_get_values_len"));
  static struct berval *ret[2];
  static struct berval val = { sizeof("ccccccdhuvvv"), "ccccccdhuvvv" };
  ret[0] = &val;
  ret[1] = 0;
  return ret;
}

int test_ldap_count_values_len(struct berval **vals) {
  //D(("test_ldap_count_values_len"));
  return 1;
}

void test_ldap_value_free_len(struct berval **vals) {
  //D(("test_ldap_value_free_len"));
}

void test_ldap_memfree(void *p) {
  //D(("test_ldap_memfree"));
}

int test_ldap_msgfree(LDAPMessage *msg ) {
  //D(("test_ldap_msgfree"));
  return LDAP_SUCCESS;
}

int test_ldap_unbind_s(LDAP *ld) {
  //D(("test_ldap_unbind_s"));
  return LDAP_SUCCESS;
}

void test_ber_free(BerElement *ber, int freebuf) {
  //D(("test_ber_free"));
}

static VirtLdap test_ldap = {
  &test_ldap_initialize,
  &test_ldap_init,
  &test_ldap_err2string,
  &test_ldap_set_option,
  &test_ldap_simple_bind_s,
  &test_ldap_search_ext_s,
  &test_ldap_first_entry,
  &test_ldap_first_attribute,
  &test_ldap_next_attribute,
  &test_ldap_get_values_len,
  &test_ldap_count_values_len,
  &test_ldap_value_free_len,
  &test_ldap_memfree,
  &test_ldap_msgfree,
  &test_ldap_unbind_s,
  &test_ber_free
};



ykclient_rc test_ykclient_init (ykclient_t ** ykc) {
  return YKCLIENT_OK;
}

void test_ykclient_done (ykclient_t ** ykc) {
}

ykclient_rc test_ykclient_request (ykclient_t * ykc, const char *yubikey_otp) {
  if (!strcmp("ccccccdhuvvvijehidgthrhtglegiiijdktvgrhgukci", yubikey_otp)) {
    return YKCLIENT_OK;
  }
  return YKCLIENT_BAD_OTP;
}

const char *test_ykclient_strerror (ykclient_rc ret) {
  return ykclient_strerror(ret);
}

ykclient_rc test_ykclient_set_client_b64 (ykclient_t * ykc, unsigned int client_id, const char *key) {
  return YKCLIENT_OK;
}

void test_ykclient_set_verify_signature (ykclient_t * ykc, int value) {
}

void test_ykclient_set_ca_path (ykclient_t * ykc, const char *ca_path) {
}

ykclient_rc test_ykclient_set_url_template (ykclient_t * ykc, const char *url_template) {
  return YKCLIENT_BAD_INPUT;
}

ykclient_rc test_ykclient_set_url_bases (ykclient_t * ykc, size_t num_templates, const char **url_templates) {
  return YKCLIENT_BAD_INPUT;
}

static VirtYkClient test_ykclient = {
  &test_ykclient_init,
  &test_ykclient_done,
  &test_ykclient_request,
  &test_ykclient_strerror,
  &test_ykclient_set_client_b64,
  &test_ykclient_set_verify_signature,
  &test_ykclient_set_ca_path,
  &test_ykclient_set_url_template,
  &test_ykclient_set_url_bases,
};

static struct TestPam {
  const char *user;
  const char *auth_ok_password;
} test_pam_instance;

const char *test_pam_strerror(PAM_STRERROR_CONST pam_handle_t *_pamh, int _error_number) {
  switch (_error_number) {
    case 0:
      return "PAM is fine";
    default:
      return "really a error";
  }
}

int test_pam_get_data(const pam_handle_t *_pamh, const char *_module_data_name, const void **_data) {
  return 0;
}

int test_pam_set_data(pam_handle_t *_pamh, const char *_module_data_name, void *_data, void (*_cleanup)(pam_handle_t *_pamh,
                  void *_data, int _pam_end_status)) {
  return 0;
}

int test_pam_get_user(pam_handle_t *_pamh, const char **_user, const char *_prompt) {
  *_user = ((struct TestPam *)_pamh)->user;
  return 0;
}

int test_pam_get_item(const pam_handle_t *_pamh, int _item_type, const void **_item) {
  if (_item_type == PAM_AUTHTOK) {
    *_item = ((struct TestPam *)_pamh)->auth_ok_password;
    return 0;
  }
  return 1;
}

int test_pam_set_item(pam_handle_t *_pamh, int _item_type, const void *_item) {
  if (_item_type == PAM_AUTHTOK) {
    ((struct TestPam *)_pamh)->auth_ok_password = _item;
    return 0;
  }
  return 1;
}

int test_pam_start(const char *_service, const char *_user, const struct pam_conv *_pam_conv, pam_handle_t **_pamh) {
  test_pam_instance.user = _user;
  *_pamh = (pam_handle_t *)&test_pam_instance;
  return 0;
}

int test_pam_modutil_drop_priv(pam_handle_t *pamh, PamModutilPrivs *p, const struct passwd *pw) {
  return 0;
}

int test_pam_modutil_regain_priv(pam_handle_t *pamh, PamModutilPrivs *p) {
  return 0;
}


static VirtPam test_pam = {
  &test_pam_strerror,
  &test_pam_get_data,
  &test_pam_set_data,
  &test_pam_get_user,
  &test_pam_get_item,
  &test_pam_set_item,
  &test_pam_start,
  &test_pam_modutil_drop_priv,
  &test_pam_modutil_regain_priv
};


// signature from pam_yubikey.c
PAM_EXTERN int pam_sm_authenticate (pam_handle_t * pamh, int flags, int argc, const char **argv);


static int my_conv(int n, const struct pam_message **msg_array, struct pam_response **response_array, void *appdata_ptr) {
  return 0;
}

void test_active_directory_login_ok(const char *otp) {
  pam_handle_t *pamh = NULL;
  int rc;

  const char *argv[] = { 
    "ldap_uri=ldap://192.168.176.13",
    "debug",
    "id=19",
    "yubi_attr=pager",
    "ldapdn=dc=ad,dc=adviser,dc=com",
    "ldap_filter=(&(sAMAccountName=%u)(memberOf=CN=Administrators,CN=Builtin,DC=ad,DC=adviser,DC=com))",
    "ldap_bind_no_anonymous",
    "ldap_bind_user_filter=%u@ad.adviser.com",
    "try_first_pass"
  };

  if (otp == 0) {
    otp = "ccccccdhuvvvijehidgthrhtglegiiijdktvgrhgukci";
    v_ykclient_inject(&test_ykclient);
    v_ldap_inject(&test_ldap);
  }

  v_pam_inject(&test_pam);
  struct pam_conv pam_conv;
  memset(&pam_conv, 0, sizeof(pam_conv));
  v_pam_start("yubico", "administrator", &pam_conv, &pamh);
  char password[128];
  strcpy(password, "Ip^U95VHGtX*42h3");
  strcat(password, otp);
  printf("password:[%s]\n", password);
  v_pam_set_item(pamh, PAM_AUTHTOK, password);
  rc = pam_sm_authenticate (pamh, 0, sizeof(argv)/sizeof(*argv), argv);
  printf ("rc %d\n", rc);
  assert(rc == 0);
}

int main (int argc, const char **argv) {
  const char *otp = argc > 1 ? argv[1] : 0;
  test_active_directory_login_ok(otp);
}

