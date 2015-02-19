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

#include "virt_test_ldap.h"
#include "virt_test_ykclient.h"
#include "virt_test_pam.h"

// signature from pam_yubikey.c
PAM_EXTERN int pam_sm_authenticate (pam_handle_t * pamh, int flags, int argc, const char **argv);


static int my_conv(int n, const struct pam_message **msg_array, struct pam_response **response_array, void *appdata_ptr) {
  return 0;
}

static const char *test_argv[] = { 
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

int test_active_directory_login(const char *user, const char *password, const char *otp) {
  pam_handle_t *pamh = NULL;
  int rc;
  v_pam_inject(&test_pam);
  struct pam_conv pam_conv;
  memset(&pam_conv, 0, sizeof(pam_conv));
  v_pam_start("yubico", user, &pam_conv, &pamh);
  char password[128];
  strcpy(password, password);
  strcat(password, otp);
  printf("password:[%s]\n", password);
  v_pam_set_item(pamh, PAM_AUTHTOK, password);
  rc = pam_sm_authenticate (pamh, 0, sizeof(test_argv)/sizeof(*test_argv), test_argv);
  printf ("rc %d\n", rc);
  return rc;
}

void test_active_directory_ask_password_plus_otp(const char *otp) {
}

void test_active_directory_ask_password_ask_otp(const char *otp) {
}

int main (int argc, const char **argv) {
  const char *test_otp = "ccccccdhuvvvijehidgthrhtglegiiijdktvgrhgukci";
  const char *otp = argc > 1 ? argv[1] : test_otp;
  if (argc > 1) {
    v_ykclient_inject(&test_ykclient);
    v_ldap_inject(&test_ldap);
  }
  const char *user = "administrator";
  const char *password = "Ip^U95VHGtX*42h3";

  assert(test_active_directory_login(user, "", "") != 0);
  assert(test_active_directory_login(user, password, "") != 0);
  assert(test_active_directory_login(user, "", otp) != 0);
  assert(test_active_directory_login(user, password, otp) == 0);
  assert(test_active_directory_login(user, "murks", otp) != 0);
  assert(test_active_directory_login(user, "murks", "ccccccdhuvvvijehidgthrhtglegiiijdktvgrhmurks") != 0);

//  test_active_directory_pass_password_ask_otp(user, otp);
//  test_active_directory_ask_password_provid_password_plus_otp(user, otp);
//  test_active_directory_ask_password_ask_otp(user, otp);
}

