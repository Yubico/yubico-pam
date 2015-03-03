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


static  const char *test_otp = "ccccccdhuvvvijehidgthrhtglegiiijdktvgrhgukci";
static  const char *password = "Ip^U95VHGtX*42h3";

static const char *try_first_pass_test_argv[] = { 
    "ldap_uri=ldap://192.168.176.13",
    "debug",
    "id=19",
    "yubi_attr=pager",
    "ldapdn=dc=ad,dc=adviser,dc=com",
    "ldap_filter=(&(sAMAccountName=%u)(memberOf=CN=Administrators,CN=Builtin,DC=ad,DC=adviser,DC=com))",
    "ldap_bind_no_anonymous",
    "ldap_bind_user_filter=%u@ad.adviser.com",
    "try_first_pass",
    0
  };

static const char *test_argv[] = { 
    "ldap_uri=ldap://192.168.176.13",
    "debug",
    "id=19",
    "yubi_attr=pager",
    "ldapdn=dc=ad,dc=adviser,dc=com",
    "ldap_filter=(&(sAMAccountName=%u)(memberOf=CN=Administrators,CN=Builtin,DC=ad,DC=adviser,DC=com))",
    "ldap_bind_no_anonymous",
    "ldap_bind_user_filter=%u@ad.adviser.com",
    "use_first_pass",
    0
  };

static int ask_stdin_yubikey = 0;
char *ask_yubikey() {
  if (ask_stdin_yubikey) {
    printf("mock-ask_yubikey:");
    char buf[1024];
    char *pos =  fgets(buf, sizeof(buf)-1, stdin);
    if ((pos=strchr(buf, '\n')) != NULL)
      *pos = '\0';
    return strdup(buf);
  } else {
    printf("mock-ask_yubikey:%s\n", test_otp);
    return strdup(test_otp);
  }
}

static int ask_password_state = 0;
int ask_password(int num_msg, const struct pam_message **msg, struct pam_response **resp, void *appdata_ptr) {
  if (num_msg > 0) {
    if (!strcmp("password: ", msg[0]->msg)) {
      struct pam_response *data = malloc(sizeof(struct pam_response));
      data->resp = strdup(password);
      printf("mock-ask_password:%s:%s\n", msg[0]->msg, data->resp);
      *resp = data;
      ask_password_state |= 0x1;
      return PAM_SUCCESS;
    } else if (!strcmp("yubikey: ", msg[0]->msg)) {
      struct pam_response *data = malloc(sizeof(struct pam_response));
      data->resp = ask_yubikey();
      *resp = data;
      ask_password_state |= 0x2;
      return PAM_SUCCESS;
    }
  }
  return PAM_CONV_ERR;
}

int test_active_directory_login(const char **argv, const char *user, const char *password, const char *otp) {
  ask_password_state = 0;
  pam_handle_t *pamh = NULL;
  int rc;
  v_pam_inject(&test_pam);
  struct pam_conv pam_conv;
  memset(&pam_conv, 0, sizeof(pam_conv));
  pam_conv.conv = ask_password;
  v_pam_start("yubico", user, &pam_conv, &pamh);
  char tmp[strlen(password)+strlen(otp)+1];
  strcpy(tmp, password);
  strcat(tmp, otp);
  printf("password:[%s]\n", tmp);
  v_pam_set_item(pamh, PAM_AUTHTOK, tmp);
  int argc;
  for (argc = 0; argv[argc]; ++argc) {
  }
  rc = pam_sm_authenticate (pamh, 0, argc, argv);
  printf ("rc %d\n", rc);
  return rc;
}

void test_active_directory_ask_password_plus_otp(const char *otp) {
}

void test_active_directory_ask_password_ask_otp(const char *otp) {
}

int main (int argc, const char **argv) {
  if (argc <= 1) {
    printf("RUN without any backend\n");
    v_ykclient_inject(&test_ykclient);
    v_ldap_inject(&test_ldap);
  } else {
    printf("RUN with real backend\n");
    ask_stdin_yubikey = 1;
  }
  const char *user = "administrator";



  assert(test_active_directory_login(test_argv, user, "", "") != 0);
  assert(ask_password_state == 0);
  assert(test_active_directory_login(try_first_pass_test_argv, user, "", "") == 0);
  assert(ask_password_state == 3);

  assert(test_active_directory_login(test_argv, user, password, "") != 0);
  assert(ask_password_state == 0);
  assert(test_active_directory_login(try_first_pass_test_argv, user, password, "") == 0);
  assert(ask_password_state == 2);

  assert(test_active_directory_login(test_argv, user, "", ask_yubikey()) != 0);
  assert(ask_password_state == 0);
  assert(test_active_directory_login(try_first_pass_test_argv, user, "", ask_yubikey()) == 0);
  assert(ask_password_state == 1);

  assert(test_active_directory_login(test_argv, user, password, ask_yubikey()) == 0);
  assert(ask_password_state == 0);
  assert(test_active_directory_login(try_first_pass_test_argv, user, password, ask_yubikey()) == 0);
  assert(ask_password_state == 0);

  assert(test_active_directory_login(test_argv, user, "murks", ask_yubikey()) != 0);
  assert(ask_password_state == 0);
  assert(test_active_directory_login(try_first_pass_test_argv, user, "murks", ask_yubikey()) != 0);
  assert(ask_password_state == 0);

  assert(test_active_directory_login(test_argv, user, "murks", "ccccccdhuvvvijehidgthrhtglegiiijdktvgrhmurks") != 0);
  assert(ask_password_state == 0);
  assert(test_active_directory_login(try_first_pass_test_argv, user, "murks", "ccccccdhuvvvijehidgthrhtglegiiijdktvgrhmurks") != 0);
  assert(ask_password_state == 0);

}

