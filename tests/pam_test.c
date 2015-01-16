/*
 * Copyright (c) 2015 Yubico AB
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

#include <security/pam_appl.h>
#include <security/pam_modutil.h>

static const char *err = "error";
static const char *foo = "foo";
static const char *otp = "vvincredibletrerdegkkrkkneieultcjdghrejjbckh";

void test_authenticate1(void) {
  char *cfg[] = {
    "id=1",
  //  "url=http://localhost:8888/wsapi/2/verify",
    "debug"
  };
  pam_sm_authenticate(0, 0, 2, cfg);
}

const char * pam_strerror(pam_handle_t *pamh, int errnum) {
  fprintf(stderr, "in pam_strerror()\n");
  return "error";
}

int pam_set_data(pam_handle_t *pamh, const char *module_data_name, void *data,
    void (*cleanup)(pam_handle_t *pamh, void *data, int error_status)) {
  fprintf(stderr, "in pam_set_data() %s\n", module_data_name);
  return PAM_SUCCESS;
}

int pam_get_user(const pam_handle_t *pamh, const char **user, const char *prompt) {
  fprintf(stderr, "in pam_get_user()\n");
  *user = foo;
  return PAM_SUCCESS;
}

static int conv_func(int num_msg, const struct pam_message **msg,
    struct pam_response **resp, void *appdata_ptr) {
  fprintf(stderr, "in conv_func()\n");
  if(num_msg != 1) {
    return PAM_CONV_ERR;
  }

  struct pam_response *reply = malloc(sizeof(struct pam_response));
  reply->resp = otp;
  *resp = reply;
  return PAM_SUCCESS;
}

static const struct pam_conv pam_conversation = {
  conv_func,
  NULL,
};

int pam_get_item(const pam_handle_t *pamh, int item_type, const void **item) {
  fprintf(stderr, "in pam_get_item() %d\n", item_type);
  if(item_type == 5) {
    *item = &pam_conversation;
  }
  return PAM_SUCCESS;
}

int pam_modutil_drop_priv(pam_handle_t *pamh, struct pam_modutil_privs *p,
    const struct passwd *pw) {
  fprintf(stderr, "in pam_modutil_drop_priv()\n");
  return PAM_SUCCESS;
}

int pam_modutil_regain_priv(pam_handle_t *pamh, struct pam_modutil_privs *p) {
  fprintf(stderr, "in pam_modutil_regain_priv()\n");
  return PAM_SUCCESS;
}

int pam_set_item(pam_handle_t *pamh, int item_type, const void *item) {
  fprintf(stderr, "in pam_set_item()\n");
  return PAM_SUCCESS;
}


int main (void) {
  test_authenticate1();
  return 0;
}
