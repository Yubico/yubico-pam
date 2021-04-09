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
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <signal.h>
#include <unistd.h>

#include <assert.h>

#include <security/pam_appl.h>
#ifdef HAVE_PAM_MODUTIL_DROP_PRIV
#include <security/pam_modutil.h>
#else
#include <pwd.h>
struct pam_modutil_privs {
  int noop;
};
#endif

int
pam_sm_authenticate (pam_handle_t * pamh,
                     int flags, int argc, const char **argv);

#define YKVAL_PORT1 "17502"
#define YKVAL_PORT2 "30559"
#define LDAP_PORT "52825"

#ifndef TEST_MYSQL_PORT
#define TEST_MYSQL_PORT "3306"
#endif

#define YKVAL SRCDIR"/aux/ykval.pl"
#define LDAP SRCDIR"/aux/ldap.pl"
#define AUTHFILE SRCDIR"/aux/authfile"

static struct data {
  const char user[255];
  const char otp[255];
} _data[] = {
  {"foo", "vvincredibletrerdegkkrkkneieultcjdghrejjbckh"},
  {"bar", "vvincredibletrerdegkkrkkneieultcjdghrejjbckh"},
  {"foo", "vvincrediblltrerdegkkrkkneieultcjdghrejjbckh"},
  {"foo", "vvincredibletrerdegkkrkkneieultcjdghrejjbckl"},
  {"test", "ccccccbchvthlivuitriujjifivbvtrjkjfirllluurj"},
  {"foo", ""},
  {"bar", ""},
  {"nokeys", ""},
  {"foo", "testpasswordvvincredibletrerdegkkrkkneieultcjdghrejjbckh"},
  {"foo", "testpassword"},
  {"bar", "testpassword"},
};


static const char *ldap_cfg[] = {
  "id=1",
  "urllist=http://localhost:"YKVAL_PORT2"/wsapi/2/verify;http://localhost:"YKVAL_PORT1"/wsapi/2/verify",
  "ldap_uri=ldap://localhost:"LDAP_PORT,
  "ldapdn=ou=users,dc=example,dc=com",
  "user_attr=uid",
  "yubi_attr=yubiKeyId",
  "debug"
};

static const char *ldap_cfg2[] = {
  "id=1",
  "urllist=http://localhost:"YKVAL_PORT1"/wsapi/2/verify;http://localhost:"YKVAL_PORT2"/wsapi/2/verify",
  "ldap_uri=ldap://localhost:"LDAP_PORT,
  "ldap_filter=(uid=%u)",
  "yubi_attr=yubiKeyId",
  "debug"
};

static const char *mysql_cfg[] = {
  "id=1",
  "urllist=http://localhost:"YKVAL_PORT1"/wsapi/2/verify",
  "mysql_server=127.0.0.1",
  "mysql_port="TEST_MYSQL_PORT,
  "mysql_user=user",
  "mysql_password=password",
  "mysql_database=otp",
  "debug"
};

static const struct data *test_get_data(void *id) {
  return &_data[(long)id];
}

#ifdef OPENPAM
const char * pam_strerror(const pam_handle_t *pamh, int errnum) {
#else
const char * pam_strerror(pam_handle_t *pamh, int errnum) {
#endif
  fprintf(stderr, "in pam_strerror()\n");
  return "error";
}

int pam_set_data(pam_handle_t *pamh, const char *module_data_name, void *data,
    void (*cleanup)(pam_handle_t *pamh, void *data, int error_status)) {
  fprintf(stderr, "in pam_set_data() %s\n", module_data_name);
  return PAM_SUCCESS;
}

int pam_get_data(const pam_handle_t *pamh, const char *module_data_name, const void **data) {
  fprintf(stderr, "in pam_get_data() %s\n", module_data_name);
  return PAM_SUCCESS;
}

#ifdef OPENPAM
int pam_get_user(pam_handle_t *pamh, const char **user, const char *prompt) {
#else
int pam_get_user(const pam_handle_t *pamh, const char **user, const char *prompt) {
#endif
  fprintf(stderr, "in pam_get_user()\n");
  *user = test_get_data((void*)pamh)->user;
  return PAM_SUCCESS;
}

static int conv_func(int num_msg, const struct pam_message **msg,
    struct pam_response **resp, void *appdata_ptr) {
  struct pam_response *reply;
  fprintf(stderr, "in conv_func()\n");
  if(num_msg != 1) {
    return PAM_CONV_ERR;
  }

  reply = malloc(sizeof(struct pam_response));
  reply->resp = strdup(test_get_data(appdata_ptr)->otp);
  *resp = reply;
  return PAM_SUCCESS;
}

static struct pam_conv pam_conversation = {
  conv_func,
  NULL,
};

int pam_get_item(const pam_handle_t *pamh, int item_type, const void **item) {
  fprintf(stderr, "in pam_get_item() %d for %d\n", item_type, (int)(uintptr_t)pamh);
  if(item_type == PAM_CONV) {
    pam_conversation.appdata_ptr = (void*)pamh;
    *item = &pam_conversation;
  }
  if(item_type == PAM_AUTHTOK && pamh >= (pam_handle_t*)8) {
    *item = (void*)_data[(int)(uintptr_t)pamh].otp;
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

static int test_authenticate1(void) {
  const char *cfg[] = {
    "id=1",
    "url=http://localhost:"YKVAL_PORT1"/wsapi/2/verify?id=%d&otp=%s",
    "authfile="AUTHFILE,
    "debug",
  };
  return pam_sm_authenticate((pam_handle_t *)0, 0, sizeof(cfg) / sizeof(char*), cfg);
}

static int test_authenticate2(void) {
  const char *cfg[] = {
    "id=1",
    "urllist=http://localhost:"YKVAL_PORT1"/wsapi/2/verify;http://localhost:"YKVAL_PORT2"/wsapi/2/verify",
    "authfile="AUTHFILE,
    "debug",
  };
  return pam_sm_authenticate((pam_handle_t *)0, 0, sizeof(cfg) / sizeof(char*), cfg);
}

static int test_authenticate3(void) {
  const char *cfg[] = {
    "id=1",
    "urllist=http://localhost:"YKVAL_PORT1"/wsapi/2/verify",
    "authfile="AUTHFILE,
    "debug",
  };
  return pam_sm_authenticate((pam_handle_t *)4, 0, sizeof(cfg) / sizeof(char*), cfg);
}

static int test_authenticate4(void) {
  const char *cfg[] = {
    "id=1",
    "urllist=http://localhost:"YKVAL_PORT1"/wsapi/2/verify;http://localhost:"YKVAL_PORT2"/wsapi/2/verify",
    "authfile="AUTHFILE,
    "debug",
  };
  return pam_sm_authenticate((pam_handle_t *)5, 0, sizeof(cfg) / sizeof(char*), cfg);
}

static int test_authenticate5(void) {
  const char *cfg[] = {
    "id=1",
    "urllist=http://localhost:"YKVAL_PORT1"/wsapi/2/verify;http://localhost:"YKVAL_PORT2"/wsapi/2/verify",
    "authfile="AUTHFILE,
    "debug",
  };
  return pam_sm_authenticate((pam_handle_t *)6, 0, sizeof(cfg) / sizeof(char*), cfg);
}

static int test_fail_authenticate1(void) {
  const char *cfg[] = {
    "id=1",
    "urllist=http://localhost:"YKVAL_PORT2"/wsapi/2/verify;http://localhost:"YKVAL_PORT1"/wsapi/2/verify",
    "authfile="AUTHFILE,
    "debug"
  };
  return pam_sm_authenticate((pam_handle_t *)1, 0, sizeof(cfg) / sizeof(char*), cfg);
}

static int test_fail_authenticate2(void) {
  const char *cfg[] = {
    "id=1",
    "urllist=http://localhost:"YKVAL_PORT2"/wsapi/2/verify;http://localhost:"YKVAL_PORT1"/wsapi/2/verify",
    "authfile="AUTHFILE,
    "debug"
  };
  return pam_sm_authenticate((pam_handle_t *)2, 0, sizeof(cfg) / sizeof(char*), cfg);
}

static int test_fail_authenticate3(void) {
  const char *cfg[] = {
    "id=1",
    "urllist=http://localhost:"YKVAL_PORT2"/wsapi/2/verify",
    "authfile="AUTHFILE,
    "debug"
  };
  return pam_sm_authenticate((pam_handle_t *)3, 0, sizeof(cfg) / sizeof(char*), cfg);
}

static int test_firstpass_authenticate(void) {
  const char *cfg[] = {
    "id=1",
    "urllist=http://localhost:"YKVAL_PORT2"/wsapi/2/verify;http://localhost:"YKVAL_PORT1"/wsapi/2/verify",
    "authfile="AUTHFILE,
    "use_first_pass",
    "debug"
  };
  return pam_sm_authenticate((pam_handle_t *)8, 0, sizeof(cfg) / sizeof(char*), cfg);
}

static int test_firstpass_fail(void) {
  const char *cfg[] = {
    "id=1",
    "urllist=http://localhost:"YKVAL_PORT2"/wsapi/2/verify;http://localhost:"YKVAL_PORT1"/wsapi/2/verify",
    "authfile="AUTHFILE,
    "use_first_pass",
    "debug"
  };
  return pam_sm_authenticate((pam_handle_t *)9, 0, sizeof(cfg) / sizeof(char*), cfg);
}

static int test_firstpass_fail2(void) {
  const char *cfg[] = {
    "id=1",
    "urllist=http://localhost:"YKVAL_PORT2"/wsapi/2/verify;http://localhost:"YKVAL_PORT1"/wsapi/2/verify",
    "authfile="AUTHFILE,
    "use_first_pass",
    "debug"
  };
  return pam_sm_authenticate((pam_handle_t *)10, 0, sizeof(cfg) / sizeof(char*), cfg);
}

static int test_authenticate_ldap1(void) {
  return pam_sm_authenticate((pam_handle_t *)0, 0, sizeof(ldap_cfg) / sizeof(char*), ldap_cfg);
}

static int test_authenticate_ldap_fail1(void) {
  return pam_sm_authenticate((pam_handle_t *)1, 0, sizeof(ldap_cfg) / sizeof(char*), ldap_cfg);
}

static int test_authenticate_ldap_fail2(void) {
  return pam_sm_authenticate((pam_handle_t *)2, 0, sizeof(ldap_cfg) / sizeof(char*), ldap_cfg);
}

static int test_authenticate_ldap2(void) {
  return pam_sm_authenticate((pam_handle_t *)4, 0, sizeof(ldap_cfg) / sizeof(char*), ldap_cfg);
}

static int test_authenticate_ldap3(void) {
  return pam_sm_authenticate((pam_handle_t *)4, 0, sizeof(ldap_cfg2) / sizeof(char*), ldap_cfg2);
}

static int test_authenticate_ldap4(void) {
  return pam_sm_authenticate((pam_handle_t *)5, 0, sizeof(ldap_cfg) / sizeof(char*), ldap_cfg);
}

static int test_authenticate_ldap5(void) {
  return pam_sm_authenticate((pam_handle_t *)6, 0, sizeof(ldap_cfg) / sizeof(char*), ldap_cfg);
}

static int test_authenticate_ldap6(void) {
  return pam_sm_authenticate((pam_handle_t *)7, 0, sizeof(ldap_cfg) / sizeof(char*), ldap_cfg);
}

static int test_authenticate_mysql1(void) {
  return pam_sm_authenticate((pam_handle_t *)0, 0, sizeof(mysql_cfg) / sizeof(char*), mysql_cfg);
}

static int test_fail_authenticate_mysql1(void) {
  return pam_sm_authenticate((pam_handle_t *)1, 0, sizeof(mysql_cfg) / sizeof(char*), mysql_cfg);
}

static int test_fail_authenticate_mysql2(void) {
  return pam_sm_authenticate((pam_handle_t *)5, 0, sizeof(mysql_cfg) / sizeof(char*), mysql_cfg);
}

static pid_t run_mock(const char *port, const char *type) {
  pid_t pid = fork();
  if(pid == 0) {
    execlp(type, type, port, NULL);
  }
  return pid;
}

int main(void) {
  int ret = 0;
  pid_t child = run_mock(YKVAL_PORT1, YKVAL);
  pid_t child2 = run_mock(YKVAL_PORT2, YKVAL);
#ifdef HAVE_LIBLDAP
  pid_t child3 = run_mock(LDAP_PORT, LDAP);
#endif

  /* Give the "server" time to settle */
  sleep(1);

  if(test_authenticate1() != PAM_SUCCESS) {
    ret = 1;
    goto out;
  }
  if(test_authenticate2() != PAM_SUCCESS) {
    ret = 2;
    goto out;
  }
  if(test_fail_authenticate1() != PAM_USER_UNKNOWN) {
    ret = 3;
    goto out;
  }
  if(test_fail_authenticate2() != PAM_AUTH_ERR) {
    ret = 4;
    goto out;
  }
  if(test_fail_authenticate3() != PAM_AUTH_ERR) {
    ret = 5;
    goto out;
  }
  if(test_authenticate3() != PAM_SUCCESS) {
    ret = 6;
    goto out;
  }
  if(test_authenticate4() != PAM_AUTH_ERR) {
    ret = 7;
    goto out;
  }
  if(test_authenticate5() != PAM_USER_UNKNOWN) {
    ret = 8;
    goto out;
  }
  if(test_firstpass_authenticate() != PAM_SUCCESS) {
    ret = 9;
    goto out;
  }
  if(test_firstpass_fail() != PAM_AUTH_ERR) {
    ret = 10;
    goto out;
  }
  if(test_firstpass_fail2() != PAM_USER_UNKNOWN) {
    ret = 11;
    goto out;
  }
#ifdef HAVE_LIBLDAP
  if(test_authenticate_ldap1() != PAM_SUCCESS) {
    ret = 1001;
    goto out;
  }
  if(test_authenticate_ldap_fail1() != PAM_USER_UNKNOWN) {
    ret = 1002;
    goto out;
  }
  if(test_authenticate_ldap_fail2() != PAM_AUTH_ERR) {
    ret = 1003;
    goto out;
  }
  if(test_authenticate_ldap2() != PAM_SUCCESS) {
    ret = 1004;
    goto out;
  }
  if(test_authenticate_ldap3() != PAM_SUCCESS) {
    ret = 1005;
    goto out;
  }
  if(test_authenticate_ldap4() != PAM_AUTH_ERR) {
    ret = 1006;
    goto out;
  }
  if(test_authenticate_ldap5() != PAM_USER_UNKNOWN) {
    ret = 1007;
    goto out;
  }
  if(test_authenticate_ldap6() != PAM_USER_UNKNOWN) {
    ret = 1008;
    goto out;
  }
#endif
#if defined(RUN_MYSQL_TESTS) && defined(HAVE_MYSQL)
  if(test_authenticate_mysql1() != PAM_SUCCESS) {
    ret = 2001;
    goto out;
  }
  if(test_fail_authenticate_mysql1() != PAM_USER_UNKNOWN) {
    ret = 2002;
    goto out;
  }
  if(test_fail_authenticate_mysql2() != PAM_AUTH_ERR) {
    ret = 2003;
    goto out;
  }
#endif

out:
  kill(child, 9);
  kill(child2, 9);
#ifdef HAVE_LIBLDAP
  kill(child3, 9);
  printf("killed %d, %d and %d\n", child, child2, child3);
#else
  printf("killed %d and %d\n", child, child2);
#endif
  if(ret != 0) {
    fprintf(stderr, "test %d failed!\n", ret);
  }
  return ret;
}
