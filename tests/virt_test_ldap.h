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

