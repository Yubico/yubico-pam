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

ykclient_rc test_ykclient_global_init () {
  return YKCLIENT_OK;
}

void test_ykclient_global_done () {
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
  &test_ykclient_global_init,
  &test_ykclient_global_done,
};

