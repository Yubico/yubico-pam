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

#include "virt_ykclient.h"

static VirtYkClient lib_ykclient = {
  &ykclient_init,
  &ykclient_done,
  &ykclient_request,
  &ykclient_strerror,
  &ykclient_set_client_b64,
  &ykclient_set_verify_signature,
  &ykclient_set_ca_path,
  &ykclient_set_url_template,
  &ykclient_set_url_bases,
  &ykclient_global_init,
  &ykclient_global_done
};

static VirtYkClient *running = &lib_ykclient;

void v_ykclient_inject(VirtYkClient *target) {
  running = target;
}

ykclient_rc v_ykclient_init (ykclient_t ** ykc) {
  return (running->ykclient_init)(ykc);
}

void v_ykclient_done (ykclient_t ** ykc) {
  return (running->ykclient_done)(ykc);
}

ykclient_rc v_ykclient_request (ykclient_t * ykc, const char *yubikey_otp) {
  return (running->ykclient_request)(ykc, yubikey_otp);
}

const char *v_ykclient_strerror (ykclient_rc ret) {
  return (running->ykclient_strerror)(ret);
}

ykclient_rc v_ykclient_set_client_b64 (ykclient_t * ykc, unsigned int client_id, const char *key) {
  return (running->ykclient_set_client_b64)(ykc, client_id, key);
}

void v_ykclient_set_verify_signature (ykclient_t * ykc, int value) {
  return (running->ykclient_set_verify_signature)(ykc, value);
}

void v_ykclient_set_ca_path (ykclient_t * ykc, const char *ca_path) {
  return (running->ykclient_set_ca_path)(ykc, ca_path);
}

ykclient_rc v_ykclient_set_url_template (ykclient_t * ykc, const char *url_template) {
  return (running->ykclient_set_url_template)(ykc, url_template);
}

ykclient_rc v_ykclient_set_url_bases (ykclient_t * ykc, size_t num_templates, const char **url_templates) {
  return (running->ykclient_set_url_bases)(ykc, num_templates, url_templates);
}

ykclient_rc v_ykclient_global_init () {
  return (running->ykclient_global_init)();
}

void v_ykclient_global_done () {
  (running->ykclient_global_done)();
}
