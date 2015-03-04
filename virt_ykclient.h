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

#ifndef __PAM_YUBICO_YUBI_YKCLIENT_H_INCLUDED__
#define __PAM_YUBICO_YUBI_YKCLIENT_H_INCLUDED__

#include <ykclient.h>

typedef struct {
  ykclient_rc (*ykclient_init)(ykclient_t ** ykc);
  void (*ykclient_done)(ykclient_t ** ykc);
  ykclient_rc (*ykclient_request)(ykclient_t * ykc, const char *yubikey_otp);
  const char *(*ykclient_strerror)(ykclient_rc ret);
  ykclient_rc (*ykclient_set_client_b64)(ykclient_t * ykc, unsigned int client_id, const char *key);
  void (*ykclient_set_verify_signature)(ykclient_t * ykc, int value);
  void (*ykclient_set_ca_path)(ykclient_t * ykc, const char *ca_path);
  ykclient_rc (*ykclient_set_url_template)(ykclient_t * ykc, const char *url_template);
  ykclient_rc (*ykclient_set_url_bases)(ykclient_t * ykc, size_t num_templates, const char **url_templates);
  ykclient_rc (*ykclient_global_init)();
  void (*ykclient_global_done)();
} VirtYkClient;


void v_ykclient_inject(VirtYkClient *target);

ykclient_rc v_ykclient_init (ykclient_t ** ykc);
void v_ykclient_done (ykclient_t ** ykc);
ykclient_rc v_ykclient_request (ykclient_t * ykc, const char *yubikey_otp);
const char *v_ykclient_strerror (ykclient_rc ret);
ykclient_rc v_ykclient_set_client_b64 (ykclient_t * ykc, unsigned int client_id, const char *key);
void v_ykclient_set_verify_signature (ykclient_t * ykc, int value);
void v_ykclient_set_ca_path (ykclient_t * ykc, const char *ca_path);
ykclient_rc v_ykclient_set_url_template (ykclient_t * ykc, const char *url_template);
ykclient_rc v_ykclient_set_url_bases (ykclient_t * ykc, size_t num_templates, const char **url_templates);

ykclient_rc v_ykclient_global_init ();
void v_ykclient_global_done ();

#endif
