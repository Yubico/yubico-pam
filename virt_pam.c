/* Written by Meno Abels <meno.abels@gmail.com>
 * Copyright (c) 2015 Yubico AB
 * Copyright (c) 2015 Meno.Abels@gmail.com
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
#include "virt_pam.h"

static VirtPam lib_pam = {
  &pam_strerror,
  &pam_get_data,
  &pam_set_data,
  &pam_get_user,
  &pam_get_item,
  &pam_set_item,
  &pam_start,
  &pam_modutil_drop_priv,
  &pam_modutil_regain_priv
};

static VirtPam *running = &lib_pam;

void v_pam_inject(VirtPam *target) {
  running = target;
}

const char *v_pam_strerror(PAM_STRERROR_CONST pam_handle_t *_pamh, int _error_number) {
  return (running->pam_strerror)(_pamh, _error_number);
}

int v_pam_get_data(const pam_handle_t *_pamh, const char *_module_data_name, const void **_data) {
  return (running->pam_get_data)(_pamh, _module_data_name, _data);
}

int v_pam_set_data(pam_handle_t *_pamh, const char *_module_data_name, void *_data, void (*_cleanup)(pam_handle_t *_pamh,
                  void *_data, int _pam_end_status)) {
  return (running->pam_set_data)(_pamh, _module_data_name, _data, _cleanup);
}

int v_pam_get_user(pam_handle_t *_pamh, const char **_user, const char *_prompt) {
  return (running->pam_get_user)(_pamh, _user, _prompt);
}

int v_pam_get_item(const pam_handle_t *_pamh, int _item_type, const void **_item) {
  return (running->pam_get_item)(_pamh, _item_type, _item);
}

int v_pam_set_item(pam_handle_t *_pamh, int _item_type, const void *_item) {
  return (running->pam_set_item)(_pamh, _item_type, _item);
}

int v_pam_start(const char *_service, const char *_user, const struct pam_conv *_pam_conv, pam_handle_t **_pamh) {
  return (running->pam_start)(_service, _user, _pam_conv, _pamh);
}

int v_pam_modutil_drop_priv(pam_handle_t *pamh, PamModutilPrivs *p, const struct passwd *pw) {
  return (running->pam_modutil_drop_priv)(pamh, p, pw);
}

int v_pam_modutil_regain_priv(pam_handle_t *pamh, PamModutilPrivs *p) {
  return (running->pam_modutil_regain_priv)(pamh, p);
}

