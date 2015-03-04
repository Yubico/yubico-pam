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

#ifndef __PAM_YUBICO_YUBI_PAM_H_INCLUDED__
#define __PAM_YUBICO_YUBI_PAM_H_INCLUDED__

/* Libtool defines PIC for shared objects */
#ifndef PIC
#define PAM_STATIC
#endif

#include "drop_privs.h"

/* These #defines must be present according to PAM documentation. */
#define PAM_SM_AUTH

#ifdef HAVE_SECURITY_PAM_APPL_H
#include <security/pam_appl.h>
#endif
#ifdef HAVE_SECURITY_PAM_MODULES_H
#include <security/pam_modules.h>
#endif

#ifdef __LINUX_PAM__
#define PAM_STRERROR_CONST 
#else
#define PAM_STRERROR_CONST const
#endif

typedef struct {
  const char *(*pam_strerror)(PAM_STRERROR_CONST pam_handle_t *_pamh, int _error_number);
  int (*pam_get_data)(const pam_handle_t *_pamh, const char *_module_data_name, const void **_data);
  int (*pam_set_data)(pam_handle_t *_pamh, const char *_module_data_name, void *_data, void (*_cleanup)(pam_handle_t *_pamh,
                    void *_data, int _pam_end_status));
  int (*pam_get_user)(pam_handle_t *_pamh, const char **_user, const char *_prompt);
  int (*pam_get_item)(const pam_handle_t *_pamh, int _item_type, const void **_item);
  int (*pam_set_item)(pam_handle_t *_pamh, int _item_type, const void *_item);
  int (*pam_start)(const char *_service, const char *_user, const struct pam_conv *_pam_conv, pam_handle_t **_pamh);
  int (*pam_modutil_drop_priv)(pam_handle_t *pamh, PamModutilPrivs *p, const struct passwd *pw);
  int (*pam_modutil_regain_priv)(pam_handle_t *pamh, PamModutilPrivs *p);
} VirtPam;

void v_pam_inject(VirtPam *target); 

const char *v_pam_strerror(PAM_STRERROR_CONST pam_handle_t *_pamh, int _error_number);
int v_pam_get_data(const pam_handle_t *_pamh, const char *_module_data_name, const void **_data);
int v_pam_set_data(pam_handle_t *_pamh, const char *_module_data_name, void *_data, void (*_cleanup)(pam_handle_t *_pamh,
                  void *_data, int _pam_end_status));
int v_pam_get_user(pam_handle_t *_pamh, const char **_user, const char *_prompt);
int v_pam_get_item(const pam_handle_t *_pamh, int _item_type, const void **_item);
int v_pam_set_item(pam_handle_t *_pamh, int _item_type, const void *_item);
int v_pam_start(const char *_service, const char *_user, const struct pam_conv *_pam_conv, pam_handle_t **_pamh);

int v_pam_modutil_drop_priv(pam_handle_t *pamh, PamModutilPrivs *p, const struct passwd *pw);
int v_pam_modutil_regain_priv(pam_handle_t *pamh, PamModutilPrivs *p);

#endif
