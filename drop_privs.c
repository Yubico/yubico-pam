/* Written by Ricky Zhou <ricky@fedoraproject.org>
 * Fredrik Thulin <fredrik@yubico.com> implemented pam_modutil_drop_priv
 *
 * Copyright (c) 2011-2012 Yubico AB
 * Copyright (c) 2011 Ricky Zhou <ricky@fedoraproject.org>
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

#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

#include "util.h"

#ifdef HAVE_SECURITY_PAM_APPL_H
#include <security/pam_appl.h>
#endif
#ifdef HAVE_SECURITY_PAM_MODULES_H
#include <security/pam_modules.h>
#endif

#ifdef HAVE_PAM_MODUTIL_DROP_PRIV
#ifdef HAVE_SECURITY_PAM_MODUTIL_H
#include <security/pam_modutil.h>
#endif /* HAVE_SECURITY_PAM_MODUTIL_H */
#else
static uid_t saved_euid;
static gid_t saved_egid;

static gid_t *saved_groups;
static int saved_groups_length;
#endif /* HAVE_PAM_MODUTIL_DROP_PRIV */

#ifdef HAVE_PAM_MODUTIL_DROP_PRIV
struct pam_modutil_privs * _privs_location(int force_init) {
  static int init = 0;
  static struct pam_modutil_privs privs;
  if (init == 0 || force_init) {
    PAM_MODUTIL_DEF_PRIVS(def_privs);
    privs = def_privs;
    init = 1;
  }
  return &privs;
}
#endif /* HAVE_PAM_MODUTIL_DROP_PRIV */

int drop_privileges(struct passwd *pw, pam_handle_t *pamh) {
#ifdef HAVE_PAM_MODUTIL_DROP_PRIV
  int res;
  res = pam_modutil_drop_priv(pamh, _privs_location(0), pw);
  if (res)
    D (("pam_modutil_drop_priv: %i", res));
  return res;
#else
    saved_euid = geteuid();
    saved_egid = getegid();

    saved_groups_length = getgroups(0, NULL);
    if (saved_groups_length < 0) {
        D (("getgroups: %s", strerror(errno)));
        return -1;
    }

    if (saved_groups_length > 0) {
        saved_groups = malloc(saved_groups_length * sizeof(gid_t));
        if (saved_groups == NULL) {
            D (("malloc: %s", strerror(errno)));
            return -1;
        }

        if (getgroups(saved_groups_length, saved_groups) < 0) {
            D (("getgroups: %s", strerror(errno)));
            return -1;
        }
    }

    if (initgroups(pw->pw_name, pw->pw_gid) < 0) {
        D (("initgroups: %s", strerror(errno)));
        return -1;
    }

    if (setegid(pw->pw_gid) < 0) {
        D (("setegid: %s", strerror(errno)));
        return -1;
    }

    if (seteuid(pw->pw_uid) < 0) {
        D (("seteuid: %s", strerror(errno)));
        return -1;
    }

    return 0;
#endif /* HAVE_PAM_MODUTIL_DROP_PRIV */
}

int restore_privileges(pam_handle_t *pamh) {
#ifdef HAVE_PAM_MODUTIL_DROP_PRIV
  int res;
  res = pam_modutil_regain_priv(pamh, _privs_location(0));
  if (res)
    D (("pam_modutil_drop_priv: %i", res));
  /* re-initialize privs in case we want to drop privs again (sic) */
  _privs_location(1);
  return res;
#else
    if (seteuid(saved_euid) < 0) {
        D (("seteuid: %s", strerror(errno)));
        return -1;
    }

    if (setegid(saved_egid) < 0) {
        D (("setegid: %s", strerror(errno)));
        return -1;
    }

    if (setgroups(saved_groups_length, saved_groups) < 0) {
        D (("setgroups: %s", strerror(errno)));
        return -1;
    }

    free(saved_groups);

    return 0;
#endif /* HAVE_PAM_MODUTIL_DROP_PRIV */
}
