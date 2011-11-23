/* Written by Ricky Zhou <ricky@fedoraproject.org>
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

#include "util.h"

static uid_t saved_euid;
static gid_t saved_egid;

static gid_t *saved_groups;
static int saved_groups_length;

int drop_privileges(struct passwd *pw) {
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
}

int restore_privileges(void) {
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
}
