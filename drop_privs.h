#ifndef __PAM_YUBICO_DROP_PRIVS_H_INCLUDED__
#define __PAM_YUBICO_DROP_PRIVS_H_INCLUDED__

#include <pwd.h>

#ifdef HAVE_SECURITY_PAM_APPL_H
#include <security/pam_appl.h>
#endif
#ifdef HAVE_SECURITY_PAM_MODULES_H
#include <security/pam_modules.h>
#endif

int drop_privileges(struct passwd *, pam_handle_t *);
int restore_privileges(pam_handle_t *);

#endif
