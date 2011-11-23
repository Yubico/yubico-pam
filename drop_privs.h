#ifndef __PAM_YUBICO_DROP_PRIVS_H_INCLUDED__
#define __PAM_YUBICO_DROP_PRIVS_H_INCLUDED__

#include <pwd.h>

int drop_privileges(struct passwd *);
int restore_privileges(void);

#endif
