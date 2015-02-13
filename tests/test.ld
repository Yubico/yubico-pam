clang -I$HOME/linux/include -I$HOME/macosx/yubico/include -g \
-o test test.c -DHAVE_LIBLDAP -DHAVE_SECURITY_PAM_APPL_H \
-DHAVE_SECURITY_PAM_MODULES_H -DHAVE_PAM_MODUTIL_DROP_PRIV \
../.libs/pam_yubico.o ../.libs/drop_privs.o ../.libs/libpam_util.a \
../.libs/libpam_real.a -lldap -llber \
-Wl,-rpath=$HOME/linux/lib \
-Wvisibility \
-L/Users/menabe/macosx/yubico/lib -L$HOME/linux/lib -lykpers-1 \
-L/Users/menabe/macosx/yubico/lib -lykclient -lcurl -lssl -lcrypto -lldap \
-lz -L/Users/menabe/macosx/yubico/lib -lyubikey  -lpam
