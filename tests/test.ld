clang -I$HOME/macosx/yubico/include -g -o test test.c -DHAVE_LIBLDAP -DHAVE_SECURITY_PAM_APPL_H -DHAVE_SECURITY_PAM_MODULES_H  ../.libs/libpam_util.a ../.libs/pam_yubico.o ../.libs/drop_privs.o -lldap -L/Users/menabe/macosx/yubico/lib -lykpers-1 -L/Users/menabe/macosx/yubico/lib -lykclient -lcurl -lssl -lcrypto -lldap -lz -L/Users/menabe/macosx/yubico/lib -lyubikey \
-Lrra-c-util/tests/fakepam -lfakepam -Lrra-c-util/tests/tap -ltap -Lrra-c-util/util -lutil \
-Lrra-c-util/portable -lportable
