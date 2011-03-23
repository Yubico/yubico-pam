# Written by Simon Josefsson <simon@yubico.com>.
# Copyright (c) 2006, 2007, 2008, 2009, 2010 Yubico AB
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#
#     * Redistributions in binary form must reproduce the above
#       copyright notice, this list of conditions and the following
#       disclaimer in the documentation and/or other materials provided
#       with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

AC_INIT([pam_yubico], [2.6], [simon@yubico.com])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([foreign])
AC_PROG_CC
AC_LIBTOOL_WIN32_DLL
AC_DISABLE_STATIC
AC_PROG_LIBTOOL

AC_CHECK_HEADERS([security/pam_appl.h], [],
  [AC_MSG_ERROR([[PAM header files not found, install libpam-dev.]])])
AC_CHECK_HEADERS([security/pam_modules.h security/_pam_macros.h], [], [],
  [#include <security/pam_appl.h>])

AC_ARG_WITH([ldap],
            [AS_HELP_STRING([--without-ldap],
              [disable support for ldap])],
            [],
            [with_ldap=yes])
          
          LIBLDAP=
          AS_IF([test "x$with_ldap" != xno],
            [AC_CHECK_LIB([ldap], [ldap_init],
              [AC_SUBST([LIBLDAP], ["-lldap -llber"])
               AC_DEFINE([HAVE_LIBLDAP], [1],
                         [Define if you have libldap])
              ],
              [AC_MSG_WARN(
                 [libldap not found, will not be compiled (--without-ldap to disable ldap support)])],
              [])])


AC_LIB_HAVE_LINKFLAGS([ykclient],, [#include <ykclient.h>],
                      [ykclient_set_ca_path(0, 0)])
if test "$ac_cv_libykclient" != yes; then
   AC_MSG_ERROR([[Libykclient v2.4+ required, see http://code.google.com/p/yubico-c-client/]])
fi

AC_LIB_HAVE_LINKFLAGS(yubikey,,
		      [#include <yubikey.h>],                                                                                                                               			  [yubikey_modhex_p("foo")])
if test "$ac_cv_libyubikey" != yes; then
  AC_MSG_ERROR([libyubikey v1.5+ not found, see http://code.google.com/p/yubico-c/])
fi


PKG_CHECK_MODULES([YKPERS], [ykpers-1]);

AC_SUBST(PAMDIR, "\$(exec_prefix)/lib/security")
AC_ARG_WITH(pam-dir,
  AC_HELP_STRING([--with-pam-dir=DIR],
                 [Where to install PAM module [[PREFIX/lib/security]]]),
            [case "${withval}" in
            /*) PAMDIR="${withval}";;
            ./*|../*) AC_MSG_ERROR(Bad value for --with-pam-dir);;
            *)  PAMDIR="\$(exec_prefix)/lib/${withval}";;
            esac])
AC_MSG_NOTICE([PAM installation path $PAMDIR])

AC_CONFIG_FILES(Makefile)
AC_OUTPUT
