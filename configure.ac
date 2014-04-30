# Written by Simon Josefsson <simon@yubico.com>.
# Copyright (c) 2006-2014 Yubico AB
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

AC_INIT([pam_yubico], [2.16], [yubico-devel@googlegroups.com])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([1.11 foreign -Wall -Werror])
AM_SILENT_RULES([yes])
AM_PROG_CC_C_O

m4_ifdef([AM_PROG_AR], [AM_PROG_AR])

AC_LIBTOOL_WIN32_DLL
AC_DISABLE_STATIC
AC_PROG_LIBTOOL

AC_CHECK_HEADERS([security/pam_appl.h], [],
  [AC_MSG_ERROR([[PAM header files not found, install libpam-dev.]])])
AC_CHECK_HEADERS([security/pam_modules.h security/_pam_macros.h security/pam_modutil.h], [], [],
  [#include <sys/types.h>
   #include <security/pam_appl.h>])

AC_CHECK_LIB([pam], [pam_start])

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
                      [ykclient_set_url_bases(0, 0, 0)])
if test "$ac_cv_libykclient" != yes; then
   AC_MSG_ERROR([[Libykclient v2.12+ required, see https://developers.yubico.com/yubico-c-client/]])
fi

AC_LIB_HAVE_LINKFLAGS(yubikey,, [#include <yubikey.h>],
                      [yubikey_modhex_p("foo")])

AC_ARG_WITH([cr],
  [AS_HELP_STRING([--without-cr],
    [disable support for challenge/response])],
  [],
  [with_cr=yes])
if test "x$with_cr" != xno; then
  PKG_CHECK_MODULES([YKPERS], [ykpers-1 >= 1.8.0]);
  # libyubikey required for HAVE_CR
  if test "$ac_cv_libyubikey" != yes; then
    AC_MSG_ERROR([Libyubikey v1.5+ not found, see https://developers.yubico.com/yubico-c/ (required for challenge-response)])
  fi
fi
if test -n "$YKPERS_LIBS"; then
  AC_DEFINE([HAVE_CR], [1], [Define if you have libykpers-1 and libyubikey])
fi
AM_CONDITIONAL([YKPERS], [test -n "$YKPERS_LIBS"])

AC_CHECK_FUNCS([pam_modutil_drop_priv])

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

AC_ARG_ENABLE([gcc-warnings],
  [AS_HELP_STRING([--enable-gcc-warnings],
      [turn on lots of GCC warnings (for developers)])],
  [case $enableval in
     yes|no) ;;
     *)      AC_MSG_ERROR([bad value $enableval for gcc-warnings option]) ;;
   esac
   gl_gcc_warnings=$enableval],
  [gl_gcc_warnings=no]
)

if test "$gl_gcc_warnings" = yes; then
  nw="$nw -Wsystem-headers"         # Don't let system headers trigger warnings
  nw="$nw -Wpadded"                 # Struct's arenot padded
  nw="$nw -Wc++-compat"             # We don't care strongly about C++ compilers
  nw="$nw -Wtraditional"            # Warns on #elif which we use often
  nw="$nw -Wtraditional-conversion" # Too many warnings for now
  nw="$nw -Wconversion"             # Too many warnings for now
  nw="$nw -Wsuggest-attribute=pure" # Is it worth using attributes?

  gl_MANYWARN_ALL_GCC([ws])
  gl_MANYWARN_COMPLEMENT(ws, [$ws], [$nw])
  for w in $ws; do
    gl_WARN_ADD([$w])
  done

  gl_WARN_ADD([-fdiagnostics-show-option])
fi


AC_CONFIG_FILES(Makefile)
AC_OUTPUT

AC_MSG_NOTICE([Summary of build options:

  Version:            ${VERSION}
  Host type:          ${host}
  Install prefix:     ${prefix}
  Compiler:           ${CC}
  Library types:      Shared=${enable_shared}, Static=${enable_static}
  LDAP:               ${with_ldap}
  Challenge-Response: ${with_cr}
])
