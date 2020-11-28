dnl
dnl configure.in helper macros
dnl 
 
dnl TODO: fix "mutual exclusive" stuff

dnl 3rd party macro for version number comparisons
m4_include([ax_compare_version.m4])

MYSQL_VERSION=none

dnl check for a --with-mysql configure option and set up
dnl MYSQL_CONFIG and MYSLQ_VERSION variables for further use
dnl this must always be called before any other macro from this file
dnl
dnl WITH_MYSQL()
dnl
AC_DEFUN([WITH_MYSQL], [ 
  AC_MSG_CHECKING(for mysql_config executable)

  # try to find the mysql_config script,
  # --with-mysql will either accept its path directly
  # or will treat it as the mysql install prefix and will 
  # search for the script in there
  # if no path is given at all we look for the script in
  # /usr/bin and /usr/local/mysql/bin
  AC_ARG_WITH(mysql, [  --with-mysql=PATH       path to mysql_config binary or mysql prefix dir], [
    if test $withval = "no"
    then
      MYSQL_CONFIG="no"
    else
      if test -x $withval -a -f $withval
      then
        MYSQL_CONFIG=$withval
        MYSQL_PREFIX=$(dirname $(dirname $withval))
      elif test -x $withval/bin/mysql_config -a -f $withval/bin/mysql_config
      then 
        MYSQL_CONFIG=$withval/bin/mysql_config
        MYSQL_PREFIX=$withval
      elif test -x $withval/bin/mariadb_config -a -f $withval/bin/mariadb_config
      then 
        MYSQL_CONFIG=$withval/bin/mariadb_config
        MYSQL_PREFIX=$withval
      fi
    fi
  ], [
    # implicit "yes", check in $PATH and in known default prefix, 
    # but only if source not already configured
    if test "x$MYSQL_SRCDIR" != "x"
    then
      MYSQL_CONFIG="no"
    elif MYSQL_CONFIG=$(which mysql_config)
    then      
      MYSQL_PREFIX=$(dirname $(dirname $MYSQL_CONFIG))
    elif MYSQL_CONFIG=$(which mariadb_config)
    then      
      MYSQL_PREFIX=$(dirname $(dirname $MYSQL_CONFIG))
    elif test -x /usr/local/mysql/bin/mysql_config -a -f /usr/local/mysql/bin/mysql_config 
    then
      MYSQL_CONFIG=/usr/local/mysql/bin/mysql_config
      MYSQL_PREFIX=/usr/local/mysql
    elif MYSQL_CONFIG=$(which mariadb_config)
    then      
      MYSQL_PREFIX=$(dirname $(dirname $MYSQL_CONFIG))
    elif test -x /usr/local/mysql/bin/mariadb_config -a -f /usr/local/mysql/bin/mariadb_config 
    then
      MYSQL_CONFIG=/usr/local/mysql/bin/mariadb_config
      MYSQL_PREFIX=/usr/local/mysql
    fi
  ])

  if test "x$MYSQL_CONFIG" = "x" 
  then
    AC_MSG_ERROR([not found])
  elif test "$MYSQL_CONFIG" = "no" 
  then
    MYSQL_CONFIG=""
    MYSQL_PREFIX=""
    AC_MSG_RESULT([no])
  else
    if test "x$MYSQL_SRCDIR" != "x"
    then
      AC_MSG_ERROR("--with-mysql can't be used together with --with-mysql-src")
    else
      # get installed version
      MYSQL_VERSION=$($MYSQL_CONFIG --version)

      MYSQL_CONFIG_INCLUDE=$($MYSQL_CONFIG --include)
      MYSQL_CONFIG_LIBS_R=$($MYSQL_CONFIG --libs_r)

      MYSQL_CLIENT=$(dirname $MYSQL_CONFIG)/mysql

      AC_MSG_RESULT($MYSQL_CONFIG)
    fi
  fi
])



dnl check for a --with-mysql-src configure option and set up
dnl MYSQL_CONFIG and MYSLQ_VERSION variables for further use
dnl this must always be called before any other macro from this file
dnl
dnl if you use this together with WITH_MYSQL you have to put this in front of it
dnl
dnl WITH_MYSQL_SRC()
dnl
AC_DEFUN([WITH_MYSQL_SRC], [ 
  AC_MSG_CHECKING(for mysql source directory)

  AC_ARG_WITH(mysql-src, [  --with-mysql-src=PATH   path to mysql sourcecode], [
    if test "x$MYSQL_CONFIG" != "x"
    then
      AC_MSG_ERROR([--with-mysql-src can't be used together with --with-mysql])
    fi

    if test -f $withval/include/mysql_version.h.in
    then
        if test -f $withval/include/mysql_version.h
        then
            AC_MSG_RESULT(ok)
            MYSQL_SRCDIR=$withval
            MYSQL_VERSION=$(grep MYSQL_SERVER_VERSION $MYSQL_SRCDIR/include/mysql_version.h | sed -e's/"$//g' -e's/.*"//g')
        else
            AC_MSG_ERROR([not configured yet])
        fi
    else
        AC_MSG_ERROR([$withval doesn't look like a mysql source dir])
    fi
  ], [
        AC_MSG_RESULT(no)
  ])

  if test "x$MYSQL_SRCDIR" != "x"
  then
    MYSQL_CONFIG_INCLUDE="-I$MYSQL_SRCDIR/include"
    MYSQL_CONFIG_LIBS_R="-L$MYSQL_SRCDIR/libmysql_r/.libs -lmysqlclient_r -lz -lm"
  fi
])


dnl
dnl check for successfull mysql detection
dnl and register AC_SUBST variables
dnl
dnl MYSQL_SUBST()
dnl
AC_DEFUN([MYSQL_SUBST], [
  if test "$MYSQL_VERSION" = "none" 
  then
    AC_MSG_ERROR([MySQL required but not found])
  fi
   
  # register replacement vars, these will be filled
  # with contant by the other macros 
  AC_SUBST([MYSQL_CFLAGS])
  AC_SUBST([MYSQL_CXXFLAGS])
  AC_SUBST([MYSQL_LIBS])
  AC_SUBST([MYSQL_LIBS])
  AC_SUBST([MYSQL_VERSION])
  AC_SUBST([MYSQL_PLUGIN_DIR])
])


dnl check if current MySQL version meets a version requirement
dnl and act accordingly
dnl
dnl MYSQL_CHECK_VERSION([requested_version],[yes_action],[no_action])
dnl 
AC_DEFUN([MYSQL_CHECK_VERSION], [
  AX_COMPARE_VERSION([$MYSQL_VERSION], [GE], [$1], [$2], [$3])
])



dnl check if current MySQL version meets a version requirement
dnl and bail out with an error message if not
dnl
dnl MYSQL_NEED_VERSION([need_version])
dnl 
AC_DEFUN([MYSQL_NEED_VERSION], [
  AC_MSG_CHECKING([mysql version >= $1])
  MYSQL_CHECK_VERSION([$1], 
    [AC_MSG_RESULT([yes ($MYSQL_VERSION)])], 
    [AC_MSG_ERROR([no ($MYSQL_VERSION)])])
])



dnl check whether the installed server was compiled with libdbug
dnl
dnl MYSQL_DEBUG_SERVER()
dnl
AC_DEFUN([MYSQL_DEBUG_SERVER], [
  AC_MSG_CHECKING(for mysqld debug version)

  MYSQL_DBUG=unknown

  OLD_CFLAGS=$CFLAGS
  CFLAGS="$CFLAGS $MYSQL_CONFIG_INCLUDE"
  # check for DBUG_ON/OFF being defined in my_config.h
  AC_TRY_COMPILE(,[
#include "my_config.h"
#ifdef DBUG_ON
  int ok;
#else
#  ifdef DBUG_OFF
  int ok;
#  else
  choke me
#  endif
#endif
  ],AS_VAR_SET(MYSQL_DBUG, ["defined by header file"]),AS_VAR_SET(MYSQL_DBUG, unknown))
  CFLAGS=$OLD_CFLAGS


  if test "$MYSQL_DBUG" = "unknown"
  then
    # fallback: need to check mysqld binary itself
    # check $prefix/libexec, $prefix/sbin, $prefix/bin in that order
    for dir in libexec sbin bin
    do
      MYSQLD=$MYSQL_PREFIX/$dir/mysqld
      if test -f $MYSQLD -a -x $MYSQLD
      then
        if ($MYSQLD --help --verbose | grep -q -- "--debug")
        then
          AC_DEFINE([DBUG_ON], [1], [Use libdbug])
          MYSQL_DBUG=yes
        else
          AC_DEFINE([DBUG_OFF], [1], [Don't use libdbug])
          MYSQL_DBUG=no
        fi
        break;
      fi
    done
  fi

  if test "$MYSQL_DBUG" = "unknown"
  then
    # still unknown? make sure not to use it then
    AC_DEFINE([DBUG_OFF], [1], [Don't use libdbug])
    MYSQL_DBUG="unknown, assuming no"
  fi

  AC_MSG_RESULT($MYSQL_DBUG)
  # 
])



dnl set up variables for compilation of regular C API applications
dnl 
dnl MYSQL_USE_CLIENT_API()
dnl
AC_DEFUN([MYSQL_USE_CLIENT_API], [
  # add regular MySQL C flags
  ADDFLAGS=$MYSQL_CONFIG_INCLUDE 

  MYSQL_CFLAGS="$MYSQL_CFLAGS $ADDFLAGS"    
  MYSQL_CXXFLAGS="$MYSQL_CXXFLAGS $ADDFLAGS"    

  # add linker flags for client lib
  AC_ARG_ENABLE([embedded-mysql], [  --enable-embedded-mysql enable the MySQL embedded server feature], 
    [MYSQL_LIBS="$MYSQL_LIBS "$($MYSQL_CONFIG --libmysqld-libs)],
    [MYSQL_LIBS="$MYSQL_LIBS $MYSQL_CONFIG_LIBS_R"])
])





dnl set up variables for compilation of NDBAPI applications
dnl 
dnl MYSQL_USE_NDB_API()
dnl
AC_DEFUN([MYSQL_USE_NDB_API], [
  MYSQL_USE_CLIENT_API()
  AC_PROG_CXX
  MYSQL_CHECK_VERSION([5.0.0],[  

    # mysql_config results need some post processing for now

    # the include pathes changed in 5.1.x due
    # to the pluggable storage engine clenups,
    # it also dependes on whether we build against
    # mysql source or installed headers
    if test "x$MYSQL_SRCDIR" = "x"
    then 
      IBASE=$MYSQL_CONFIG_INCLUDE
    else
      IBASE=$MYSQL_SRCDIR
    fi
    MYSQL_CHECK_VERSION([5.1.0], [
      IBASE="$IBASE/storage/ndb"
    ],[
      IBASE="$IBASE/ndb"
    ])
    if test "x$MYSQL_SRCDIR" != "x"
    then 
      IBASE="$MYSQL_SRCDIR/include"
    fi

    # add the ndbapi specifc include dirs
    ADDFLAGS="$ADDFLAGS $IBASE"
    ADDFLAGS="$ADDFLAGS $IBASE/ndbapi"
    ADDFLAGS="$ADDFLAGS $IBASE/mgmapi"

    MYSQL_CFLAGS="$MYSQL_CFLAGS $ADDFLAGS"
    MYSQL_CXXFLAGS="$MYSQL_CXXFLAGS $ADDFLAGS"

    # check for ndbapi header file NdbApi.hpp
    AC_LANG_PUSH(C++)
    OLD_CXXFLAGS=$CXXFLAGS
    CXXFLAGS="$CXXFLAGS $MYSQL_CXXFLAGS"
    AC_CHECK_HEADER([NdbApi.hpp],,[AC_ERROR(["Can't find NdbApi header files"])])
    CXXFLAGS=$OLD_CXXFLAGS
    AC_LANG_POP()

    # check for the ndbapi client library
    AC_LANG_PUSH(C++)
    OLD_LIBS=$LIBS
    LIBS="$LIBS $MYSQL_LIBS -lmysys -lmystrings"
    OLD_LIBS=$LIBS
    LIBS="$LIBS $MYSQL_LIBS"
    AC_CHECK_LIB([ndbclient],[ndb_init],,[AC_ERROR(["Can't find NdbApi client lib"])]) 
    LIBS=$OLD_LIBS
    LIBS=$OLD_LIBS
    AC_LANG_POP()

    # add the ndbapi specific static libs
    MYSQL_LIBS="$MYSQL_LIBS -lndbclient -lmysys -lmystrings "    

  ],[
    AC_ERROR(["NdbApi needs at lest MySQL 5.0"])
  ])
])



dnl set up variables for compilation of UDF extensions
dnl 
dnl MYSQL_USE_UDF_API()
dnl
AC_DEFUN([MYSQL_USE_UDF_API], [
  # add regular MySQL C flags
  ADDFLAGS=$MYSQL_CONFIG_INCLUDE 

  MYSQL_CFLAGS="$MYSQL_CFLAGS $ADDFLAGS"    
  MYSQL_CXXFLAGS="$MYSQL_CXXFLAGS $ADDFLAGS"    

  MYSQL_DEBUG_SERVER()
])



dnl set up variables for compilation of plugins
dnl 
dnl MYSQL_USE_PLUGIN_API()
dnl
AC_DEFUN([MYSQL_USE_PLUGIN_API], [
  # plugin interface is only availabe starting with MySQL 5.1
  MYSQL_NEED_VERSION([5.1.0])

  # for plugins the recommended way to include plugin.h 
  # is <mysql/plugin.h>, not <plugin.h>, so we have to
  # strip thetrailing /mysql from the include paht 
  # reported by mysql_config
  ADDFLAGS=$(echo $MYSQL_CONFIG_INCLUDE | sed -e"s/\/mysql\$//g")

  MYSQL_CFLAGS="$MYSQL_CFLAGS $ADDFLAGS -DMYSQL_DYNAMIC_PLUGIN"    
  MYSQL_CXXFLAGS="$MYSQL_CXXFLAGS $ADDFLAGS"    

  MYSQL_PLUGIN_DIR=$($MYSQL_CLIENT -BNe "show variables like 'plugin_dir'" | sed -e "s/^plugin_dir\t//g")
])