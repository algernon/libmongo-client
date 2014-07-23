dnl Process this file with autoconf to produce a configure script.
dnl

AC_INIT([libmongo-client],[0.1.7.1],[algernon@madhouse-project.org],[libmongo-client],[https://github.com/algernon/libmongo-client])
AM_INIT_AUTOMAKE([1.9 tar-ustar foreign no-dist-gzip dist-xz subdir-objects])

dnl ***************************************************************************
dnl dependencies

GLIB_MIN_VERSION="2.12.0"
OPENSSL_MIN_VERSION="0.9.8"

dnl ***************************************************************************
dnl Initial setup

AC_CONFIG_MACRO_DIR([m4])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])
AC_CONFIG_HEADERS([config.h])

AC_ARG_WITH([versioned-symbols], AS_HELP_STRING([--with-versioned-symbols],[Use versioned symbols]),[dnl
vsymldflags="-Wl,--version-script,\${srcdir}/libmongo-client.ver -Wl,-O1"
],[vsymldflags=])

dnl ***************************************************************************
dnl Checks for programs.
AC_PROG_CC
AC_PROG_CC_C_O

AC_PROG_MAKE_SET
PKG_PROG_PKG_CONFIG
LT_INIT([shared])

dnl ***************************************************************************
dnl Miscellanneous headers
dnl ***************************************************************************

AC_HEADER_STDC

dnl ***************************************************************************
dnl Header checks
dnl ***************************************************************************
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netinet/in.h sys/socket.h netdb.h])

AC_CACHE_CHECK(for struct sockaddr_storage, blb_cv_c_struct_sockaddr_storage,
  [AC_EGREP_HEADER([sockaddr_storage], sys/socket.h, blb_cv_c_struct_sockaddr_storage=yes,blb_cv_c_struct_sockaddr_storage=no)])

if test "$blb_cv_c_struct_sockaddr_storage" = "yes"; then
	AC_DEFINE(HAVE_STRUCT_SOCKADDR_STORAGE,[1],[struct sockaddr_storage is present on your system])
fi

AC_CACHE_CHECK(for struct sockaddr_in6, blb_cv_c_struct_sockaddr_in6,
  [AC_EGREP_HEADER([sockaddr_in6], netinet/in.h, blb_cv_c_struct_sockaddr_in6=yes,blb_cv_c_struct_sockaddr_in6=no)])

AC_EGREP_HEADER([MSG_NOSIGNAL], [sys/socket.h], AC_DEFINE([HAVE_MSG_NOSIGNAL], [1], [Define to 1 when your system supports MSG_NOSIGNAL]))

dnl ***************************************************************************
dnl Checks for libraries
AC_CHECK_FUNC(socket,,
 AC_CHECK_LIB(socket, socket))

AC_FUNC_MMAP
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_CHECK_FUNCS(memset socket getaddrinfo munmap strtol strerror)

dnl ***************************************************************************
dnl GLib headers/libraries
dnl ***************************************************************************

PKG_CHECK_MODULES(GLIB, glib-2.0 >= $GLIB_MIN_VERSION,,)

old_CPPFLAGS=$CPPFLAGS
CPPFLAGS="$GLIB_CFLAGS"
old_LDFLAGS=$LDFLAGS
LDFLAGS="$LDFLAGS $GLIB_LIBS"

AC_CACHE_CHECK(sanity checking Glib headers,
               blb_cv_glib_sane,
[AC_RUN_IFELSE([AC_LANG_SOURCE([[
#include <glib.h>

int main()
{
  if (sizeof(long) != GLIB_SIZEOF_LONG)
    return 1;
  return 0;
}
]])],[blb_cv_glib_sane=yes],[blb_cv_glib_sane=no],[blb_cv_glib_sane=yes])])
CPPFLAGS=$old_CPPFLAGS
LDFLAGS=$old_LDFLAGS

if test "x$blb_cv_glib_sane" = "xno"; then
	AC_MSG_ERROR([Glib headers inconsistent with current compiler setting. You might be using 32 bit Glib with a 64 bit compiler, check PKG_CONFIG_PATH])
fi

dnl Check for g_checksum_new
old_LIBS=$LIBS

dnl to make sure we're using glib from the proper path
LIBS=$GLIB_LIBS
AC_CHECK_LIB(glib-2.0, g_checksum_new, [glib_checksum="yes"; with_openssl="0"], [glib_checksum="no"; with_openssl="1"])
LIBS=$old_LIBS
if test "x$glib_checksum" = "xno"; then
  PKG_CHECK_MODULES(OPENSSL, openssl >= $OPENSSL_MIN_VERSION,, OPENSSL_LIBS="")
  dnl Using the compat stuff disables symbol versioning
  vsymldflags=""
  if test "x$OPENSSL_LIBS" = "x"; then
     AC_MSG_ERROR([OpenSSL is required when glib-2.0 << 2.16.0])
  fi
fi


AC_DEFINE_UNQUOTED(NO_GLIB_HASH_FUNCTIONS, $with_openssl, [Glib has no checksum functions])

AC_ARG_WITH([ssl], [AS_HELP_STRING([--with-ssl], [Compile with SSL support (OpenSSL)])], [with_ssl_support="1"], [with_ssl_support="0"])

if test "x$with_ssl_support" = "x1" -a "x$with_openssl" = "x0"; then 
  PKG_CHECK_MODULES(OPENSSL, openssl >= $OPENSSL_MIN_VERSION,, OPENSSL_LIBS="")
  if test "x$OPENSSL_LIBS" = "x"; then
    AC_MSG_ERROR([OpenSSL is required when configured with --with-ssl])
  fi
  with_openssl="1"
fi

AC_DEFINE_UNQUOTED(WITH_OPENSSL, $with_openssl, [Compile with OpenSSL])
AM_CONDITIONAL([HAVE_OPENSSL], [test $with_openssl -eq 1])

dnl ***************************************************************************
dnl misc features to be enabled
dnl ***************************************************************************
AC_C_INLINE

AC_MSG_CHECKING(whether to enable IPv6 support)
if test "x$blb_cv_c_struct_sockaddr_in6" = "xyes"; then
	enable_ipv6=yes
	AC_MSG_RESULT(yes)
else
	enable_ipv6=no
	AC_MSG_RESULT(no)
fi

AC_MSG_CHECKING([whether to enable symbol versioning])
AC_SUBST(vsymldflags)
if test -z "${vsymldflags}"; then
   AC_MSG_RESULT([no])
else
   AC_MSG_RESULT([yes, ${vsymldflags}])
fi

enable_value () {
   if test -z "$1"; then
      echo 0
   else
      echo 1
   fi
}

AC_DEFINE_UNQUOTED(VERSIONED_SYMBOLS, `enable_value ${vsymldflags}`,
                   [Define to 1 if symbol versioning is enabled])
AC_DEFINE_UNQUOTED(PACKAGE, "$PACKAGE", [package name])
AC_DEFINE_UNQUOTED(VERSION, "$VERSION", [version number])

AC_CONFIG_FILES([Doxyfile
	Makefile
	docs/Makefile
	docs/tutorial/Makefile
	examples/Makefile
	src/Makefile
	src/libmongo-client.pc
	tests/Makefile
	tests/libtap/Makefile
])
AC_OUTPUT
