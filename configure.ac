m4_define([cryptopANT_major_version], [1])
m4_define([cryptopANT_minor_version], [2])
m4_define([cryptopANT_micro_version], [0])
m4_define([cryptopANT_version], [cryptopANT_major_version.cryptopANT_minor_version.cryptopANT_micro_version])

AC_INIT([cryptopANT], [cryptopANT_version], [ant@isi.edu], [cryptopANT])
dnl m4_pattern_allow(AC_CONFIG_MACRO_DIRS)
AC_CONFIG_MACRO_DIR([m4])
AC_PROG_CC
AC_C_BIGENDIAN()
AM_PROG_CC_C_O

# Check headers
AC_CHECK_HEADERS([openssl/blowfish.h], HAVE_OPENSSL=1, HAVE_OPENSSL=0)
AC_CHECK_HEADERS([openssl/sha.h],,                     HAVE_OPENSSL=0)

# Check for POSIX regular expressions support.
AC_CHECK_HEADERS([regex.h], HAVE_REGEX_H=1,            HAVE_REGEX_H=0)

if test "x$HAVE_REGEX_H" = "x1"; then
    AC_CHECK_FUNCS([regcomp regexec],,                 HAVE_REGEX=0)
else
    HAVE_REGEX=0
fi
if test "x$HAVE_REGEX_H" = "x0"; then
	AC_MSG_FAILURE([regex library is not found: make sure glibc-devel is installed])
fi
AC_CHECK_LIB([crypto], [BF_ecb_encrypt],,              HAVE_OPENSSL=0)
if test "x$HAVE_OPENSSL_H" = "x0"; then
     AC_MSG_FAILURE([ssl is not found: make sure openssl-devel is installed])
fi

AC_CHECK_MEMBER([struct in6_addr.s6_addr32],
	[AC_DEFINE([HAVE_S6_ADDR32], [1])],
	[
		AC_CHECK_MEMBER([struct in6_addr.__u6_addr.__u6_addr32],
			[AC_DEFINE([HAVE__U6_ADDR32], [1])],
			[AC_MSG_ERROR([CAN'T find s6_addr32])],
			[#include <netinet/in.h>])
	], [#include <netinet/in.h>])

AC_CHECK_FUNCS([strlcpy])

AC_C_CONST
AC_TYPE_SIZE_T
AC_TYPE_UINT32_T

# Check --enable-warn-all
AC_ARG_ENABLE([warn-all], [AS_HELP_STRING([--enable-warn-all], [Enable all compiler warnings])], [AX_CFLAGS_WARN_ALL()])

# Check --with-extra-cflags
AC_ARG_WITH([extra-cflags], [AS_HELP_STRING([--with-extra-cflags=CFLAGS], [Add extra CFLAGS])], [
  AC_MSG_NOTICE([appending extra CFLAGS... $withval])
  AS_VAR_APPEND(CFLAGS, [" $withval"])
])

# Check --with-extra-ldflags
AC_ARG_WITH([extra-ldflags], [AS_HELP_STRING([--with-extra-ldflags=CFLAGS], [Add extra LDFLAGS])], [
  AC_MSG_NOTICE([appending extra LDFLAGS... $withval])
  AS_VAR_APPEND(LDFLAGS, [" $withval"])
])

# Check --without-scramble_ips
build_scramble_ips=yes
AC_ARG_WITH([scramble_ips], [AS_HELP_STRING([--without-scramble_ips], [Do not build scramble_ips (default built)])], [
  if test "x$withval" = "xno"; then
    AC_MSG_NOTICE([NOT building scramble_ips])
    build_scramble_ips=no
  fi
])
AM_CONDITIONAL([BUILD_SCRAMBLE_IPS], [test "x$build_scramble_ips" = "xyes"])

AC_CONFIG_FILES([Makefile cryptopANT.spec])
AC_ENABLE_SHARED
AC_ENABLE_STATIC
AM_INIT_AUTOMAKE([-Wall -Werror foreign subdir-objects])
m4_ifdef([AM_PROG_AR], [AM_PROG_AR])
LT_INIT

AC_SUBST([PACKAGE_VERSION], [cryptopANT_version])
AC_SUBST([PACKAGE_VERSION_MAJOR], [cryptopANT_major_version])
AC_SUBST([PACKAGE_VERSION_MINOR], [cryptopANT_minor_version])
AC_SUBST([PACKAGE_VERSION_MICRO], [cryptopANT_micro_version])
AC_OUTPUT
