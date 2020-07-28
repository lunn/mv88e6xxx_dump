dnl Process this file with autoconf to produce a configure script.
AC_PREREQ([2.68])

AC_INIT([mv88e6xxx_dump], [0.1.0], [andrew@lunn.ch])
AC_CONFIG_SRCDIR([config.h.in])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])

AM_INIT_AUTOMAKE([1.11 foreign no-define no-dist-gzip dist-xz tar-ustar -Wno-portability])
AM_MAINTAINER_MODE([enable])

dnl Support silent build rules. Disable
dnl by either passing --disable-silent-rules to configure or passing V=1
dnl to make
AM_SILENT_RULES([yes])

dnl Required programs
AC_PROG_CC
AC_PROG_INSTALL
AX_PTHREAD

dnl Initialize libtool
LT_PREREQ([2.2])
LT_INIT

dnl Require libmnl
PKG_CHECK_MODULES([LIBMNL], [libmnl])
AC_SUBST(LIBMNL_CFLAGS)
AC_SUBST(LIBMNL_LIBS)

AC_CONFIG_FILES([Makefile])
AC_OUTPUT

echo "
    mv88e6xxx_dump $VERSION
    ==============================================

    compiler:        ${CC}
    cflags:          ${CFLAGS}
    maintainer mode: ${USE_MAINTAINER_MODE}
"
