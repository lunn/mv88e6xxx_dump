#!/bin/sh
# Run this to generate all the initial makefiles, etc.

srcdir=`dirname $0`
test -z "$srcdir" && srcdir=.
REQUIRED_AUTOMAKE_VERSION=1.9
PKG_NAME=mv88e6xx_dump

(test -f $srcdir/configure.ac \
  && test -f $srcdir/mv88e6xxx_dump.c) || {
    echo -n "**Error**: Directory "\`$srcdir\'" does not look like the"
    echo " top-level $PKG_NAME directory"
    exit 1
}

(cd $srcdir;
    autoreconf --force --install --verbose
    if test -z "$NOCONFIGURE"; then
        ./configure --enable-maintainer-mode "$@"
    fi
)
