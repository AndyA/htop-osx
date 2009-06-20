#!/bin/sh

aclocal
autoconf
autoheader
glibtoolize --copy
automake --add-missing --copy


