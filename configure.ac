AC_INIT([logforj], [0.4], [matthew@ife.onl])

AC_CONFIG_MACRO_DIRS([m4])
AM_INIT_AUTOMAKE([foreign -Wall -Wno-extra-portability -Werror subdir-objects])

LT_INIT
AC_PROG_CC
AC_CONFIG_HEADERS([config.h])

PKG_CHECK_MODULES([MNL], libmnl)
PKG_CHECK_MODULES([NFTNL], libnftnl)

AC_SEARCH_LIBS([pthread_key_create], [pthread])
CFLAGS+=" -std=C99"

AC_SUBST([AM_CPPFLAGS], [-D_GNU_SOURCE])
AC_CONFIG_FILES([Makefile der/Makefile logforj/Makefile])
AC_OUTPUT
