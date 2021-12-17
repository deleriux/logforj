AC_INIT([logforj], [0.3], [matthew@ife.onl])

AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([foreign -Wall -Wno-extra-portability -Werror subdir-objects])

LT_INIT
AC_PROG_CC
AC_CONFIG_HEADERS([config.h])

PKG_CHECK_MODULES([MNL], libmnl)

AC_SEARCH_LIBS([pthread_key_create], [pthread])

AX_CHECK_COMPILE_FLAG([-std=c11], [
  CFLAGS+=" -std=c11"
], [
  echo "C compiler cannot compile C11 code"
  exit -1
])

AC_SUBST([AM_CPPFLAGS], [-D_GNU_SOURCE])
AC_CONFIG_FILES([Makefile der/Makefile logforj/Makefile])
AC_OUTPUT
