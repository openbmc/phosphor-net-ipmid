# Initialization
AC_PREREQ([2.69])
AC_INIT([phosphor-net-ipmid], [1.0], [https://github.com/openbmc/phosphor-net-ipmid/issues])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE([subdir-objects -Wall -Werror foreign dist-xz])
AM_SILENT_RULES([yes])

# Checks for programs.
AC_PROG_CXX
AM_PROG_AR
AC_PROG_INSTALL
AC_PROG_MAKE_SET
LT_INIT

# Checks for typedefs, structures, and compiler characteristics.
AX_CXX_COMPILE_STDCXX_14([noext])
AX_APPEND_COMPILE_FLAGS([-Wall -Werror], [CXXFLAGS])

# Checks for libraries.
PKG_CHECK_MODULES([SYSTEMD], [libsystemd >= 221])
PKG_CHECK_MODULES([CRYPTO], [libcrypto])
AC_CHECK_LIB([mapper], [mapper_get_service], ,[AC_MSG_ERROR([Could not find libmapper...openbmc/phosphor-objmgr package required])])

# Checks for header files.
AC_CHECK_HEADER(systemd/sd-bus.h, ,[AC_MSG_ERROR([Could not find systemd/sd-bus.h...systemd developement package required])])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
