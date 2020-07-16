AC_INIT([uget], [1.0-beta1],,, [https://github.com/troglobit/uget/])
AC_CONFIG_AUX_DIR(aux)
AM_INIT_AUTOMAKE([1.11 foreign])
AM_SILENT_RULES([yes])

AC_CONFIG_SRCDIR([src/uget.c])
AC_CONFIG_HEADER([config.h])
AC_CONFIG_FILES([Makefile src/Makefile])

PKG_PROG_PKG_CONFIG

AC_PROG_CC
AC_PROG_INSTALL

AC_ARG_WITH(ssl,
        AS_HELP_STRING([--without-ssl], [Disable HTTPS support, default: enabled]),,
        [with_ssl=yes])

AS_IF([test "x$with_ssl" != "xno"], [
	PKG_CHECK_MODULES([OpenSSL], [openssl >= 1.1.1])
	LDFLAGS="$LDFLAGS $OpenSSL_LIBS"
	CPPFLAGS="$CPPFLAGS $OpenSSL_CFLAGS"
	AC_CHECK_LIB([crypto], [EVP_EncryptInit], [],
		AC_MSG_ERROR([*** Crypto library (OpenSSL) not found!]))
	AC_CHECK_LIB([ssl], [SSL_library_init], [],
		AC_CHECK_LIB([ssl], [OPENSSL_init_ssl], [],
		AC_MSG_ERROR([*** SSL library (OpenSSL) not found!])))
	AC_CHECK_HEADERS([openssl/crypto.h openssl/x509.h openssl/pem.h openssl/ssl.h openssl/tls1.h openssl/err.h], [],
		AC_MSG_ERROR([*** Cannot find required header files!]), [
			#include <openssl/conf.h>
		])
	AC_CHECK_DECLS([SSL_COMP_free_compression_methods,SSL_CTX_set_ecdh_auto], [], [], [
		#ifdef HAVE_OPENSSL_ERR_H
		#include <openssl/err.h>
		#endif

		#ifdef HAVE_OPENSSL_RAND_H
		#include <openssl/rand.h>
		#endif

		#ifdef HAVE_OPENSSL_CONF_H
		#include <openssl/conf.h>
		#endif

		#ifdef HAVE_OPENSSL_ENGINE_H
		#include <openssl/engine.h>
		#endif
		#include <openssl/ssl.h>
		#include <openssl/evp.h>
	])
	AC_DEFINE([ENABLE_SSL], [1], [Enable HTTPS support])
])

# By default we rely on the built-in locations of Open/LibreSSL and GnuTLS,
# on error we fall back to these two locations
# For more excellent information on the topic, see this blog post
#   https://www.happyassassin.net/2015/01/12/a-note-about-ssltls-trusted-certificate-stores-and-platforms/
CAFILE1="/etc/ssl/certs/ca-certificates.crt"
CAFILE2="/etc/pki/tls/certs/ca-bundle.trust.crt"

# Add OS-specific flags
case "$host_os" in
darwin*)
   LDFLAGS="$LDFLAGS -lresolv"
   CAFILE2="/usr/local/etc/openssl/cert.pem"   # where Homebrew's libressl places it
   ;;
esac

AC_DEFINE_UNQUOTED([CAFILE1], "$CAFILE1", [First fallback location for Open/LibreSSL and GnuTLS trust db])
AC_DEFINE_UNQUOTED([CAFILE2], "$CAFILE2", [Second location for Open/LibreSSL and GnuTLS trust db])

AM_CONDITIONAL([ENABLE_SSL], test "x$with_ssl" = "xyes")

AC_OUTPUT
