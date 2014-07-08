LMC_CURRENT			= 5
LMC_REVISION			= 0
LMC_AGE				= 5

lib_LTLIBRARIES			= libmongo-client.la
libmongo_client_la_LIBADD	= @GLIB_LIBS@ @OPENSSL_LIBS@
libmongo_client_la_CFLAGS	= @GLIB_CFLAGS@ @OPENSSL_CFLAGS@
libmongo_client_la_LDFLAGS	= -version-info ${LMC_CURRENT}:${LMC_REVISION}:${LMC_AGE}

libmongo_client_la_SOURCES	= \
	compat.c compat.h \
	bson.c bson.h \
	mongo-wire.c mongo-wire.h \
    mongo-ssl.c mongo-ssl.h \
	mongo-client.c mongo-client.h \
	mongo-utils.c mongo-utils.h \
	mongo-sync.c mongo-sync.h \
	mongo-sync-cursor.c mongo-sync-cursor.h \
	mongo-sync-pool.c mongo-sync-pool.h \
	sync-gridfs.c sync-gridfs.h \
	sync-gridfs-chunk.c sync-gridfs-chunk.h \
	sync-gridfs-stream.c sync-gridfs-stream.h \
	mongo.h \
	libmongo-private.h libmongo-macros.h

libmongo_client_includedir	= $(includedir)/mongo-client
libmongo_client_include_HEADERS	= \
	bson.h mongo-wire.h mongo-client.h mongo-ssl.h mongo-utils.h \
	mongo-sync.h mongo-sync-cursor.h mongo-sync-pool.h \
	sync-gridfs.h sync-gridfs-chunk.h sync-gridfs-stream.h \
	mongo.h

if HAVE_VERSIONING
libmongo_client_la_LDFLAGS += \
	-Wl,--version-script,$(top_srcdir)/src/libmongo-client.ver
libmongo_client_la_DEPENDENCIES	= ${top_srcdir}/src/libmongo-client.ver
endif

pkgconfigdir			= $(libdir)/pkgconfig
pkgconfig_DATA			= libmongo-client.pc

CLEANFILES			= *.gcda *.gcno *.gcov
CLEANDIRS			= coverage

coverage:
	$(AM_V_GEN)
	$(AM_V_at) SOURCES="$(SOURCES)" builddir="$(builddir)" srcdir="$(srcdir)" top_srcdir="$(top_srcdir)" $(top_srcdir)/tests/coverage.sh

clean-local:
	-test -z "$(CLEANDIRS)" || rm -rf "$(CLEANDIRS)"

.PHONY: coverage
