SUBDIRS		= libtap

bson_unit_tests	= \
		unit/bson/bson_new \
		unit/bson/bson_empty \
		unit/bson/bson_validate_key \
		\
		unit/bson/bson_append_string \
		unit/bson/bson_append_double \
		unit/bson/bson_append_boolean \
		unit/bson/bson_append_utc_datetime \
		unit/bson/bson_append_null \
		unit/bson/bson_append_int32 \
		unit/bson/bson_append_int64 \
		unit/bson/bson_append_regexp \
		unit/bson/bson_append_binary \
		unit/bson/bson_append_js_code \
		unit/bson/bson_append_symbol \
		unit/bson/bson_append_js_code_w_scope \
		unit/bson/bson_append_timestamp \
		unit/bson/bson_append_oid \
		unit/bson/bson_append_document \
		unit/bson/bson_append_array \
		\
		unit/bson/bson_reset \
		unit/bson/bson_new_from_data \
		\
		unit/bson/bson_build \
		unit/bson/bson_build_full \
		\
		unit/bson/bson_type_as_string \
		\
		unit/bson/bson_cursor_new \
		unit/bson/bson_find \
		unit/bson/bson_cursor_next \
		unit/bson/bson_cursor_find_next \
		unit/bson/bson_cursor_find \
		unit/bson/bson_cursor_type \
		unit/bson/bson_cursor_type_as_string \
		unit/bson/bson_cursor_key \
		\
		unit/bson/bson_cursor_get_string \
		unit/bson/bson_cursor_get_double \
		unit/bson/bson_cursor_get_document \
		unit/bson/bson_cursor_get_array \
		unit/bson/bson_cursor_get_binary \
		unit/bson/bson_cursor_get_oid \
		unit/bson/bson_cursor_get_boolean \
		unit/bson/bson_cursor_get_utc_datetime \
		unit/bson/bson_cursor_get_regex \
		unit/bson/bson_cursor_get_javascript \
		unit/bson/bson_cursor_get_symbol \
		unit/bson/bson_cursor_get_javascript_w_scope \
		unit/bson/bson_cursor_get_int32 \
		unit/bson/bson_cursor_get_timestamp \
		unit/bson/bson_cursor_get_int64

bson_func_tests	= \
		func/bson/huge_doc \
		func/bson/f_weird_types

bson_perf_tests	= \
		perf/bson/p_bson_find

mongo_utils_unit_tests	= \
		unit/mongo/utils/oid_init \
		unit/mongo/utils/oid_new \
		unit/mongo/utils/oid_new_with_time \
		unit/mongo/utils/oid_as_string \
		unit/mongo/utils/parse_addr

mongo_wire_unit_tests	= \
		unit/mongo/wire/packet_new \
		unit/mongo/wire/packet_get_set_header \
		unit/mongo/wire/packet_get_set_header_raw \
		unit/mongo/wire/packet_get_set_data \
		\
		unit/mongo/wire/reply_packet_get_header \
		unit/mongo/wire/reply_packet_get_data \
		unit/mongo/wire/reply_packet_get_nth_document \
		\
		unit/mongo/wire/cmd_update \
		unit/mongo/wire/cmd_insert \
		unit/mongo/wire/cmd_insert_n \
		unit/mongo/wire/cmd_query \
		unit/mongo/wire/cmd_get_more \
		unit/mongo/wire/cmd_delete \
		unit/mongo/wire/cmd_kill_cursors \
		unit/mongo/wire/cmd_custom

mongo_client_unit_tests	= \
		unit/mongo/client/connect \
		unit/mongo/client/disconnect \
		unit/mongo/client/packet_send \
		unit/mongo/client/packet_recv \
		unit/mongo/client/connection_set_timeout \
		unit/mongo/client/connection_get_requestid

mongo_client_func_tests = \
		func/mongo/client/f_client_big_packet

mongo_sync_unit_tests	= \
		unit/mongo/sync/sync_connect \
		unit/mongo/sync/sync_connect_cache \
		unit/mongo/sync/sync_conn_seed_add \
		unit/mongo/sync/sync_conn_seed_add_cache \
		unit/mongo/sync/sync_reconnect \
		unit/mongo/sync/sync_disconnect \
		unit/mongo/sync/sync_get_set_auto_reconnect \
		unit/mongo/sync/sync_get_set_safe_mode \
		unit/mongo/sync/sync_get_set_slaveok \
		unit/mongo/sync/sync_get_set_max_insert_size \
		unit/mongo/sync/sync_cmd_update \
		unit/mongo/sync/sync_cmd_insert \
		unit/mongo/sync/sync_cmd_insert_n \
		unit/mongo/sync/sync_cmd_query \
		unit/mongo/sync/sync_cmd_get_more \
		unit/mongo/sync/sync_cmd_delete \
		unit/mongo/sync/sync_cmd_kill_cursors \
		unit/mongo/sync/sync_cmd_custom \
		unit/mongo/sync/sync_cmd_count \
		unit/mongo/sync/sync_cmd_create \
		unit/mongo/sync/sync_cmd_exists \
		unit/mongo/sync/sync_cmd_drop \
		unit/mongo/sync/sync_cmd_get_last_error \
		unit/mongo/sync/sync_cmd_reset_error \
		unit/mongo/sync/sync_cmd_is_master \
		unit/mongo/sync/sync_cmd_ping \
		unit/mongo/sync/sync_cmd_user_add \
		unit/mongo/sync/sync_cmd_user_add_with_roles \
		unit/mongo/sync/sync_cmd_user_remove \
		unit/mongo/sync/sync_cmd_authenticate \
		unit/mongo/sync/sync_cmd_authenticate_cache \
		unit/mongo/sync/sync_cmd_index_create \
		unit/mongo/sync/sync_cmd_index_drop \
		unit/mongo/sync/sync_cmd_index_drop_all \
		unit/mongo/sync/sync_connect_from_cache_enforce_primary

mongo_sync_func_tests	= \
		func/mongo/sync/f_sync_max_insert_size \
		func/mongo/sync/f_sync_conn_seed_add \
		func/mongo/sync/f_sync_safe_mode \
		func/mongo/sync/f_sync_safe_mode_cache \
		func/mongo/sync/f_sync_auto_reconnect \
		func/mongo/sync/f_sync_auto_reconnect_cache \
		func/mongo/sync/f_sync_oidtest \
		func/mongo/sync/f_sync_auto_reauth \
		func/mongo/sync/f_sync_invalid_getlasterror \
		func/mongo/sync/f_sync_write_error

mongo_sync_cursor_unit_tests	= \
		unit/mongo/sync-cursor/sync_cursor_new \
		unit/mongo/sync-cursor/sync_cursor_next \
		unit/mongo/sync-cursor/sync_cursor_get_data \
		unit/mongo/sync-cursor/sync_cursor_free

mongo_sync_cursor_func_tests	= \
		func/mongo/sync-cursor/f_sync_cursor_iterate \
		func/mongo/sync-cursor/f_sync_cursor_tailable

mongo_sync_pool_unit_tests	= \
		unit/mongo/sync-pool/sync_pool_new \
		unit/mongo/sync-pool/sync_pool_free \
		unit/mongo/sync-pool/sync_pool_pick \
		unit/mongo/sync-pool/sync_pool_return

mongo_sync_pool_func_tests	= \
		func/mongo/sync-pool/f_sync_pool

mongo_sync_gridfs_unit_tests	= \
		unit/mongo/sync-gridfs/sync_gridfs_new \
		unit/mongo/sync-gridfs/sync_gridfs_free \
		unit/mongo/sync-gridfs/sync_gridfs_get_set_chunk_size \
		unit/mongo/sync-gridfs/sync_gridfs_list \
		unit/mongo/sync-gridfs/sync_gridfs_remove \
		unit/mongo/sync-gridfs/sync_gridfs_file_get_metadata

mongo_sync_gridfs_chunk_unit_tests = \
		unit/mongo/sync-gridfs-chunk/sync_gridfs_chunked_find \
		unit/mongo/sync-gridfs-chunk/sync_gridfs_chunked_file_new_from_buffer \
		unit/mongo/sync-gridfs-chunk/sync_gridfs_chunked_file_free \
		unit/mongo/sync-gridfs-chunk/sync_gridfs_chunked_file_cursor_new \
		unit/mongo/sync-gridfs-chunk/sync_gridfs_chunked_file_cursor_get_chunk

mongo_sync_gridfs_chunk_func_tests = \
		func/mongo/sync-gridfs-chunk/f_sync_gridfs_chunk

mongo_sync_gridfs_stream_unit_tests = \
		unit/mongo/sync-gridfs-stream/sync_gridfs_stream_find \
		unit/mongo/sync-gridfs-stream/sync_gridfs_stream_new \
		unit/mongo/sync-gridfs-stream/sync_gridfs_stream_read \
		unit/mongo/sync-gridfs-stream/sync_gridfs_stream_write \
		unit/mongo/sync-gridfs-stream/sync_gridfs_stream_seek \
		unit/mongo/sync-gridfs-stream/sync_gridfs_stream_close

mongo_sync_gridfs_stream_func_tests = \
		func/mongo/sync-gridfs-stream/f_sync_gridfs_stream

UNIT_TESTS	= ${bson_unit_tests} ${mongo_utils_unit_tests} \
		${mongo_wire_unit_tests} ${mongo_client_unit_tests} \
		${mongo_sync_unit_tests} ${mongo_sync_cursor_unit_tests} \
		${mongo_sync_pool_unit_tests} ${mongo_sync_gridfs_unit_tests} \
		${mongo_sync_gridfs_chunk_unit_tests} \
		${mongo_sync_gridfs_stream_unit_tests}
FUNC_TESTS	= ${bson_func_tests} ${mongo_sync_func_tests} \
		${mongo_client_func_tests} \
		${mongo_sync_cursor_func_tests} ${mongo_sync_pool_func_tests} \
		${mongo_sync_gridfs_func_tests} \
		${mongo_sync_gridfs_chunk_func_tests} \
		${mongo_sync_gridfs_stream_func_tests}
PERF_TESTS	= ${bson_perf_tests}
TESTCASES	= ${UNIT_TESTS} ${FUNC_TESTS} ${PERF_TESTS}

check_PROGRAMS	= ${TESTCASES} test_cleanup

AM_CFLAGS = -I$(top_srcdir)/src/ -I${top_srcdir}/tests/libtap/ @GLIB_CFLAGS@
AM_LDFLAGS = -no-install
LDADD = $(top_builddir)/src/libmongo-client.la ${top_builddir}/tests/libtap/libtap.la @GLIB_LIBS@

EXTRA_DIST = README \
	     runall \
	     coverage.sh \
             tools/coverage-report-entry.pl tools/coverage-report.pl \
             tools/coverage-report.xsl

PROVE      = prove -e "${PROVE_ENV}" ${PROVE_OPTIONS}

check-%: BASE=$(subst -,_,$(subst check-,,$@))
check-%: TESTCASES=$(value $(BASE)_unit_tests) $(value $(BASE)_func_tests) $(value $(BASE)_tests)
check-%: check-recursive test_cleanup ${TESTCASES}
	$(AM_V_at) ${builddir}/test_cleanup
	$(AM_V_GEN) srcdir=${srcdir} ${PROVE} ${TESTCASES}
	$(AM_V_at) ${builddir}/test_cleanup

check: check-recursive test_cleanup ${TESTCASES}
	$(AM_V_at) ${builddir}/test_cleanup
	$(AM_V_GEN) srcdir=${srcdir} ${PROVE} ${TESTCASES}
	$(AM_V_at) ${builddir}/test_cleanup

.PHONY: check
