#include "test.h"
#include <mongo.h>

#include <errno.h>
#include <sys/socket.h>

#include "libmongo-private.h"

void
test_func_mongo_sync_auto_reconnect_cache (void)
{
  mongo_sync_conn_recovery_cache cache;
  mongo_sync_connection *conn;
  bson *b;
  mongo_packet *p;
  GList *hosts;
  gchar *primary_addr;

  primary_addr = g_strdup_printf("%s:%d", config.primary_host, config.primary_port);

  b = bson_new ();
  bson_append_int32 (b, "f_sync_auto_reconnect", 1);
  bson_finish (b);

  mongo_sync_conn_recovery_cache_init(&cache);

  mongo_sync_conn_recovery_cache_seed_add(&cache,
                                          config.primary_host,
                                          config.primary_port);

  conn = mongo_sync_connect_recovery_cache (&cache,
                                            TRUE);

  ok (mongo_sync_cmd_insert (conn, config.ns, b, NULL) == TRUE);

  shutdown (conn->super.fd, SHUT_RDWR);
  sleep (1);

  ok (mongo_sync_cmd_insert (conn, config.ns, b, NULL) == FALSE,
      "Inserting fails with auto-reconnect turned off, and a broken "
      "connection");

  mongo_sync_conn_set_auto_reconnect (conn, TRUE);

  ok (mongo_sync_cmd_insert (conn, config.ns, b, NULL) == TRUE,
      "Inserting works with auto-reconnect turned on, and a broken "
      "connection");

  mongo_sync_conn_set_auto_reconnect (conn, FALSE);

  shutdown (conn->super.fd, SHUT_RDWR);
  sleep (1);

  ok (mongo_sync_cmd_insert (conn, config.ns, b, NULL) == FALSE,
      "Turning off auto-reconnect works");

  shutdown (conn->super.fd, SHUT_RDWR);
  sleep (1);

  p = mongo_sync_cmd_query (conn, config.ns, 0, 0, 1, b, NULL);
  ok (p == NULL,
      "Query fails with auto-reconnect turned off");

  mongo_sync_conn_set_auto_reconnect (conn, TRUE);
  p = mongo_sync_cmd_query (conn, config.ns, 0, 0, 1, b, NULL);
  ok (p != NULL,
      "Query does reconnect with auto-reconnect turned on");
  mongo_wire_packet_free (p);

  hosts = conn->rs.hosts;

  ok (cache.rs.hosts == NULL,
      "cache is discarded due to connect replace during auto-reconnect");

  ok ((conn->rs.hosts != NULL) &&
      (g_list_length(conn->rs.hosts) > 0),
      "hosts is filled in mongo_sync_connection");

  mongo_sync_disconnect (conn);

  ok ((cache.rs.hosts != NULL) &&
      (cache.rs.hosts == hosts) &&
      (g_list_length(cache.rs.hosts) > 0),
      "cache is filled by disconnect()");

  mongo_sync_conn_recovery_cache_discard (&cache);

  g_free(primary_addr);
}

RUN_NET_TEST (9, func_mongo_sync_auto_reconnect_cache);
