#include "test.h"
#include <mongo.h>

#include <errno.h>
#include <sys/socket.h>

#include "libmongo-private.h"

void
test_func_mongo_sync_auto_reconnect_cache (void)
{
  mongo_sync_conn_recovery_cache *cache;
  mongo_sync_connection *conn;
  bson *b;
  mongo_packet *p;
  GList *hosts;
  gchar *primary_addr;
  const gchar *error_msg;

  primary_addr = g_strdup_printf ("%s:%d", config.primary_host, config.primary_port);

  b = bson_new ();
  bson_append_int32 (b, "f_sync_auto_reconnect", 1);
  bson_finish (b);

  cache = mongo_sync_conn_recovery_cache_new ();

  mongo_sync_conn_recovery_cache_seed_add (cache,
                                           config.primary_host,
                                           config.primary_port);

  conn = mongo_sync_connect_recovery_cache (cache,
                                            TRUE);

  ok (mongo_sync_cmd_insert (conn, config.ns, b, NULL) == TRUE);

  shutdown (conn->super.fd, SHUT_RDWR);
  sleep (1);

  ok (mongo_sync_cmd_insert (conn, config.ns, b, NULL) == FALSE,
      "Inserting fails with auto-reconnect turned off, and a broken "
      "connection");

  error_msg = mongo_sync_conn_get_last_error (conn);

  ok (error_msg != NULL, "We have an error msg when insert fails.");

  mongo_sync_conn_set_auto_reconnect (conn, TRUE);

  ok (mongo_sync_cmd_insert (conn, config.ns, b, NULL) == TRUE,
      "Inserting works with auto-reconnect turned on, and a broken "
      "connection");

  error_msg = mongo_sync_conn_get_last_error (conn);

  ok (error_msg == NULL,
      "After a succesful insert we shouldn't have an error msg.");

  mongo_sync_conn_set_auto_reconnect (conn, FALSE);

  shutdown (conn->super.fd, SHUT_RDWR);
  sleep (1);

  ok (mongo_sync_cmd_insert (conn, config.ns, b, NULL) == FALSE,
      "Turning off auto-reconnect works");

  skip (!config.secondary_host, 7,
        "Secondary host not set up");

  shutdown (conn->super.fd, SHUT_RDWR);
  sleep (1);

  p = mongo_sync_cmd_query (conn, config.ns, 0, 0, 1, b, NULL);
  ok (p == NULL,
      "Query fails with auto-reconnect turned off");

  error_msg = mongo_sync_conn_get_last_error(conn);
  ok (error_msg != NULL, "We have an error msg after a failure query.");

  mongo_sync_conn_set_auto_reconnect (conn, TRUE);
  p = mongo_sync_cmd_query (conn, config.ns, 0, 0, 1, b, NULL);
  ok (p != NULL,
      "Query does reconnect with auto-reconnect turned on");

  ok (mongo_sync_conn_get_last_error(conn) == NULL,
      "We shouldn't have any error messages after a successful operation.");

  mongo_wire_packet_free (p);

  mongo_sync_cmd_is_master (conn);

  ok (conn->rs.hosts != NULL,
      "We have hosts in the connection's replica set.");

  ok (cache->rs.hosts == NULL, "Cache is empty.");

  mongo_sync_disconnect (conn);

  ok (cache->rs.hosts != NULL, "Cache is filled by disconnect()");

  mongo_sync_conn_recovery_cache_free (cache);

  endskip;

  g_free (primary_addr);
}

RUN_NET_TEST (13, func_mongo_sync_auto_reconnect_cache);
