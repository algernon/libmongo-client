#include "test.h"
#include "tap.h"
#include "mongo.h"

#include <sys/socket.h>
#include "libmongo-private.h"

// Right now, just an SSL-enabled version of sync_cmd_delete.c TODO: Make a complex unit test for checking SSL support
// via the synchronous wrapper API !!!

void
test_mongo_sync_cmd_delete_net_secondary_ssl (void)
{
  mongo_sync_connection *conn;
  bson *b;
  GList *l;

  skip (!config.secondary_host, 2,
        "Secondary server not configured");

  conn = mongo_sync_ssl_connect (config.primary_host, config.primary_port,
                             TRUE, config.ssl_settings);

  b = bson_new ();
  bson_append_string (b, "unit-test", __FILE__, -1);
  bson_append_boolean (b, "delete-me", TRUE);
  bson_finish (b);
  mongo_sync_cmd_insert (conn, config.ns, b, NULL);

  mongo_sync_disconnect (conn);

  conn = mongo_sync_ssl_connect (config.secondary_host, config.secondary_port,
                             TRUE, config.ssl_settings);
  mongo_sync_conn_set_auto_reconnect (conn, TRUE);

  ok (mongo_sync_cmd_delete (conn, config.ns, 0, b) == TRUE,
      "mongo_sync_cmd_delete() can reconnect to master");
  mongo_sync_disconnect (conn);

  conn = mongo_sync_ssl_connect (config.primary_host, config.primary_port,
                             TRUE, config.ssl_settings);
  mongo_sync_cmd_insert (conn, config.ns, b, NULL);
  mongo_sync_disconnect (conn);

  conn = mongo_sync_ssl_connect (config.secondary_host, config.secondary_port,
                             TRUE, config.ssl_settings);
  mongo_sync_conn_set_auto_reconnect (conn, TRUE);

  shutdown (conn->super.fd, SHUT_RDWR);

  l = conn->rs.hosts;
  while (l)
    {
      g_free (l->data);
      l = g_list_delete_link (l, l);
    }
  conn->rs.hosts = NULL;

  l = conn->rs.seeds;
  while (l)
    {
      g_free (l->data);
      l = g_list_delete_link (l, l);
    }
  conn->rs.seeds = NULL;

  sleep (3);

  ok (mongo_sync_cmd_delete (conn, config.ns, 0, b) == FALSE,
      "mongo_sync_cmd_delete() fails if it can't reconnect to master");

  mongo_sync_disconnect (conn);
  bson_free (b);

  endskip;
}

void
test_mongo_sync_cmd_delete_net_ssl (void)
{
  mongo_sync_connection *conn;
  bson *b;

  begin_ssl_tests (4);

  conn = mongo_sync_ssl_connect (config.primary_host, config.primary_port, TRUE, config.ssl_settings);
  mongo_sync_conn_set_auto_reconnect (conn, TRUE);

  b = bson_new ();
  bson_append_string (b, "unit-test", __FILE__, -1);
  bson_append_boolean (b, "delete-me", TRUE);
  bson_finish (b);
  mongo_sync_cmd_insert (conn, config.ns, b, NULL);

  ok (mongo_sync_cmd_delete (conn, config.ns, 0, b) == TRUE,
      "mongo_sync_cmd_delete() works");

  mongo_sync_cmd_insert (conn, config.ns, b, NULL);

  shutdown (conn->super.fd, SHUT_RDWR);
  sleep (3);

  ok (mongo_sync_cmd_delete (conn, config.ns, 0, b) == TRUE,
      "mongo_sync_cmd_delete() automatically reconnects");

  mongo_sync_disconnect (conn);
  bson_free (b);

  test_mongo_sync_cmd_delete_net_secondary_ssl ();
 
  end_ssl_tests ();
}

void
test_mongo_sync_cmd_delete_ssl (void)
{
  mongo_sync_connection *c;
  bson *b;

  c = test_make_fake_sync_conn (-1, FALSE);
  b = test_bson_generate_full ();

  ok (mongo_sync_cmd_delete (NULL, "test.ns", 0, b) == FALSE,
      "mongo_sync_cmd_delete() fails with a NULL connection");
  ok (mongo_sync_cmd_delete (c, NULL, 0, b) == FALSE,
      "mongo_sync_cmd_delete() fails with a NULL namespace");
  ok (mongo_sync_cmd_delete (c, "test.ns", 0, NULL) == FALSE,
      "mongo_sync_cmd_delete() fails with a NULL selector");

  ok (mongo_sync_cmd_delete (c, "test.ns", 0, b) == FALSE,
      "mongo_sync_cmd_delete() fails with a bogus FD");

  bson_free (b);
  mongo_sync_disconnect (c);

  test_mongo_sync_cmd_delete_net_ssl ();
}

RUN_TEST (8, mongo_sync_cmd_delete_ssl);
