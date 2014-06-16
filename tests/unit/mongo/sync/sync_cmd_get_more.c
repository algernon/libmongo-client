#include "test.h"
#include "mongo.h"

#include <errno.h>
#include <sys/socket.h>
#include "libmongo-private.h"

void
test_mongo_sync_cmd_get_more_net_secondary (void)
{
  mongo_packet *p;
  mongo_sync_connection *conn;
  bson *b;

  mongo_reply_packet_header rh;
  gint64 cid;

  skip (!config.secondary_host, 2,
        "Secondary server not configured");

  conn = mongo_sync_connect (config.secondary_host, config.secondary_port,
                             TRUE);
  b = bson_new ();
  bson_append_string (b, "test-name", __FILE__, -1);
  bson_finish (b);

  p = mongo_sync_cmd_query (conn, config.ns,
                            MONGO_WIRE_FLAG_QUERY_NO_CURSOR_TIMEOUT,
                            0, 2, b, NULL);
  bson_free (b);
  mongo_wire_reply_packet_get_header (p, &rh);
  cid = rh.cursor_id;
  mongo_wire_packet_free (p);

  p = mongo_sync_cmd_get_more (conn, config.ns, 3, cid);
  ok (p != NULL,
      "mongo_sync_cmd_get_more() works on secondary too");
  mongo_wire_packet_free (p);

  mongo_sync_reconnect (conn, TRUE);

  p = mongo_sync_cmd_get_more (conn, config.ns, 10, cid);
  ok (p == NULL && errno == EPROTO,
      "mongo_sync_cmd_get_more() can't jump servers");
  mongo_wire_packet_free (p);

  mongo_sync_disconnect (conn);

  endskip;
}

void
test_mongo_sync_cmd_get_more_net (void)
{
  mongo_packet *p;
  mongo_sync_connection *conn;
  bson *b;
  gint i;
  mongo_reply_packet_header rh;
  gint64 cid;

  begin_network_tests (4);

  conn = mongo_sync_connect (config.primary_host, config.primary_port, TRUE);
  mongo_sync_conn_set_auto_reconnect (conn, TRUE);

  b = bson_new ();
  for (i = 0; i < 40; i++)
    {
      bson_reset (b);
      bson_append_string (b, "test-name", __FILE__, -1);
      bson_append_int32 (b, "seq", i);
      bson_finish (b);

      mongo_sync_cmd_insert (conn, config.ns, b, NULL);
    }
  bson_free (b);

  b = bson_new ();
  bson_append_string (b, "test-name", __FILE__, -1);
  bson_finish (b);

  p = mongo_sync_cmd_query (conn, config.ns,
                            MONGO_WIRE_FLAG_QUERY_NO_CURSOR_TIMEOUT,
                            0, 2, b, NULL);
  bson_free (b);
  mongo_wire_reply_packet_get_header (p, &rh);
  cid = rh.cursor_id;
  mongo_wire_packet_free (p);

  p = mongo_sync_cmd_get_more (conn, config.ns, 3, cid);
  ok (p != NULL,
      "mongo_sync_cmd_get_more() works");
  mongo_wire_packet_free (p);

  errno = 0;
  shutdown (conn->super.fd, SHUT_RDWR);
  sleep (3);

  p = mongo_sync_cmd_get_more (conn, config.ns, 10, cid);
  ok (p != NULL,
      "mongo_sync_cmd_get_more() automatically reconnects");
  mongo_wire_packet_free (p);

  mongo_sync_disconnect (conn);

  test_mongo_sync_cmd_get_more_net_secondary ();

  end_network_tests ();
}

void
test_mongo_sync_cmd_get_more (void)
{
  mongo_sync_connection *c;

  c = test_make_fake_sync_conn (-1, FALSE);

  ok (mongo_sync_cmd_get_more (NULL, "test.ns", 1, 1234) == NULL,
      "mongo_sync_cmd_get_more() fails with a NULL connection");
  ok (mongo_sync_cmd_get_more (c, NULL, 1, 1234) == NULL,
      "mongo_sync_cmd_get_more() fails with a NULL namespace");

  ok (mongo_sync_cmd_get_more (c, "test.ns", 1, 1234) == NULL,
      "mongo_sync_cmd_get_more() fails with a bogus FD");
  mongo_sync_conn_set_slaveok (c, TRUE);
  ok (mongo_sync_cmd_get_more (c, "test.ns", 1, 1234) == NULL,
      "mongo_sync_cmd_get_more() fails with a bogus FD");

  mongo_sync_disconnect (c);

  test_mongo_sync_cmd_get_more_net ();
}

RUN_TEST (8, mongo_sync_cmd_get_more);
