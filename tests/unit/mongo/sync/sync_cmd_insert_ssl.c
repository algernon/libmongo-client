#include "test.h"
#include "mongo.h"

#include <sys/socket.h>
#include "libmongo-private.h"

void
test_mongo_sync_cmd_insert_ssl (void)
{
  mongo_sync_connection *c;
  bson *b1, *b2;

  c = test_make_fake_sync_conn (-1, FALSE);
  b1 = test_bson_generate_full ();
  b2 = test_bson_generate_full ();

  ok (mongo_sync_cmd_insert (NULL, "test.ns", b1, b2, NULL) == FALSE,
      "mongo_sync_cmd_insert() fails with a NULL connection");
  ok (mongo_sync_cmd_insert (c, NULL, b1, b2, NULL) == FALSE,
      "mongo_sync_cmd_insert() fails with a NULL namespace");
  ok (mongo_sync_cmd_insert (c, "test.ns", NULL) == FALSE,
      "mongo_sync_cmd_insert() fails with no documents to insert");
  ok (mongo_sync_cmd_insert (c, "test.ns", b1, b2, NULL) == FALSE,
      "mongo_sync_cmd_insert() fails with a bogus FD");

  mongo_sync_disconnect (c);
  bson_free (b1);
  bson_free (b2);

  begin_ssl_tests (4);

  b1 = bson_new ();
  bson_append_string (b1, "sync_cmd_insert", "works", -1);
  bson_finish (b1);
  b2 = bson_new ();
  bson_append_int32 (b2, "int32", 1984);
  bson_finish (b2);

  c = mongo_sync_ssl_connect (config.primary_host, config.primary_port,
                          TRUE, config.ssl_settings);
  mongo_sync_conn_set_auto_reconnect (c, TRUE);

  ok (mongo_sync_cmd_insert (c, config.ns, b1, b2, NULL) == TRUE,
      "mongo_sync_cmd_insert() works");

  shutdown (c->super.fd, SHUT_RDWR);
  sleep (3);

  ok (mongo_sync_cmd_insert (c, config.ns, b1, b2, NULL) == TRUE,
      "mongo_sync_cmd_insert() automatically reconnects");

  mongo_sync_disconnect (c);

  /*
   * Tests involving a secondary
   */
  skip (!config.secondary_host, 2, "Secondary host not set up");

  c = mongo_sync_ssl_connect (config.secondary_host, config.secondary_port,
                          TRUE, config.ssl_settings);
  mongo_sync_conn_set_auto_reconnect (c, TRUE);

  ok (c && mongo_sync_cmd_is_master (c) == FALSE,
      "Connected to a secondary");

  ok (mongo_sync_cmd_insert (c, config.ns, b1, b2, NULL) == TRUE,
      "mongo_sync_cmd_insert() automatically reconnects to master");
  mongo_sync_disconnect (c);

  endskip;

  bson_free (b1);
  bson_free (b2);

  end_ssl_tests ();
}

RUN_TEST (8, mongo_sync_cmd_insert_ssl);
