#include "test.h"
#include "mongo.h"

#include <sys/socket.h>
#include "libmongo-private.h"


void
test_mongo_ssl (void)
{
  mongo_sync_connection *conn;
  bson *b, *q;

  begin_ssl_tests (4);

  // Try bad private key password
  mongo_ssl_conf_set_key (config.ssl_settings, mongo_ssl_conf_get_key (), "invalid_pw");

  conn = mongo_sync_connect (config.primary_host, config.primary_port, TRUE);
  ok (conn == NULL,
      "connection should fail with invalid private key password");

  // Try AES cipher set
  mongo_ssl_conf_set_ciphers (config.ssl_settings, MONGO_SSL_CIPHERS_AES);
  mongo_ssl_conf_set_key (config.ssl_settings, mongo_ssl_conf_get_key (), "test_client");
  conn = mongo_sync_connect (config.primary_host, config.primary_port, TRUE);

  ok (conn != NULL,
      "connection should work with MONGO_SSL_CIPHERS_AES");
  
  q = bson_new ();
  bson_append_boolean (q, "sync_cmd_query_test_ssl", TRUE);
  
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

  test_mongo_sync_cmd_delete_net_secondary ();

  end_ssl_tests ();
}

RUN_TEST (8, test_mongo_ssl);
