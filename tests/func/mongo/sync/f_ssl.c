#include "test.h"
#include <mongo.h>
#include <glib.h>
#include "libmongo-private.h"

#define TEST_CASES 8

// TODO: Add more test cases

void
test_func_mongo_sync_ssl_connect (void)
{
  mongo_sync_connection *conn = NULL;
  // 1. Trusted Fingerprints Test (for 3party)
  GList *trusted_fps = NULL; 
  trusted_fps = g_list_append (trusted_fps, "SHA1:00:DE:AD:BE:EF"); // invalid fingerprint

  mongo_ssl_conf_set_trusted_fingerprints (config.ssl_settings, trusted_fps);

  conn = mongo_sync_ssl_connect (config.primary_host, config.primary_port, TRUE, config.ssl_settings);

  ok (conn == NULL && (mongo_ssl_get_last_verify_result (config.ssl_settings) == MONGO_SSL_V_ERR_UNTRUSTED_FP), 
     "SSL connection should fail with untrusted fingerprint");

  g_list_append (trusted_fps, "SHA1:26:08:4E:33:50:2C:E1:AD:CD:37:87:56:30:4E:A9:7B:D5:AD:30:02"); // 3party/server.pem

  conn = mongo_sync_ssl_connect (config.primary_host, config.primary_port, TRUE, config.ssl_settings);
  
  ok (((conn != NULL) && (mongo_ssl_get_last_verify_result (config.ssl_settings) == MONGO_SSL_V_OK_TRUSTED_FP)), 
     "SSL connection should work with trusted fingerprint");
  
  mongo_sync_disconnect (conn);

  // 2. Trusted DN Test (for 3party) 
  mongo_ssl_conf_set_trusted_fingerprints (config.ssl_settings, NULL);
  GList *trusted_DNs = NULL;
  trusted_DNs = g_list_append (trusted_DNs, "*, O=Example Inc, ST=Some-State, C=*");

  mongo_ssl_conf_set_trusted_DNs (config.ssl_settings, trusted_DNs);
  
  conn = mongo_sync_ssl_connect (config.primary_host, config.primary_port, TRUE, config.ssl_settings);

  ok ((conn == NULL) && (mongo_ssl_get_last_verify_result (config.ssl_settings) == MONGO_SSL_V_ERR_UNTRUSTED_DN), 
      "SSL connection should fail with untrusted DN");
  
  g_list_append (trusted_DNs, 
                 "CN=127.0.0.1, ST=hu, C=hu, emailAddress=server@example.com, O=libmongo_client_test, OU=test_server");

  conn = mongo_sync_ssl_connect (config.primary_host, config.primary_port, TRUE, config.ssl_settings);

  ok ((conn != NULL) && (mongo_ssl_get_last_verify_result (config.ssl_settings) == MONGO_SSL_V_OK_ALL), 
      "SSL connection should work with trusted DN");

  mongo_sync_disconnect (conn);
}

void
test_func_mongo_sync_ssl_insert_query (void)
{
  mongo_sync_connection *conn = NULL;
  bson *test_doc = bson_new ();
  mongo_packet *p = NULL;
  gchar *test_string =  g_strdup_printf ("%s:%s:%d", __FILE__, __func__, __LINE__);
  bson_append_string (test_doc, test_string, "ok", -1);
  bson_finish (test_doc);
  
  conn = mongo_sync_ssl_connect (config.primary_host, config.primary_port, TRUE, config.ssl_settings);
  //conn = mongo_sync_connect (config.primary_host, config.primary_port, TRUE);
  mongo_sync_conn_set_auto_reconnect (conn, TRUE);
  
  ok (conn != NULL, "connection should work without whitelists");

  ok (mongo_sync_cmd_insert (conn, config.ns, test_doc, NULL) == TRUE, "inserting a document should work via SSL");

  //FIXME: Skipping this test (see mongo_sync_cmd_delete () bug with mongo 2.6)
  //p = mongo_sync_cmd_query (conn, config.ns, 0, 0, 1, test_doc, NULL);

  //ok (p != NULL, 
  //     "querying the recently inserted document should work via SSL");

  mongo_wire_packet_free (p);

  shutdown (conn->super.fd, SHUT_RDWR);
  sleep (3);

  ok (mongo_sync_cmd_delete (conn, config.ns, 0, test_doc) == TRUE, "automatic reconnection over SSL should work (at this time: attempting delete command)");

  ok (mongo_sync_cmd_query (conn, config.ns, 0, 0, 1, test_doc, NULL) == NULL, "test document should not exist after delete");

  mongo_sync_disconnect (conn);
  bson_free (test_doc);
  g_free (test_string);
}

void 
test_func_ssl (void)
{
  begin_ssl_tests (TEST_CASES);
  test_func_mongo_sync_ssl_connect ();
  test_func_mongo_sync_ssl_insert_query ();
  end_ssl_tests ();
}


RUN_TEST (TEST_CASES, func_ssl);
