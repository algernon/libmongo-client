#include "test.h"
#include <mongo.h>
#include <glib.h>
#include "libmongo-private.h"

#include <fcntl.h>
#include <sys/types.h>

#define THREAD_POOL_SIZE 5
#define TEST_CASES (11 + THREAD_POOL_SIZE * 6)

void
test_func_mongo_sync_ssl_connect (void)
{
  char trusted_fp[64];
  int fd;

  fd = open("./ssl/3party/server.sign", O_RDONLY);  
  read(fd, trusted_fp, 64);
  close(fd);

  mongo_sync_connection *conn = NULL;
  // 1. Trusted Fingerprints Test (for 3party)
  GList *trusted_fps = NULL; 
  trusted_fps = g_list_append (trusted_fps, "SHA1:00:DE:AD:BE:EF"); // invalid fingerprint

  mongo_ssl_set_trusted_fingerprints (config.ssl_settings, trusted_fps);

  conn = mongo_sync_ssl_connect (config.primary_host, config.primary_port, TRUE, config.ssl_settings);

  ok (conn == NULL && (mongo_ssl_get_last_verify_result (config.ssl_settings) == MONGO_SSL_V_ERR_UNTRUSTED_FP), 
     "SSL connection fails with untrusted fingerprint");

  g_list_append (trusted_fps, trusted_fp); // 3party/server.pem

  conn = mongo_sync_ssl_connect (config.primary_host, config.primary_port, TRUE, config.ssl_settings);
  
  ok (((conn != NULL) && (mongo_ssl_get_last_verify_result (config.ssl_settings) == MONGO_SSL_V_OK_TRUSTED_FP)), 
     "SSL connection works with trusted fingerprint");
  
  mongo_sync_disconnect (conn);

  // 2. Trusted DN Test (for 3party) 
  mongo_ssl_set_trusted_fingerprints (config.ssl_settings, NULL);
  GList *trusted_DNs = NULL;
  trusted_DNs = g_list_append (trusted_DNs, "*, O=Example Inc, ST=Some-State, C=*");

  mongo_ssl_set_trusted_DNs (config.ssl_settings, trusted_DNs);
  
  conn = mongo_sync_ssl_connect (config.primary_host, config.primary_port, TRUE, config.ssl_settings);

  ok ((conn == NULL) && (mongo_ssl_get_last_verify_result (config.ssl_settings) == MONGO_SSL_V_ERR_UNTRUSTED_DN), 
      "SSL connection fails with untrusted DN");
  
  g_list_append (trusted_DNs, 
                 "CN=127.0.0.1, ST=hu, C=hu, emailAddress=server@example.com, O=libmongo_client_test, OU=test_server");

  conn = mongo_sync_ssl_connect (config.primary_host, config.primary_port, TRUE, config.ssl_settings);

  ok ((conn != NULL) && (mongo_ssl_get_last_verify_result (config.ssl_settings) == MONGO_SSL_V_OK_ALL), 
      "SSL connection works with trusted DN");

  mongo_sync_disconnect (conn);
}

void
test_func_mongo_sync_ssl_insert_query (void)
{
  mongo_sync_connection *conn = NULL;
  bson *test_doc = bson_new ();
  mongo_packet *p = NULL;
  //gchar *test_string =  g_strdup_printf ("%s:%s:%d", __FILE__, __func__, __LINE__);
  gchar *test_string = g_strdup ("test_func_mongo_sync_ssl_insert_query");
  bson_append_string (test_doc, test_string, "ok", -1);
  bson_finish (test_doc);
  
  conn = mongo_sync_ssl_connect (config.primary_host, config.primary_port, TRUE, config.ssl_settings);
  //conn = mongo_sync_connect (config.primary_host, config.primary_port, TRUE);
  mongo_sync_conn_set_auto_reconnect (conn, TRUE);
  
  ok (conn != NULL, "connection works without whitelists");

  ok (mongo_sync_cmd_insert (conn, config.ns, test_doc, NULL) == TRUE, "inserting a document works via SSL");

  p = mongo_sync_cmd_query (conn, config.ns, 0, 0, 1, test_doc, NULL);

  ok (p != NULL, 
       "querying the recently inserted document works via SSL");

  mongo_wire_packet_free (p);

  shutdown (conn->super.fd, SHUT_RDWR);
  sleep (3);

  ok (mongo_sync_cmd_delete (conn, config.ns, 0, test_doc) == TRUE, "automatic reconnection over SSL should work (at this time: attempting delete command)");

  /* ok (mongo_sync_cmd_query (conn, config.ns, 0, 0, 1, test_doc, NULL) == NULL, "test document should not exist after delete");
    */
    
  mongo_sync_disconnect (conn);
  bson_free (test_doc);
  g_free (test_string);
}

gpointer
ssl_insert_thread (gpointer _c)
{
  mongo_ssl_ctx *c = (mongo_ssl_ctx*) _c;
  static int insert_count = 0;
  insert_count++;
  mongo_sync_connection *conn = mongo_sync_ssl_connect (config.primary_host, config.primary_port, TRUE, c);
  bson *test_doc = bson_new ();
  gchar *test_string =  g_strdup_printf ("%s:%d", "ssl_insert_thread", insert_count);
  bson_append_string (test_doc, test_string, "ok", -1);
  bson_finish (test_doc);
  ok (mongo_sync_cmd_insert (conn, config.ns, test_doc, NULL), "mongo_sync_cmd_insert () works in a multi-threaded scenario over SSL");
  mongo_sync_disconnect (conn);
  bson_free (test_doc);
  g_free (test_string);
}


gpointer
ssl_delete_thread (gpointer _conn) // here, we pass the connection object
{
  mongo_sync_connection *conn = (mongo_sync_connection*) _conn;
  static int delete_count = 0;
  delete_count++;
  bson *test_doc = bson_new ();
  gchar *test_string =  g_strdup_printf ("%s:%d", "ssl_insert_thread", delete_count);
  bson_append_string (test_doc, test_string, "ok", -1);
  bson_finish (test_doc);
  ok (mongo_sync_cmd_delete (conn, config.ns, 0, test_doc), "mongo_sync_cmd_delete works in a multithreaded scenario");
  bson_free (test_doc);
  g_free (test_string);
  return NULL;
}

gpointer
ssl_query_thread (gpointer _c)
{
  mongo_ssl_ctx *c = (mongo_ssl_ctx*) _c;
  guint tries;
  bson *test_doc = NULL;
  gchar *test_string;
  GThread *writer = g_thread_new ("insert", ssl_insert_thread, c);
  GThread *deleter;
  mongo_sync_connection *conn = mongo_sync_ssl_connect (config.primary_host, config.primary_port, TRUE, c);
  gboolean success = FALSE;
  g_thread_join (writer);
  sleep (1); 
  
  for(tries = 1; tries <= THREAD_POOL_SIZE; ++tries) 
    {
      test_doc = bson_new ();
      test_string = g_strdup_printf ("%s:%d", "ssl_insert_thread", tries);
      bson_append_string (test_doc, test_string, "ok", -1);
      bson_finish (test_doc);
      if (mongo_sync_cmd_query (conn, config.ns, 0, 0, 1, test_doc, NULL) != NULL) 
        {
          success = TRUE;
          break;
        }
      bson_free (test_doc);
      g_free (test_string);
      sleep (1);
    }

  ok (success, "mongo_sync_cmd_query () works with writer threads over SSL");
 
  deleter = g_thread_new ("delete", ssl_delete_thread, conn); 
 
  g_thread_join (deleter);
  g_thread_unref (deleter);
  mongo_sync_disconnect (conn);
  g_thread_unref (writer);

  return NULL;
}

gpointer
ssl_ping_success_thread (gpointer _c)
{
  mongo_ssl_ctx *c = (mongo_ssl_ctx*) _c;
  sleep ( rand () % 5 );
  mongo_ssl_lock (c);
  mongo_ssl_set_crl (c, NULL);
  mongo_sync_connection *conn = mongo_sync_ssl_connect (config.primary_host, config.primary_port, TRUE, c);
  ok (conn != NULL, "connection should succeed on a thread that does not initiate CRL check");
  ok (mongo_sync_cmd_ping (conn), "ping should succeed on a thread that does not initiate CRL check");
  mongo_ssl_unlock (c);
  mongo_sync_disconnect (conn);

  return NULL;
}


gpointer
ssl_ping_fail_thread (gpointer _c)
{
  mongo_ssl_ctx *c = (mongo_ssl_ctx*) _c;
  sleep ( rand () % 3 );
  mongo_ssl_lock (c);
  mongo_ssl_set_crl (c, "./ssl/3party/ca_crl.pem");
  mongo_sync_connection *conn = mongo_sync_ssl_connect (config.primary_host, config.primary_port, TRUE, c);
  ok ((conn == NULL) && (mongo_ssl_get_last_verify_result (c) == MONGO_SSL_V_ERR_PROTO), "connection should fail on a thread that initiates CRL check");
  // we could ping here, but why? :)
  mongo_ssl_unlock (c);

  return NULL;
}

gpointer 
ssl_ping_thread (gpointer _c)
{
  mongo_ssl_ctx *c = (mongo_ssl_ctx*) _c;
  GThread *s, *f;
  s = g_thread_new ("ping_success", ssl_ping_success_thread, c);
  f = g_thread_new ("ping_fail", ssl_ping_fail_thread, c);

  g_thread_join (s);
  g_thread_join (f);
  g_thread_unref (s);
  g_thread_unref (f);

  return NULL;
}

void 
test_func_mongo_ssl_multithread (void)
{
  // 1. Many threads sharing the same context previously set up
  GThreadPool *thread_pool = g_thread_pool_new (ssl_query_thread, config.ssl_settings, THREAD_POOL_SIZE, TRUE, NULL);
  guint i;
  for (i = 0; i < THREAD_POOL_SIZE; ++i)
    g_thread_pool_push (thread_pool, config.ssl_settings, NULL);

  g_thread_pool_free (thread_pool, FALSE, TRUE);
  // 2. Many threads sharing the same context each manipulating the context
  srand (time (NULL));
  thread_pool = g_thread_pool_new (ssl_ping_thread, config.ssl_settings, THREAD_POOL_SIZE, TRUE, NULL);
  for (i = 0; i < THREAD_POOL_SIZE; ++i)
    g_thread_pool_push (thread_pool, config.ssl_settings, NULL);

  g_thread_pool_free (thread_pool, FALSE, TRUE);
}

void 
test_func_mongo_ssl_untrusted (void)
{
  mongo_sync_connection *conn;
  mongo_ssl_ctx *alternative = g_new0 (mongo_ssl_ctx, 1);
  mongo_ssl_init (alternative);
  mongo_ssl_set_cert (alternative, "./ssl/3party/client.pem");
  mongo_ssl_set_ca (alternative, "./ssl/certs/mongodb.pem");
  mongo_ssl_set_key (alternative, "./ssl/3party/client.pem", "test_client");
  conn = mongo_sync_ssl_connect (config.primary_host, config.primary_port, TRUE, alternative);
  ok (conn == NULL, "By default, invalid certificates are not accepted");
  mongo_ssl_set_security (alternative, FALSE, TRUE);
  conn = mongo_sync_ssl_connect (config.primary_host, config.primary_port, TRUE, alternative);
  ok (conn == NULL, "When certificate is not required, still gets validated if provided");
  mongo_ssl_set_crl (config.ssl_settings, "./ssl/3party/ca_crl.pem");
  mongo_ssl_set_security (config.ssl_settings, TRUE, FALSE);
  conn = mongo_sync_ssl_connect (config.primary_host, config.primary_port, TRUE, config.ssl_settings);
  ok (conn != NULL, "Connection works in untrusted mode");
  mongo_sync_disconnect (conn);
  mongo_ssl_clear (alternative);
  g_free (alternative);
}

void 
test_func_ssl (void)
{
  begin_ssl_tests (TEST_CASES);
  mongo_ssl_set_crl (config.ssl_settings, NULL);
  test_func_mongo_sync_ssl_connect ();
  test_func_mongo_sync_ssl_insert_query ();
  test_func_mongo_ssl_multithread ();
  test_func_mongo_ssl_untrusted ();
  end_ssl_tests ();
}


RUN_TEST (TEST_CASES, func_ssl);
