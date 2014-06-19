#include "test.h"
#include <mongo.h>
#include <glib.h>
#include "libmongo-private.h"

#define TEST_CASES 2

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

  ok (conn == NULL && (mongo_ssl_get_last_verify_result (config.ssl_settings) == MONGO_SSL_V_ERR_UNTRUSTED_FP), "connection should fail with untrusted fingerprint");

  g_list_append (trusted_fps, "SHA1:26:08:4E:33:50:2C:E1:AD:CD:37:87:56:30:4E:A9:7B:D5:AD:30:02"); // 3party/server.pem

  conn = mongo_sync_ssl_connect (config.primary_host, config.primary_port, TRUE, config.ssl_settings);

  ok (((conn != NULL) && (mongo_ssl_get_last_verify_result (config.ssl_settings) == MONGO_SSL_V_OK_TRUSTED_FP)), "connection should work with trusted fingerprint");
  
  mongo_sync_disconnect (conn);
}

void 
test_func_ssl (void)
{
  begin_ssl_tests (TEST_CASES);
  test_func_mongo_sync_ssl_connect ();
  end_ssl_tests ();
}


RUN_TEST (TEST_CASES, func_ssl);
