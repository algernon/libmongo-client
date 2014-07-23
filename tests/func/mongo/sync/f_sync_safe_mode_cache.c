#include "test.h"
#include <mongo.h>

#include <errno.h>
#include <string.h>

#include "libmongo-private.h"

void
test_func_mongo_sync_safe_mode_basics_cache (void)
{
  mongo_sync_connection *conn;
  mongo_sync_conn_recovery_cache *cache;

  const bson *docs[10];
  bson *b1, *b2, *b3, *b4, *cmd;
  mongo_packet *p;
  gchar *error;

  mongo_util_oid_init (0);

  b1 = bson_new ();
  bson_append_string (b1, "func_mongo_sync_safe_mode", "works", -1);
  bson_finish (b1);

  b2 = bson_new ();
  bson_append_int32 (b2, "int32", 1984);
  bson_finish (b2);

  b3 = test_bson_generate_full ();
  b4 = test_bson_generate_full ();

  docs[0] = b1;
  docs[1] = b2;
  docs[2] = b3;
  docs[3] = b4;

  cache = mongo_sync_conn_recovery_cache_new ();

  mongo_sync_conn_recovery_cache_seed_add (cache,
                                           config.primary_host,
                                           config.primary_port);

  conn = mongo_sync_connect_recovery_cache (cache, FALSE);

  /* Test inserts */
  mongo_sync_conn_set_safe_mode (conn, FALSE);
  ok (mongo_sync_cmd_insert_n (conn, config.ns, 4, docs) == TRUE,
      "mongo_sync_cmd_insert_n() should not fail with safe mode off");

  mongo_sync_conn_set_safe_mode (conn, TRUE);
  ok (mongo_sync_cmd_insert_n (conn, config.ns, 4, docs) == FALSE,
      "mongo_sync_cmd_insert_n() should fail with safe mode on");

  /* Test a custom command */
  cmd = bson_new ();
  bson_append_int32 (cmd, "bogusCommand", 1);
  bson_finish (cmd);

  mongo_sync_cmd_reset_error (conn, config.db);
  mongo_sync_conn_set_safe_mode (conn, FALSE);
  p = mongo_sync_cmd_custom (conn, config.db, cmd);
  mongo_sync_cmd_get_last_error (conn, config.db, &error);
  ok (p == NULL && strcmp (error, "no such cmd: bogusCommand") == 0,
      "mongo_sync_cmd_custom() with a bogus command fails with safe-mode off");
  bson_free (cmd);
  g_free (error);

  cmd = bson_new ();
  bson_append_int32 (cmd, "bogusCommand2", 1);
  bson_finish (cmd);
  mongo_sync_cmd_reset_error (conn, config.db);
  mongo_sync_conn_set_safe_mode (conn, TRUE);
  p = mongo_sync_cmd_custom (conn, config.db, cmd);
  mongo_sync_cmd_get_last_error (conn, config.db, &error);
  ok (p == NULL && strcmp (error, "no such cmd: bogusCommand2") == 0,
      "mongo_sync_cmd_custom() with a bogus command fails with safe-mode on");
  bson_free (cmd);
  g_free (error);

  mongo_sync_disconnect (conn);
  mongo_sync_conn_recovery_cache_free (cache);

  bson_free (b1);
  bson_free (b2);
  bson_free (b3);
  bson_free (b4);
}

#define INVALID_NS "1234567890123456789012345678901234567890123456789012345678901234567890.test"

void
test_func_mongo_sync_safe_mode_invalid_db_cache (void)
{
  mongo_sync_connection *conn;
  mongo_sync_conn_recovery_cache *cache;
  bson *b;
  const bson *docs[1];

  b = bson_new ();
  bson_append_int32 (b, "int32", 1984);
  bson_finish (b);

  docs[0] = b;

  cache = mongo_sync_conn_recovery_cache_new ();

  mongo_sync_conn_recovery_cache_seed_add (cache,
                                           config.primary_host,
                                           config.primary_port);

  conn = mongo_sync_connect_recovery_cache (cache, TRUE);

  mongo_sync_conn_set_safe_mode (conn, TRUE);

  ok (mongo_sync_cmd_insert_n (conn, INVALID_NS, 1, docs) == FALSE,
      "mongo_sync_cmd_insert_n() should fail with safe mode on and an invalid NS");

  mongo_sync_disconnect (conn);
  mongo_sync_conn_recovery_cache_free (cache);
  bson_free (b);
}

void
test_func_mongo_sync_safe_mode_cache (void)
{
  test_func_mongo_sync_safe_mode_basics_cache ();
  test_func_mongo_sync_safe_mode_invalid_db_cache ();
}

RUN_NET_TEST (5, func_mongo_sync_safe_mode_cache);
