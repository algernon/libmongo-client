#include "test.h"
#include "mongo.h"

void
test_mongo_sync_conn_recovery_cache_connection (void)
{
  mongo_sync_conn_recovery_cache *cache;
  mongo_sync_connection *c = NULL;

  cache = mongo_sync_conn_recovery_cache_new ();

  ok (mongo_sync_connect_recovery_cache (cache, FALSE) == NULL,
      "mongo_sync_connect_recovery_cache() should fail when cache is empty");

  begin_ssl_tests (4);

  ok (mongo_sync_conn_recovery_cache_seed_add (cache,
                                               config.primary_host,
                                               config.primary_port) == TRUE,
      "mongo_sync_conn_recovery_cache_seed_add() works");

  ok ((c = mongo_sync_ssl_connect_recovery_cache (cache, FALSE, config.ssl_settings)) != NULL,
      "mongo_sync_connect_recovery_cache() works");

  mongo_sync_disconnect (c);

  ok ((c = mongo_sync_ssl_connect_recovery_cache (cache, FALSE, config.ssl_settings)) != NULL,
      "mongo_sync_connect_recovery_cache() works after disconnect");

  mongo_sync_disconnect (c);

  mongo_sync_conn_recovery_cache_discard (cache);

  ok (mongo_sync_ssl_connect_recovery_cache (cache, TRUE, config.ssl_settings) == NULL,
      "mongo_sync_connect_recovery_cache() should fail when cache is discarded");

  mongo_sync_conn_recovery_cache_free (cache);

  end_ssl_tests ();
}

RUN_TEST (5, mongo_sync_conn_recovery_cache_connection);
