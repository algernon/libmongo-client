#include "test.h"
#include "mongo.h"

#define NETWORK_TESTS_NUM 5

void
test_mongo_sync_connect_from_cache_enforce_primary (void)
{
  mongo_sync_conn_recovery_cache *cache;
  mongo_sync_connection *c;

  begin_network_tests (NETWORK_TESTS_NUM);

  cache = mongo_sync_conn_recovery_cache_new ();

  skip (!config.secondary_host,
        NETWORK_TESTS_NUM,
        "Secondary server not configured");

  ok (mongo_sync_conn_recovery_cache_seed_add (cache, config.secondary_host,
                                               config.secondary_port) == TRUE,
      "mongo_sync_conn_recovery_seed_add() works");

  ok ((c = mongo_sync_connect_recovery_cache (cache, TRUE)) != NULL,
      "mongo_sync_connect_recovery_cache() works");

  ok (mongo_sync_cmd_is_master(c) == FALSE,
      "Secondary server should not be The Master.");

  mongo_sync_disconnect (c);

  ok ((c = mongo_sync_connect_recovery_cache (cache, FALSE)) != NULL,
      "mongo_sync_connect_recovery_cache() works");

  ok (mongo_sync_cmd_is_master (c) == TRUE,\
      "Retrieved connection should be The Master when it is forced to be.");

  mongo_sync_disconnect (c);

  endskip;

  mongo_sync_conn_recovery_cache_free (cache);

  end_network_tests ();
}

RUN_TEST (NETWORK_TESTS_NUM, mongo_sync_connect_from_cache_enforce_primary);
