#include "test.h"
#include "mongo.h"

void
test_mongo_sync_connection_cache_seed_add (void)
{
  mongo_sync_conn_recovery_cache cache;

  mongo_sync_conn_recovery_cache_init(&cache);

  ok (mongo_sync_conn_recovery_cache_seed_add (&cache,
                                               "localhost",
                                               27017) == TRUE,
      "mongo_sync_connection_cache_seed_add() works");

  ok (mongo_sync_conn_recovery_cache_seed_add (&cache,
                                               NULL,
                                               27017) == FALSE,
      "mongo_sync_connection_cache_seed_add() should fail with a NULL host");

  ok (mongo_sync_conn_recovery_cache_seed_add (&cache,
                                               "localhost", 
                                               -1) == FALSE,
      "mongo_sync_connection_cache_seed_add() should fail with an invalid port");

  mongo_sync_conn_recovery_cache_discard(&cache);

  ok (mongo_sync_conn_recovery_cache_seed_add (&cache,
                                               "localhost",
                                               27017) == TRUE,
      "mongo_sync_connection_cache_seed_add() works");
}

RUN_TEST (4, mongo_sync_connection_cache_seed_add);
