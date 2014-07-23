#include "test.h"
#include "mongo.h"

void
test_mongo_sync_pool_new (void)
{
  ok (mongo_sync_pool_new ("example.com", 27017, 0, 0) == NULL,
      "mongo_sync_pool_new() needs at least one connection");
  ok (mongo_sync_pool_new (NULL, 27017, 1, 0) == NULL,
      "mongo_sync_pool_new() should fail without a HOST");
  ok (mongo_sync_pool_new ("example.com", -1, 1, 0) == NULL,
      "mongo_sync_pool_new() should fail with an invalid port");
  ok (mongo_sync_pool_new ("example.com", 27017, -1, 0) == NULL,
      "mongo_sync_pool_new() should fail with an invalid number of masters");
  ok (mongo_sync_pool_new ("example.com", 27017, 10, -1) == NULL,
      "mongo_sync_pool_new() should fail with an invalid number of slaves");
}

RUN_TEST (5, mongo_sync_pool_new);
