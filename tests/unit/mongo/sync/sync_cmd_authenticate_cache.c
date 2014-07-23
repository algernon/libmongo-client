#include "test.h"
#include "mongo.h"
#include "config.h"

#include <errno.h>
#include <sys/socket.h>
#include "libmongo-private.h"

void
test_mongo_sync_cmd_authenticate_cache (void)
{
  mongo_sync_conn_recovery_cache *cache;
  mongo_sync_connection *c;

  begin_network_tests (8);

  cache = mongo_sync_conn_recovery_cache_new ();
  mongo_sync_conn_recovery_cache_seed_add (cache,
                                           config.primary_host,
                                           config.primary_port);

  c = mongo_sync_connect_recovery_cache (cache, TRUE);

  mongo_sync_cmd_user_add (c, config.db, "test", "s3kr1+");

  ok (mongo_sync_cmd_authenticate (c, config.db, "test", "s3kr1+") == TRUE,
      "mongo_sync_cmd_authenticate() works");

  mongo_sync_disconnect (c);

  ok ((cache->auth.db != NULL) && (strcmp (cache->auth.db, config.db) == 0),
      "db is cached");

  ok ((cache->auth.user != NULL) && (strcmp (cache->auth.user, "test") == 0),
      "user is cached");

  ok ((cache->auth.pw != NULL) && (strcmp (cache->auth.pw, "s3kr1+") == 0),
      "pw is cached");

  c = mongo_sync_connect_recovery_cache (cache, TRUE);

  ok (c->auth.db != NULL, "db is loaded from cache");

  ok (c->auth.user != NULL, "username is loaded from cache");

  ok (c->auth.pw != NULL, "password is loaded from cache");

  ok (mongo_sync_cmd_authenticate (c,
                                   c->auth.db,
                                   c->auth.user,
                                   c->auth.pw) == TRUE,
      "mongo_sync_cmd_authenticate() works with cached auth. credentials");

  mongo_sync_disconnect (c);
  mongo_sync_conn_recovery_cache_free (cache);

  end_network_tests ();
}

RUN_TEST (8, mongo_sync_cmd_authenticate_cache);
