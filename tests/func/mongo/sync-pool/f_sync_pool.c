#include "test.h"
#include <mongo.h>

#include <errno.h>

#include "libmongo-private.h"

void
test_func_mongo_sync_pool_secondary (void)
{
  mongo_sync_pool *pool;
  mongo_sync_pool_connection *conn[11], *m, *s1, *s2, *t;
  gint i = 0;
  gboolean ret = TRUE;

  skip (!config.secondary_host, 14,
        "Secondary server not configured");

  ok (mongo_sync_pool_new (config.secondary_host,
                           config.secondary_port, 1, 10) == NULL,
      "mongo_sync_pool_new() should fail when connecting to a secondary");

  pool = mongo_sync_pool_new (config.primary_host,
                              config.primary_port, 1, 10);
  ok (pool != NULL,
      "mongo_sync_pool_new() works with slaves too");

  m = mongo_sync_pool_pick (pool, TRUE);
  ok (m != NULL,
      "mongo_sync_pool_pick() can pick a master from a mixed pool");
  ok (mongo_sync_pool_pick (pool, TRUE) == NULL,
      "mongo_sync_pool_pick() should fail if there are no more masters, and "
      "a master was requested");

  while ((conn[i] = mongo_sync_pool_pick (pool, FALSE)) != NULL)
    i++;
  cmp_ok (i, "==", 10,
          "Successfully connect to secondaries on 10 sockets");
  ok (mongo_sync_pool_pick (pool, FALSE) == NULL,
      "mongo_sync_pool_pick() should fail if there are no free connections");

  ok (mongo_sync_pool_return (pool, m) == TRUE,
      "Returning the master to the pool works");

  m = mongo_sync_pool_pick (pool, FALSE);
  ok (m != NULL,
      "mongo_sync_pool_pick() will return a master, if no more slaves are "
      "available");

  for (i = 0; i < 10; i++)
    ret = ret && mongo_sync_pool_return (pool, conn[i]);

  ok (ret == TRUE,
      "mongo_sync_pool_return() works when returning slaves");

  mongo_sync_pool_return (pool, m);

  t = mongo_sync_pool_pick (pool, FALSE);
  t->pool_id = 4242;

  errno = 0;
  ret = mongo_sync_pool_return (pool, t);
  ok (ret == FALSE && errno == ERANGE,
      "mongo_sync_pool_return() should fail if the connection ID is "
      "out of range");

  /* Test whether masters and slaves are different. */
  m = mongo_sync_pool_pick (pool, TRUE);
  s1 = mongo_sync_pool_pick (pool, FALSE);
  s2 = mongo_sync_pool_pick (pool, FALSE);

  ok (m != s1 && m != s2,
      "Picked master and slaves are different");

  ok (mongo_sync_cmd_is_master ((mongo_sync_connection *)m) == TRUE,
      "Picked master is, indeed, a master");
  ok (mongo_sync_cmd_is_master ((mongo_sync_connection *)s1) == FALSE,
      "Picked secondary is a secondary");
  ok (mongo_sync_cmd_is_master ((mongo_sync_connection *)s2) == FALSE,
      "Picked secondary is a secondary");

  mongo_sync_pool_free (pool);

  endskip;
}

void
test_func_mongo_sync_pool (void)
{
  mongo_sync_pool *pool;
  mongo_sync_pool_connection *conn[11], *t;
  gint c = 0;
  gboolean ret = TRUE;
  bson *b;
  mongo_packet *p;

  /*
   * First we test that connecting to an invalid host fails.
   */
  pool = mongo_sync_pool_new ("invalid.example.com",
                              config.primary_port, 10, 10);
  ok (pool == NULL,
      "mongo_sync_pool_new() should fail with an invalid host");

  /*
   * Next, we test whether the basics work, like connecting, picking
   * & returning.
   */

  pool = mongo_sync_pool_new (config.primary_host,
                              config.primary_port,
                              10, 0);

  ok (pool != NULL,
      "mongo_sync_pool_new() works");

  while ((conn[c] = mongo_sync_pool_pick (pool, TRUE)) != NULL)
    c++;
  cmp_ok (c, "==", 10,
          "Successfully connect to the master on 10 sockets");

  t = mongo_sync_pool_pick (pool, TRUE);
  ok (t == NULL && errno == EAGAIN,
      "Connected to the master only on 10 sockets");

  for (c = 0; c < 10; c++)
    ret = ret && mongo_sync_pool_return (pool, conn[c]);
  ok (ret == TRUE,
      "mongo_sync_pool_return() works");

  t = mongo_sync_pool_pick (pool, TRUE);
  ok (t != NULL,
      "mongo_sync_pool_pick() works after returning connections");
  mongo_sync_pool_return (pool, t);

  /*
   * Then we test whether we can perform commands on random
   * connections.
   */
  conn[0] = mongo_sync_pool_pick (pool, TRUE);
  conn[1] = mongo_sync_pool_pick (pool, TRUE);

  ok (conn[0] != conn[1],
      "Two picked connections are not the same");

  b = bson_build (BSON_TYPE_STRING, "test-name", __FILE__, -1,
                  BSON_TYPE_INT32, "i32", 1984,
                  BSON_TYPE_NONE);
  bson_finish (b);

  ok (mongo_sync_cmd_insert ((mongo_sync_connection *)conn[0],
                             config.ns, b, NULL) == TRUE,
      "mongo_sync_cmd_insert() works on a picked connection");

  p = mongo_sync_cmd_query ((mongo_sync_connection *)conn[1],
                            config.ns, 0, 0, 1, b, NULL);
  ok (p != NULL,
      "mongo_sync_cmd_query() works on a different picked connection");
  mongo_wire_packet_free (p);

  mongo_sync_pool_free (pool);

  /*
   * Test pools with a secondary aswell.
   */
  test_func_mongo_sync_pool_secondary ();
}

RUN_NET_TEST (23, func_mongo_sync_pool);
