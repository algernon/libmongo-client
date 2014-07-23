/* mongo-sync-pool.c - libmongo-client connection pool implementation
 * Copyright 2011, 2012 Gergely Nagy <algernon@balabit.hu>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/** @file src/mongo-sync-pool.c
 * MongoDB connection pool API implementation.
 */

#include <errno.h>
#include <string.h>
#include <glib.h>
#include <mongo.h>
#include "libmongo-private.h"

/** @internal A connection pool object. */
struct _mongo_sync_pool
{
  gint nmasters; /**< Number of master connections in the pool. */
  gint nslaves; /**< Number of slave connections in the pool. */

  GList *masters; /**< List of master connections in the pool. */
  GList *slaves; /**< List of slave connections in the pool. */
};

static mongo_sync_pool_connection *
_mongo_sync_pool_connect (const gchar *host, gint port, gboolean slaveok, mongo_ssl_ctx *ssl_config)
{
  mongo_sync_connection *c = NULL;
  mongo_sync_pool_connection *conn;

#if WITH_OPENSSL
  if (ssl_config != NULL)
    {
      if (ssl_config->ctx != NULL)
        {
          c = mongo_sync_ssl_connect (host, port, slaveok, ssl_config);
        }
    } 
  else  
#endif
    {
      c = mongo_sync_connect (host, port, slaveok);
    }

  if (!c)
    return NULL;
  
  conn = g_realloc (c, sizeof (mongo_sync_pool_connection));
  conn->pool_id = 0;
  conn->in_use = FALSE;

  return conn;
}

static
mongo_sync_pool *
_mongo_sync_pool_new (const gchar *host,
                     gint port,
                     gint nmasters, gint nslaves, mongo_ssl_ctx *ssl_config)
{
  mongo_sync_pool *pool;
  mongo_sync_pool_connection *conn;
  gint i, j = 0;

  if (!host || port < 0)
    {
      errno = EINVAL;
      return NULL;
    }
  if (nmasters < 0 || nslaves < 0)
    {
      errno = ERANGE;
      return NULL;
    }
  if (nmasters + nslaves <= 0)
    {
      errno = EINVAL;
      return NULL;
    }

  conn = _mongo_sync_pool_connect (host, port, FALSE, ssl_config);
  if (!conn)
    return FALSE;

  if (!mongo_sync_cmd_is_master ((mongo_sync_connection *)conn))
    {
      mongo_sync_disconnect ((mongo_sync_connection *)conn);
      errno = EPROTO;
      return NULL;
    }

  pool = g_new0 (mongo_sync_pool, 1);
  pool->nmasters = nmasters;
  pool->nslaves = nslaves;

  for (i = 0; i < pool->nmasters; i++)
    {
      mongo_sync_pool_connection *c;

      c = _mongo_sync_pool_connect (host, port, FALSE, ssl_config);
      c->pool_id = i;

      pool->masters = g_list_append (pool->masters, c);
    }

  for (i = 0; i < pool->nslaves; i++)
    {
      mongo_sync_pool_connection *c;
      gchar *shost = NULL;
      gint sport = 27017;
      GList *l;
      gboolean found = FALSE;
      gboolean need_restart = (j != 0);

      /* Select the next secondary */
      l = g_list_nth (conn->super.rs.hosts, j);

      do
        {
          j++;
          if (l && mongo_util_parse_addr ((gchar *)l->data, &shost, &sport))
            {
              if (sport != port || strcmp (host, shost) != 0)
                {
                  found = TRUE;
                  break;
                }
            }
          l = g_list_next (l);
          if (!l && need_restart)
            {
              need_restart = FALSE;
              j = 0;
              l = g_list_nth (conn->super.rs.hosts, j);
            }
        }
      while (l);

      if (!found)
        {
          pool->nslaves = i - 1;
          break;
        }

      /* Connect to it*/
      c = _mongo_sync_pool_connect (shost, sport, TRUE, ssl_config);
      c->pool_id = pool->nmasters + i + 1;

      pool->slaves = g_list_append (pool->slaves, c);
    }

  mongo_sync_disconnect ((mongo_sync_connection *)conn);
  return pool;
}

mongo_sync_pool *
mongo_sync_pool_new (const gchar *host,
                     gint port,
                     gint nmasters, gint nslaves)
{
  return _mongo_sync_pool_new (host, port, nmasters, nslaves, NULL);
}

#if WITH_OPENSSL
mongo_sync_pool *
mongo_sync_pool_new_ssl (const gchar *host,
                         gint port,
                         gint nmasters, gint nslaves, mongo_ssl_ctx *ssl_config)
{
  return _mongo_sync_pool_new (host, port, nmasters, nslaves, ssl_config);
}
#endif

void
mongo_sync_pool_free (mongo_sync_pool *pool)
{
  GList *l;

  if (!pool)
    return;

  l = pool->masters;
  while (l)
    {
      mongo_sync_disconnect ((mongo_sync_connection *)l->data);
      l = g_list_delete_link (l, l);
    }

  l = pool->slaves;
  while (l)
    {
      mongo_sync_disconnect ((mongo_sync_connection *)l->data);
      l = g_list_delete_link (l, l);
    }

  g_free (pool);
}

mongo_sync_pool_connection *
mongo_sync_pool_pick (mongo_sync_pool *pool,
                      gboolean want_master)
{
  GList *l;

  if (!pool)
    {
      errno = ENOTCONN;
      return NULL;
    }

  if (!want_master)
    {
      l = pool->slaves;

      while (l)
        {
          mongo_sync_pool_connection *c;

          c = (mongo_sync_pool_connection *)l->data;
          if (!c->in_use)
            {
              c->in_use = TRUE;
              return c;
            }
          l = g_list_next (l);
        }
    }

  l = pool->masters;
  while (l)
    {
      mongo_sync_pool_connection *c;

      c = (mongo_sync_pool_connection *)l->data;
      if (!c->in_use)
        {
          c->in_use = TRUE;
          return c;
        }
      l = g_list_next (l);
    }

  errno = EAGAIN;
  return NULL;
}

gboolean
mongo_sync_pool_return (mongo_sync_pool *pool,
                        mongo_sync_pool_connection *conn)
{
  if (!pool)
    {
      errno = ENOTCONN;
      return FALSE;
    }
  if (!conn)
    {
      errno = EINVAL;
      return FALSE;
    }

  if (conn->pool_id > pool->nmasters)
    {
      mongo_sync_pool_connection *c;

      if (conn->pool_id - pool->nmasters > pool->nslaves ||
          pool->nslaves == 0)
        {
          errno = ERANGE;
          return FALSE;
        }

      c = (mongo_sync_pool_connection *)g_list_nth_data
        (pool->slaves, conn->pool_id - pool->nmasters - 1);
      c->in_use = FALSE;
      return TRUE;
    }
  else
    {
      mongo_sync_pool_connection *c;

      c = (mongo_sync_pool_connection *)g_list_nth_data (pool->masters,
                                                         conn->pool_id);
      c->in_use = FALSE;
      return TRUE;
    }

  errno = ENOENT;
  return FALSE;
}
