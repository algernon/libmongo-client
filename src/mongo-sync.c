/* mongo-sync.c - libmongo-client synchronous wrapper API
 * Copyright 2011, 2012, 2013 Gergely Nagy <algernon@balabit.hu>
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

/** @file src/mongo-sync.c
 * MongoDB synchronous wrapper API implementation.
 */

#include "config.h"
#include "mongo.h"
#include "libmongo-private.h"

#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

static void
_list_free_full (GList **list)
{
  GList *l;

  if (!list || !*list)
    return;

  l = *list;
  while (l)
    {
      g_free (l->data);
      l = g_list_delete_link (l, l);
    }

  *list = NULL;
}

static void
_recovery_cache_store (mongo_sync_conn_recovery_cache *cache,
                       mongo_sync_connection *conn)
{
  cache->rs.seeds = conn->rs.seeds;
  cache->rs.hosts = conn->rs.hosts;
  cache->rs.primary = conn->rs.primary;

  cache->auth.db = conn->auth.db;
  cache->auth.user = conn->auth.user;
  cache->auth.pw = conn->auth.pw;
}

static void
_recovery_cache_load (mongo_sync_conn_recovery_cache *cache,
                      mongo_sync_connection *conn)
{
  conn->rs.seeds = cache->rs.seeds;
  conn->rs.hosts = cache->rs.hosts;
  conn->rs.primary = cache->rs.primary;

  conn->auth.db = cache->auth.db;
  conn->auth.user = cache->auth.user;
  conn->auth.pw = cache->auth.pw;

  conn->recovery_cache = cache;
}

static void
_mongo_sync_conn_init (mongo_sync_connection *conn, gboolean slaveok)
{
  conn->slaveok = slaveok;
  conn->safe_mode = FALSE;
  conn->auto_reconnect = FALSE;
  conn->last_error = NULL;
  conn->max_insert_size = MONGO_SYNC_DEFAULT_MAX_INSERT_SIZE;
  conn->recovery_cache = NULL;
  conn->rs.seeds = NULL;
  conn->rs.hosts = NULL;
  conn->rs.primary = NULL;
  conn->auth.db = NULL;
  conn->auth.user = NULL;
  conn->auth.pw = NULL;
}

static mongo_sync_connection *
_recovery_cache_connect (mongo_sync_conn_recovery_cache *cache,
                         const gchar *address, gint port,
                         gboolean slaveok)
{
  mongo_sync_connection *s;
  mongo_connection *c;

  c = mongo_connect (address, port);
  if (!c)
    return NULL;
  s = g_realloc (c, sizeof (mongo_sync_connection));

  _mongo_sync_conn_init (s, slaveok);

  if (!cache)
    {
      s->rs.seeds = g_list_append (NULL, g_strdup_printf ("%s:%d", address, port));
    }
  else
    {
      _recovery_cache_load (cache, s);
    }

  return s;
}

mongo_sync_connection *
mongo_sync_connect (const gchar *address, gint port,
                    gboolean slaveok)
{
  return _recovery_cache_connect (NULL, address, port, slaveok);
}

mongo_sync_connection *
mongo_sync_connect_0_1_0 (const gchar *host, gint port,
                          gboolean slaveok)
{
  return mongo_sync_connect (host, port, slaveok);
}

#if VERSIONED_SYMBOLS
__asm__(".symver mongo_sync_connect_0_1_0,mongo_sync_connect@LMC_0.1.0");
#endif

gboolean
mongo_sync_conn_seed_add (mongo_sync_connection *conn,
                          const gchar *host, gint port)
{
  if (!conn)
    {
      errno = ENOTCONN;
      return FALSE;
    }
  if (!host || port < 0)
    {
      errno = EINVAL;
      return FALSE;
    }

  conn->rs.seeds = g_list_append (conn->rs.seeds,
                                  g_strdup_printf ("%s:%d", host, port));
  return TRUE;
}

static void
_mongo_sync_connect_replace (mongo_sync_connection *old,
                             mongo_sync_connection *new)
{
  if (!old || !new)
    return;


  if (!old->recovery_cache)
    {
      g_free (old->rs.primary);
      old->rs.primary = NULL;

      /* Delete the host list. */
      _list_free_full (&old->rs.hosts);

      /* Free the replicaset struct in the new connection. These aren't
         copied, in order to avoid infinite loops. */
      _list_free_full (&new->rs.hosts);
      _list_free_full (&new->rs.seeds);
      g_free (new->rs.primary);
    }
  else
    {
      /* Delete the host list. */
      if (!new->recovery_cache->rs.seeds)
        _list_free_full (&new->rs.seeds);

      if (!new->recovery_cache->rs.hosts)
        _list_free_full (&new->rs.hosts);
      
      if (!new->recovery_cache->rs.primary)
        g_free(new->rs.primary);

      /* Free the replicaset struct in the new connection. These aren't
         copied, in order to avoid infinite loops. */
      _list_free_full (&old->recovery_cache->rs.hosts);
      g_free(old->rs.primary);
      old->rs.primary = NULL;
    }

  g_free (new->last_error);
  if (old->super.fd && (old->super.fd != new->super.fd))
    close (old->super.fd);

  old->super.fd = new->super.fd;
  old->super.request_id = -1;
  old->slaveok = new->slaveok;
  g_free (old->last_error);
  old->last_error = NULL;

  g_free (new);
}

mongo_sync_connection *
mongo_sync_reconnect (mongo_sync_connection *conn,
                      gboolean force_master)
{
  gboolean ping = FALSE;
  guint i;
  mongo_sync_connection *nc;
  gchar *host;
  gint port;

  if (!conn)
    {
      errno = ENOTCONN;
      return NULL;
    }

  ping = mongo_sync_cmd_ping (conn);

  if (ping)
    {
      if (!force_master)
        return conn;
      if (force_master && mongo_sync_cmd_is_master (conn))
        return conn;

      /* Force refresh the host list. */
      mongo_sync_cmd_is_master (conn);
    }

  /* We either didn't ping, or we're not master, and have to
   * reconnect.
   *
   * First, check if we have a primary, and if we can connect there.
   */

  if (conn->rs.primary)
    {
      if (mongo_util_parse_addr (conn->rs.primary, &host, &port))
        {
          nc = _recovery_cache_connect (conn->recovery_cache, host, port, conn->slaveok);
          g_free (host);
          if (nc)
            {
              int e;

              /* We can call ourselves here, since connect does not set
                 conn->rs, thus, we won't end up in an infinite loop. */
              nc = mongo_sync_reconnect (nc, force_master);
              e = errno;
              _mongo_sync_connect_replace (conn, nc);
              errno = e;
              if (conn->auth.db && conn->auth.user && conn->auth.pw)
                mongo_sync_cmd_authenticate (conn, conn->auth.db,
                                             conn->auth.user,
                                             conn->auth.pw);
              return conn;
            }
        }
    }

  /* No primary found, or we couldn't connect, try the rest of the
     hosts. */

  for (i = 0; i < g_list_length (conn->rs.hosts); i++)
    {
      gchar *addr = (gchar *)g_list_nth_data (conn->rs.hosts, i);
      int e;

      if (!mongo_util_parse_addr (addr, &host, &port))
        continue;

      nc = _recovery_cache_connect (conn->recovery_cache, host, port, conn->slaveok);
      g_free (host);
      if (!nc)
        continue;

      nc = mongo_sync_reconnect (nc, force_master);
      e = errno;
      _mongo_sync_connect_replace (conn, nc);
      errno = e;

      if (conn->auth.db && conn->auth.user && conn->auth.pw)
        mongo_sync_cmd_authenticate (conn, conn->auth.db,
                                     conn->auth.user,
                                     conn->auth.pw);

      return conn;
    }

  /* And if that failed too, try the seeds. */

  for (i = 0; i < g_list_length (conn->rs.seeds); i++)
    {
      gchar *addr = (gchar *)g_list_nth_data (conn->rs.seeds, i);
      int e;

      if (!mongo_util_parse_addr (addr, &host, &port))
        continue;

      nc = _recovery_cache_connect (conn->recovery_cache,
                                    host,
                                    port,
                                    conn->slaveok);

      g_free (host);

      if (!nc)
        continue;

      nc = mongo_sync_reconnect (nc, force_master);
      e = errno;
      _mongo_sync_connect_replace (conn, nc);
      errno = e;

      if (conn->auth.db && conn->auth.user && conn->auth.pw)
        mongo_sync_cmd_authenticate (conn, conn->auth.db,
                                     conn->auth.user,
                                     conn->auth.pw);

      return conn;
    }

  errno = EHOSTUNREACH;
  return NULL;
}

static void
_mongo_auth_prop_destroy (gchar **prop)
{
  size_t l;

  if (!prop || !*prop)
    return;

  l = strlen (*prop);
  memset (*prop, 0, l);
  munlock (*prop, l);
  g_free (*prop);

  *prop = NULL;
}

static void
_replica_set_free(replica_set *rs)
{
  g_free (rs->primary);

  _list_free_full (&rs->hosts);
  _list_free_full (&rs->seeds);

  rs->hosts = NULL;
  rs->seeds = NULL;
  rs->primary = NULL;
}

void
mongo_sync_disconnect (mongo_sync_connection *conn)
{
  if (!conn)
    return;

  g_free (conn->last_error);

  if (!conn->recovery_cache)
    {
      _mongo_auth_prop_destroy (&conn->auth.db);
      _mongo_auth_prop_destroy (&conn->auth.user);
      _mongo_auth_prop_destroy (&conn->auth.pw);

      _replica_set_free (&conn->rs);
    }
  else
    {
      _recovery_cache_store (conn->recovery_cache, conn);
    }

  mongo_disconnect ((mongo_connection *)conn);
}

gint32
mongo_sync_conn_get_max_insert_size (mongo_sync_connection *conn)
{
  if (!conn)
    {
      errno = ENOTCONN;
      return -1;
    }
  return conn->max_insert_size;
}

gboolean
mongo_sync_conn_set_max_insert_size (mongo_sync_connection *conn,
                                     gint32 max_size)
{
  if (!conn)
    {
      errno = ENOTCONN;
      return FALSE;
    }
  if (max_size <= 0)
    {
      errno = ERANGE;
      return FALSE;
    }

  errno = 0;
  conn->max_insert_size = max_size;
  return TRUE;
}

gboolean
mongo_sync_conn_get_safe_mode (const mongo_sync_connection *conn)
{
  if (!conn)
    {
      errno = ENOTCONN;
      return FALSE;
    }

  errno = 0;
  return conn->safe_mode;
}

gboolean
mongo_sync_conn_set_safe_mode (mongo_sync_connection *conn,
                               gboolean safe_mode)
{
  if (!conn)
    {
      errno = ENOTCONN;
      return FALSE;
    }

  errno = 0;
  conn->safe_mode = safe_mode;
  return TRUE;
}

gboolean
mongo_sync_conn_get_auto_reconnect (const mongo_sync_connection *conn)
{
  if (!conn)
    {
      errno = ENOTCONN;
      return FALSE;
    }

  errno = 0;
  return conn->auto_reconnect;
}

gboolean
mongo_sync_conn_set_auto_reconnect (mongo_sync_connection *conn,
                                    gboolean auto_reconnect)
{
  if (!conn)
    {
      errno = ENOTCONN;
      return FALSE;
    }

  conn->auto_reconnect = auto_reconnect;
  return TRUE;
}

gboolean
mongo_sync_conn_get_slaveok (const mongo_sync_connection *conn)
{
  if (!conn)
    {
      errno = ENOTCONN;
      return FALSE;
    }

  errno = 0;
  return conn->slaveok;
}

gboolean
mongo_sync_conn_set_slaveok (mongo_sync_connection *conn,
                             gboolean slaveok)
{
  if (!conn)
    {
      errno = ENOTCONN;
      return FALSE;
    }

  errno = 0;
  conn->slaveok = slaveok;
  return TRUE;
}

#define _SLAVE_FLAG(c) ((c->slaveok) ? MONGO_WIRE_FLAG_QUERY_SLAVE_OK : 0)

static inline gboolean
_mongo_cmd_ensure_conn (mongo_sync_connection *conn,
                        gboolean force_master)
{
  if (!conn)
    {
      errno = ENOTCONN;
      return FALSE;
    }

  if (force_master || !conn->slaveok)
    {
      errno = 0;
      if (!mongo_sync_cmd_is_master (conn))
        {
          if (errno == EPROTO)
            return FALSE;
          if (!conn->auto_reconnect)
            {
              errno = ENOTCONN;
              return FALSE;
            }
          if (!mongo_sync_reconnect (conn, TRUE))
            return FALSE;
        }
      return TRUE;
    }

  errno = 0;
  if (!mongo_sync_cmd_ping (conn))
    {
      if (errno == EPROTO)
        return FALSE;
      if (!conn->auto_reconnect)
        {
          errno = ENOTCONN;
          return FALSE;
        }
      if (!mongo_sync_reconnect (conn, FALSE))
        {
          errno = ENOTCONN;
          return FALSE;
        }
    }
  errno = 0;
  return TRUE;
}

static inline gboolean
_mongo_cmd_verify_slaveok (mongo_sync_connection *conn)
{
  if (!conn)
    {
      errno = ENOTCONN;
      return FALSE;
    }

  if (conn->slaveok || !conn->safe_mode)
    return TRUE;

  errno = 0;
  if (!mongo_sync_cmd_is_master (conn))
    {
      if (errno == EPROTO)
        return FALSE;
      if (!conn->auto_reconnect)
        {
          errno = ENOTCONN;
          return FALSE;
        }
      if (!mongo_sync_reconnect (conn, TRUE))
        return FALSE;
    }
  return TRUE;
}

static inline gboolean
_mongo_sync_packet_send (mongo_sync_connection *conn,
                         mongo_packet *p,
                         gboolean force_master,
                         gboolean auto_reconnect)
{
  gboolean out = FALSE;

  if (force_master)
    if (!_mongo_cmd_ensure_conn (conn, force_master))
      {
        mongo_wire_packet_free (p);
        return FALSE;
      }

  for (;;)
    {
      if (!mongo_packet_send ((mongo_connection *)conn, p))
        {
          int e = errno;

          if (!auto_reconnect || (conn && !conn->auto_reconnect))
            {
              mongo_wire_packet_free (p);
              errno = e;
              return FALSE;
            }

          if (out || !mongo_sync_reconnect (conn, force_master))
            {
              mongo_wire_packet_free (p);
              errno = e;
              return FALSE;
            }

          out = TRUE;
          continue;
        }
      break;
    }
  mongo_wire_packet_free (p);
  return TRUE;
}

static inline mongo_packet *
_mongo_sync_packet_recv (mongo_sync_connection *conn, gint32 rid, gint32 flags)
{
  mongo_packet *p;
  mongo_packet_header h;
  mongo_reply_packet_header rh;

  p = mongo_packet_recv ((mongo_connection *)conn);
  if (!p)
    return NULL;

  if (!mongo_wire_packet_get_header_raw (p, &h))
    {
      int e = errno;

      mongo_wire_packet_free (p);
      errno = e;
      return NULL;
    }

  if (h.resp_to != rid)
    {
      mongo_wire_packet_free (p);
      errno = EPROTO;
      return NULL;
    }

  if (!mongo_wire_reply_packet_get_header (p, &rh))
    {
      int e = errno;

      mongo_wire_packet_free (p);
      errno = e;
      return NULL;
    }

  if (rh.flags & flags)
    {
      mongo_wire_packet_free (p);
      errno = EPROTO;
      return NULL;
    }

  if (rh.returned == 0)
    {
      mongo_wire_packet_free (p);
      errno = ENOENT;
      return NULL;
    }

  return p;
}

static gboolean
_mongo_sync_check_ok (bson *b)
{
  bson_cursor *c;
  gdouble d;

  c = bson_find (b, "ok");
  if (!c)
    {
      errno = ENOENT;
      return FALSE;
    }

  if (!bson_cursor_get_double (c, &d))
    {
      bson_cursor_free (c);
      errno = EINVAL;
      return FALSE;
    }
  bson_cursor_free (c);
  errno = (d == 1) ? 0 : EPROTO;
  return (d == 1);
}

static gboolean
_mongo_sync_get_error (const bson *rep, gchar **error)
{
  bson_cursor *c;

  if (!error)
    return FALSE;

  c = bson_find (rep, "err");
  if (!c)
    {
      c = bson_find (rep, "errmsg");
      if (!c)
        {
          errno = EPROTO;
          return FALSE;
        }
    }
  if (bson_cursor_type (c) == BSON_TYPE_NONE ||
      bson_cursor_type (c) == BSON_TYPE_NULL)
    {
      *error = NULL;
      bson_cursor_free (c);
      return TRUE;
    }
  else if (bson_cursor_type (c) == BSON_TYPE_STRING)
    {
      const gchar *err;

      bson_cursor_get_string (c, &err);
      *error = g_strdup (err);
      bson_cursor_free (c);
      return TRUE;
    }
  errno = EPROTO;
  return FALSE;
}

static mongo_packet *
_mongo_sync_packet_check_error (mongo_sync_connection *conn, mongo_packet *p,
                                gboolean check_ok)
{
  bson *b;
  gboolean error;

  if (!p)
    return NULL;

  if (!mongo_wire_reply_packet_get_nth_document (p, 1, &b))
    {
      mongo_wire_packet_free (p);
      errno = EPROTO;
      return NULL;
    }
  bson_finish (b);

  if (check_ok)
    {
      if (!_mongo_sync_check_ok (b))
        {
          int e = errno;

          g_free (conn->last_error);
          conn->last_error = NULL;
          _mongo_sync_get_error (b, &conn->last_error);
          bson_free (b);
          mongo_wire_packet_free (p);
          errno = e;
          return NULL;
        }
      bson_free (b);
      return p;
    }

  g_free (conn->last_error);
  conn->last_error = NULL;
  error = _mongo_sync_get_error (b, &conn->last_error);
  bson_free (b);

  if (error)
    {
      mongo_wire_packet_free (p);
      return NULL;
    }
  return p;
}

static inline gboolean
_mongo_sync_cmd_verify_result (mongo_sync_connection *conn,
                               const gchar *ns)
{
  gchar *error = NULL, *db, *tmp;
  gboolean res;

  if (!conn || !ns)
    return FALSE;
  if (!conn->safe_mode)
    return TRUE;

  tmp = g_strstr_len (ns, -1, ".");
  if (tmp)
    db = g_strndup (ns, tmp - ns);
  else
    db = g_strdup (ns);

  res = mongo_sync_cmd_get_last_error (conn, db, &error);
  g_free (db);
  res = res && ((error) ? FALSE : TRUE);
  g_free (error);

  return res;
}

static void
_set_last_error (mongo_sync_connection *conn, int err)
{
  g_free (conn->last_error);
  conn->last_error = g_strdup(strerror(err));
}

gboolean
mongo_sync_cmd_update (mongo_sync_connection *conn,
                       const gchar *ns,
                       gint32 flags, const bson *selector,
                       const bson *update)
{
  mongo_packet *p;
  gint32 rid;

  rid = mongo_connection_get_requestid ((mongo_connection *)conn) + 1;

  p = mongo_wire_cmd_update (rid, ns, flags, selector, update);
  if (!p)
    return FALSE;

  if (!_mongo_sync_packet_send (conn, p, TRUE, TRUE))
    return FALSE;

  return _mongo_sync_cmd_verify_result (conn, ns);
}

gboolean
mongo_sync_cmd_insert_n (mongo_sync_connection *conn,
                         const gchar *ns, gint32 n,
                         const bson **docs)
{
  mongo_packet *p;
  gint32 rid;
  gint32 pos = 0, c, i = 0;
  gint32 size = 0;

  if (!conn)
    {
      errno = ENOTCONN;
      return FALSE;
    }

  if (!ns || !docs)
    {
      errno = EINVAL;
      return FALSE;
    }
  if (n <= 0)
    {
      errno = EINVAL;
      return FALSE;
    }

  for (i = 0; i < n; i++)
    {
      if (bson_size (docs[i]) >= conn->max_insert_size)
        {
          errno = EMSGSIZE;
          return FALSE;
        }
    }

  do
    {
      i = pos;
      c = 0;

      while (i < n && size < conn->max_insert_size)
        {
          size += bson_size (docs[i++]);
          c++;
        }
      size = 0;
      if (i < n)
        c--;

      rid = mongo_connection_get_requestid ((mongo_connection *)conn) + 1;

      p = mongo_wire_cmd_insert_n (rid, ns, c, &docs[pos]);
      if (!p)
        return FALSE;

      if (!_mongo_sync_packet_send (conn, p, TRUE, TRUE))
        {
          _set_last_error (conn, errno);
          return FALSE;
        }

      if (!_mongo_sync_cmd_verify_result (conn, ns))
        return FALSE;

      pos += c;
    } while (pos < n);

  return TRUE;
}

gboolean
mongo_sync_cmd_insert (mongo_sync_connection *conn,
                       const gchar *ns, ...)
{
  gboolean b;
  bson **docs, *d;
  gint32 n = 0;
  va_list ap;

  if (!conn)
    {
      errno = ENOTCONN;
      return FALSE;
    }

  if (!ns)
    {
      errno = EINVAL;
      return FALSE;
    }

  docs = (bson **)g_new0 (bson *, 1);

  va_start (ap, ns);
  while ((d = (bson *)va_arg (ap, gpointer)))
    {
      if (bson_size (d) < 0)
        {
          g_free (docs);
          errno = EINVAL;
          return FALSE;
        }

      docs = (bson **)g_renew (bson *, docs, n + 1);
      docs[n++] = d;
    }
  va_end (ap);

  b = mongo_sync_cmd_insert_n (conn, ns, n, (const bson **)docs);
  g_free (docs);
  return b;
}

mongo_packet *
mongo_sync_cmd_query (mongo_sync_connection *conn,
                      const gchar *ns, gint32 flags,
                      gint32 skip, gint32 ret,
                      const bson *query, const bson *sel)
{
  mongo_packet *p;
  gint32 rid;

  if (!_mongo_cmd_verify_slaveok (conn))
    return FALSE;

  rid = mongo_connection_get_requestid ((mongo_connection *)conn) + 1;

  p = mongo_wire_cmd_query (rid, ns, flags | _SLAVE_FLAG (conn),
                            skip, ret, query, sel);
  if (!p)
    return NULL;

  if (!_mongo_sync_packet_send (conn, p,
                                !((conn && conn->slaveok) ||
                                  (flags & MONGO_WIRE_FLAG_QUERY_SLAVE_OK)),
                                TRUE))
    return NULL;

  p = _mongo_sync_packet_recv (conn, rid, MONGO_REPLY_FLAG_QUERY_FAIL);
  return _mongo_sync_packet_check_error (conn, p, FALSE);
}

mongo_packet *
mongo_sync_cmd_get_more (mongo_sync_connection *conn,
                         const gchar *ns,
                         gint32 ret, gint64 cursor_id)
{
  mongo_packet *p;
  gint32 rid;

  if (!_mongo_cmd_verify_slaveok (conn))
    return FALSE;

  rid = mongo_connection_get_requestid ((mongo_connection *)conn) + 1;

  p = mongo_wire_cmd_get_more (rid, ns, ret, cursor_id);
  if (!p)
    return NULL;

  if (!_mongo_sync_packet_send (conn, p, FALSE, TRUE))
    return FALSE;

  p = _mongo_sync_packet_recv (conn, rid, MONGO_REPLY_FLAG_NO_CURSOR);
  return _mongo_sync_packet_check_error (conn, p, FALSE);
}

gboolean
mongo_sync_cmd_delete (mongo_sync_connection *conn, const gchar *ns,
                       gint32 flags, const bson *sel)
{
  mongo_packet *p;
  gint32 rid;

  rid = mongo_connection_get_requestid ((mongo_connection *)conn) + 1;

  p = mongo_wire_cmd_delete (rid, ns, flags, sel);
  if (!p)
    return FALSE;

  return _mongo_sync_packet_send (conn, p, TRUE, TRUE);
}

gboolean
mongo_sync_cmd_kill_cursors (mongo_sync_connection *conn,
                             gint32 n, ...)
{
  mongo_packet *p;
  gint32 rid;
  va_list ap;

  if (n <= 0)
    {
      errno = EINVAL;
      return FALSE;
    }

  rid = mongo_connection_get_requestid ((mongo_connection *)conn) + 1;

  va_start (ap, n);
  p = mongo_wire_cmd_kill_cursors_va (rid, n, ap);
  if (!p)
    {
      int e = errno;

      va_end (ap);
      errno = e;
      return FALSE;
    }
  va_end (ap);

  return _mongo_sync_packet_send (conn, p, FALSE, TRUE);
}

static mongo_packet *
_mongo_sync_cmd_custom (mongo_sync_connection *conn,
                        const gchar *db,
                        const bson *command,
                        gboolean check_conn,
                        gboolean force_master)
{
  mongo_packet *p;
  gint32 rid;

  if (!conn)
    {
      errno = ENOTCONN;
      return NULL;
    }

  rid = mongo_connection_get_requestid ((mongo_connection *)conn) + 1;

  p = mongo_wire_cmd_custom (rid, db, _SLAVE_FLAG (conn), command);
  if (!p)
    return NULL;

  if (!_mongo_sync_packet_send (conn, p, force_master, check_conn))
    return NULL;

  p = _mongo_sync_packet_recv (conn, rid, MONGO_REPLY_FLAG_QUERY_FAIL);
  return _mongo_sync_packet_check_error (conn, p, TRUE);
}

mongo_packet *
mongo_sync_cmd_custom (mongo_sync_connection *conn,
                       const gchar *db,
                       const bson *command)
{
  return _mongo_sync_cmd_custom (conn, db, command, TRUE, FALSE);
}

gdouble
mongo_sync_cmd_count (mongo_sync_connection *conn,
                      const gchar *db, const gchar *coll,
                      const bson *query)
{
  mongo_packet *p;
  bson *cmd;
  bson_cursor *c;
  gdouble d;

  cmd = bson_new_sized (bson_size (query) + 32);
  bson_append_string (cmd, "count", coll, -1);
  if (query)
    bson_append_document (cmd, "query", query);
  bson_finish (cmd);

  p = _mongo_sync_cmd_custom (conn, db, cmd, TRUE, FALSE);
  if (!p)
    {
      int e = errno;

      bson_free (cmd);
      errno = e;
      return -1;
    }
  bson_free (cmd);

  if (!mongo_wire_reply_packet_get_nth_document (p, 1, &cmd))
    {
      int e = errno;

      mongo_wire_packet_free (p);
      errno = e;
      return -1;
    }
  mongo_wire_packet_free (p);
  bson_finish (cmd);

  c = bson_find (cmd, "n");
  if (!c)
    {
      bson_free (cmd);
      errno = ENOENT;
      return -1;
    }
  if (!bson_cursor_get_double (c, &d))
    {
      bson_free (cmd);
      bson_cursor_free (c);
      errno = EINVAL;
      return -1;
    }
  bson_cursor_free (c);
  bson_free (cmd);

  return d;
}

gboolean
mongo_sync_cmd_create (mongo_sync_connection *conn,
                       const gchar *db, const gchar *coll,
                       gint flags, ...)
{
  mongo_packet *p;
  bson *cmd;

  if (!conn)
    {
      errno = ENOTCONN;
      return FALSE;
    }
  if (!db || !coll)
    {
      errno = EINVAL;
      return FALSE;
    }

  cmd = bson_new_sized (128);
  bson_append_string (cmd, "create", coll, -1);
  if (flags & MONGO_COLLECTION_AUTO_INDEX_ID)
    bson_append_boolean (cmd, "autoIndexId", TRUE);
  if (flags & MONGO_COLLECTION_CAPPED ||
      flags & MONGO_COLLECTION_CAPPED_MAX ||
      flags & MONGO_COLLECTION_SIZED)
    {
      va_list ap;
      gint64 i;

      if (flags & MONGO_COLLECTION_CAPPED ||
          flags & MONGO_COLLECTION_CAPPED_MAX)
        bson_append_boolean (cmd, "capped", TRUE);

      va_start (ap, flags);
      i = (gint64)va_arg (ap, gint64);
      if (i <= 0)
        {
          bson_free (cmd);
          errno = ERANGE;
          return FALSE;
        }
      bson_append_int64 (cmd, "size", i);

      if (flags & MONGO_COLLECTION_CAPPED_MAX)
        {
          i = (gint64)va_arg (ap, gint64);
          if (i <= 0)
            {
              bson_free (cmd);
              errno = ERANGE;
              return FALSE;
            }
          bson_append_int64 (cmd, "max", i);
        }
      va_end (ap);
    }
  bson_finish (cmd);

  p = _mongo_sync_cmd_custom (conn, db, cmd, TRUE, TRUE);
  if (!p)
    {
      int e = errno;

      bson_free (cmd);
      errno = e;
      return FALSE;
    }
  bson_free (cmd);
  mongo_wire_packet_free (p);

  return TRUE;
}

bson *
mongo_sync_cmd_exists (mongo_sync_connection *conn,
                       const gchar *db, const gchar *coll)
{
  bson *cmd, *r;
  mongo_packet *p;
  gchar *ns, *sys;
  gint32 rid;

  if (!conn)
    {
      errno = ENOTCONN;
      return NULL;
    }
  if (!db || !coll)
    {
      errno = EINVAL;
      return NULL;
    }

  rid = mongo_connection_get_requestid ((mongo_connection *)conn) + 1;

  ns = g_strconcat (db, ".", coll, NULL);
  cmd = bson_new_sized (128);
  bson_append_string (cmd, "name", ns, -1);
  bson_finish (cmd);
  g_free (ns);

  sys = g_strconcat (db, ".system.namespaces", NULL);

  p = mongo_wire_cmd_query (rid, sys, _SLAVE_FLAG (conn), 0, 1, cmd, NULL);
  if (!p)
    {
      int e = errno;

      bson_free (cmd);
      g_free (sys);

      errno = e;
      return NULL;
    }
  g_free (sys);
  bson_free (cmd);

  if (!_mongo_sync_packet_send (conn, p, !conn->slaveok, TRUE))
    return NULL;

  p = _mongo_sync_packet_recv (conn, rid, MONGO_REPLY_FLAG_QUERY_FAIL);
  if (!p)
    return NULL;

  p = _mongo_sync_packet_check_error (conn, p, FALSE);
  if (!p)
    return NULL;

  if (!mongo_wire_reply_packet_get_nth_document (p, 1, &r))
    {
      int e = errno;

      mongo_wire_packet_free (p);
      errno = e;
      return NULL;
    }
  mongo_wire_packet_free (p);
  bson_finish (r);

  return r;
}

gboolean
mongo_sync_cmd_drop (mongo_sync_connection *conn,
                     const gchar *db, const gchar *coll)
{
  mongo_packet *p;
  bson *cmd;

  cmd = bson_new_sized (64);
  bson_append_string (cmd, "drop", coll, -1);
  bson_finish (cmd);

  p = _mongo_sync_cmd_custom (conn, db, cmd, TRUE, TRUE);
  if (!p)
    {
      int e = errno;

      bson_free (cmd);
      errno = e;
      return FALSE;
    }
  bson_free (cmd);
  mongo_wire_packet_free (p);

  return TRUE;
}

gboolean
mongo_sync_cmd_get_last_error (mongo_sync_connection *conn,
                               const gchar *db, gchar **error)
{
  mongo_packet *p;
  bson *cmd;

  if (!conn)
    {
      errno = ENOTCONN;
      return FALSE;
    }
  if (!error)
    {
      errno = EINVAL;
      return FALSE;
    }

  cmd = bson_new_sized (64);
  bson_append_int32 (cmd, "getlasterror", 1);
  bson_finish (cmd);

  p = _mongo_sync_cmd_custom (conn, db, cmd, FALSE, FALSE);
  if (!p)
    {
      int e = errno;

      bson_free (cmd);
      errno = e;
      _set_last_error (conn, e);
      return FALSE;
    }
  bson_free (cmd);

  if (!mongo_wire_reply_packet_get_nth_document (p, 1, &cmd))
    {
      int e = errno;

      mongo_wire_packet_free (p);
      errno = e;
      _set_last_error (conn, e);
      return FALSE;
    }
  mongo_wire_packet_free (p);
  bson_finish (cmd);

  if (!_mongo_sync_get_error (cmd, error))
    {
      int e = errno;

      bson_free (cmd);
      errno = e;
      _set_last_error (conn, e);
      return FALSE;
    }
  bson_free (cmd);

  if (*error == NULL)
    *error = g_strdup (conn->last_error);
  else
    {
      g_free (conn->last_error);
      conn->last_error = g_strdup(*error);
    }

  return TRUE;
}

gboolean
mongo_sync_cmd_reset_error (mongo_sync_connection *conn,
                            const gchar *db)
{
  mongo_packet *p;
  bson *cmd;

  if (conn)
    {
      g_free (conn->last_error);
      conn->last_error = NULL;
    }

  cmd = bson_new_sized (32);
  bson_append_int32 (cmd, "reseterror", 1);
  bson_finish (cmd);

  p = _mongo_sync_cmd_custom (conn, db, cmd, FALSE, FALSE);
  if (!p)
    {
      int e = errno;

      bson_free (cmd);
      errno = e;
      return FALSE;
    }
  bson_free (cmd);
  mongo_wire_packet_free (p);
  return TRUE;
}

gboolean
mongo_sync_cmd_is_master (mongo_sync_connection *conn)
{
  bson *cmd, *res, *hosts;
  mongo_packet *p;
  bson_cursor *c;
  gboolean b;

  cmd = bson_new_sized (32);
  bson_append_int32 (cmd, "ismaster", 1);
  bson_finish (cmd);

  p = _mongo_sync_cmd_custom (conn, "system", cmd, FALSE, FALSE);
  if (!p)
    {
      int e = errno;

      bson_free (cmd);
      errno = e;
      return FALSE;
    }
  bson_free (cmd);

  if (!mongo_wire_reply_packet_get_nth_document (p, 1, &res))
    {
      int e = errno;

      mongo_wire_packet_free (p);
      errno = e;
      return FALSE;
    }
  mongo_wire_packet_free (p);
  bson_finish (res);

  c = bson_find (res, "ismaster");
  if (!bson_cursor_get_boolean (c, &b))
    {
      bson_cursor_free (c);
      bson_free (res);
      errno = EPROTO;
      return FALSE;
    }
  bson_cursor_free (c);

  if (!b)
    {
      const gchar *s;

      /* We're not the master, so we should have a 'primary' key in
         the response. */
      c = bson_find (res, "primary");
      if (bson_cursor_get_string (c, &s))
        {
          g_free (conn->rs.primary);
          conn->rs.primary = g_strdup (s);
        }
      bson_cursor_free (c);
    }

  /* Find all the members of the set, and cache them. */
  c = bson_find (res, "hosts");
  if (!c)
    {
      bson_free (res);
      errno = 0;
      return b;
    }

  if (!bson_cursor_get_array (c, &hosts))
    {
      bson_cursor_free (c);
      bson_free (res);
      errno = 0;
      return b;
    }
  bson_cursor_free (c);
  bson_finish (hosts);

  /* Delete the old host list. */
  _list_free_full (&conn->rs.hosts);

  c = bson_cursor_new (hosts);
  while (bson_cursor_next (c))
    {
      const gchar *s;

      if (bson_cursor_get_string (c, &s))
        conn->rs.hosts = g_list_append (conn->rs.hosts, g_strdup (s));
    }
  bson_cursor_free (c);
  bson_free (hosts);

  c = bson_find (res, "passives");
  if (bson_cursor_get_array (c, &hosts))
    {
      bson_cursor_free (c);
      bson_finish (hosts);

      c = bson_cursor_new (hosts);
      while (bson_cursor_next (c))
        {
          const gchar *s;

          if (bson_cursor_get_string (c, &s))
            conn->rs.hosts = g_list_append (conn->rs.hosts, g_strdup (s));
        }
      bson_free (hosts);
    }
  bson_cursor_free (c);

  bson_free (res);
  errno = 0;
  return b;
}

gboolean
mongo_sync_cmd_ping (mongo_sync_connection *conn)
{
  bson *cmd;
  mongo_packet *p;

  cmd = bson_new_sized (32);
  bson_append_int32 (cmd, "ping", 1);
  bson_finish (cmd);

  p = _mongo_sync_cmd_custom (conn, "system", cmd, FALSE, FALSE);
  if (!p)
    {
      int e = errno;

      bson_free (cmd);
      errno = e;
      return FALSE;
    }
  bson_free (cmd);
  mongo_wire_packet_free (p);

  errno = 0;
  return TRUE;
}

static gchar *
_pass_digest (const gchar *user, const gchar *pw)
{
  GChecksum *chk;
  gchar *digest;

  chk = g_checksum_new (G_CHECKSUM_MD5);
  g_checksum_update (chk, (const guchar *)user, -1);
  g_checksum_update (chk, (const guchar *)":mongo:", 7);
  g_checksum_update (chk, (const guchar *)pw, -1);
  digest = g_strdup (g_checksum_get_string (chk));
  g_checksum_free (chk);

  return digest;
}

gboolean
mongo_sync_cmd_user_add_with_roles (mongo_sync_connection *conn,
                                    const gchar *db,
                                    const gchar *user,
                                    const gchar *pw,
                                    const bson *roles)
{
  bson *s, *u;
  gchar *userns;
  gchar *hex_digest;

  if (!db || !user || !pw)
    {
      errno = EINVAL;
      return FALSE;
    }

  userns = g_strconcat (db, ".system.users", NULL);

  hex_digest = _pass_digest (user, pw);

  s = bson_build (BSON_TYPE_STRING, "user", user, -1,
                  BSON_TYPE_NONE);
  bson_finish (s);
  u = bson_build_full (BSON_TYPE_DOCUMENT, "$set", TRUE,
                       bson_build (BSON_TYPE_STRING, "pwd", hex_digest, -1,
                                   BSON_TYPE_NONE),
                       BSON_TYPE_NONE);
  if (roles)
    bson_append_array (u, "roles", roles);
  bson_finish (u);
  g_free (hex_digest);

  if (!mongo_sync_cmd_update (conn, userns, MONGO_WIRE_FLAG_UPDATE_UPSERT,
                              s, u))
    {
      int e = errno;

      bson_free (s);
      bson_free (u);
      g_free (userns);
      errno = e;
      return FALSE;
    }
  bson_free (s);
  bson_free (u);
  g_free (userns);

  return TRUE;
}

gboolean
mongo_sync_cmd_user_add (mongo_sync_connection *conn,
                         const gchar *db,
                         const gchar *user,
                         const gchar *pw)
{
  return mongo_sync_cmd_user_add_with_roles (conn, db, user, pw, NULL);
}

gboolean
mongo_sync_cmd_user_remove (mongo_sync_connection *conn,
                            const gchar *db,
                            const gchar *user)
{
  bson *s;
  gchar *userns;

  if (!db || !user)
    {
      errno = EINVAL;
      return FALSE;
    }

  userns = g_strconcat (db, ".system.users", NULL);

  s = bson_build (BSON_TYPE_STRING, "user", user, -1,
                  BSON_TYPE_NONE);
  bson_finish (s);

  if (!mongo_sync_cmd_delete (conn, userns, 0, s))
    {
      int e = errno;

      bson_free (s);
      g_free (userns);
      errno = e;
      return FALSE;
    }
  bson_free (s);
  g_free (userns);

  return TRUE;
}

gboolean
mongo_sync_cmd_authenticate (mongo_sync_connection *conn,
                             const gchar *db,
                             const gchar *user,
                             const gchar *pw)
{
  bson *b;
  mongo_packet *p;
  const gchar *s;
  gchar *nonce;
  bson_cursor *c;

  GChecksum *chk;
  gchar *hex_digest;
  const gchar *digest;
  gchar *ndb, *nuser, *npw;

  if (!db || !user || !pw)
    {
      errno = EINVAL;
      return FALSE;
    }

  /* Obtain nonce */
  b = bson_new_sized (32);
  bson_append_int32 (b, "getnonce", 1);
  bson_finish (b);

  p = mongo_sync_cmd_custom (conn, db, b);
  if (!p)
    {
      int e = errno;

      bson_free (b);
      errno = e;
      return FALSE;
    }
  bson_free (b);

  if (!mongo_wire_reply_packet_get_nth_document (p, 1, &b))
    {
      int e = errno;

      mongo_wire_packet_free (p);
      errno = e;
      return FALSE;
    }
  mongo_wire_packet_free (p);
  bson_finish (b);

  c = bson_find (b, "nonce");
  if (!c)
    {
      bson_free (b);
      errno = EPROTO;
      return FALSE;
    }
  if (!bson_cursor_get_string (c, &s))
    {
      bson_free (b);
      errno = EPROTO;
      return FALSE;
    }
  nonce = g_strdup (s);
  bson_cursor_free (c);
  bson_free (b);

  /* Generate the password digest. */
  hex_digest = _pass_digest (user, pw);

  /* Generate the key */
  chk = g_checksum_new (G_CHECKSUM_MD5);
  g_checksum_update (chk, (const guchar *)nonce, -1);
  g_checksum_update (chk, (const guchar *)user, -1);
  g_checksum_update (chk, (const guchar *)hex_digest, -1);
  g_free (hex_digest);

  digest = g_checksum_get_string (chk);

  /* Run the authenticate command. */
  b = bson_build (BSON_TYPE_INT32, "authenticate", 1,
                  BSON_TYPE_STRING, "user", user, -1,
                  BSON_TYPE_STRING, "nonce", nonce, -1,
                  BSON_TYPE_STRING, "key", digest, -1,
                  BSON_TYPE_NONE);
  bson_finish (b);
  g_free (nonce);
  g_checksum_free (chk);

  p = mongo_sync_cmd_custom (conn, db, b);
  if (!p)
    {
      int e = errno;

      bson_free (b);
      errno = e;
      return FALSE;
    }
  bson_free (b);
  mongo_wire_packet_free (p);

  ndb = g_strdup (db);
  _mongo_auth_prop_destroy (&conn->auth.db);
  conn->auth.db = ndb;
  mlock (conn->auth.db, strlen (ndb));

  nuser = g_strdup (user);
  _mongo_auth_prop_destroy (&conn->auth.user);
  conn->auth.user = nuser;
  mlock (conn->auth.user, strlen (nuser));

  npw = g_strdup (pw);
  _mongo_auth_prop_destroy (&conn->auth.pw);
  conn->auth.pw = npw;
  mlock (conn->auth.pw, strlen (npw));

  return TRUE;
}

static GString *
_mongo_index_gen_name (const bson *key)
{
  bson_cursor *c;
  GString *name;

  name = g_string_new ("_");
  c = bson_cursor_new (key);
  while (bson_cursor_next (c))
    {
      gint64 v = 0;

      g_string_append (name, bson_cursor_key (c));
      g_string_append_c (name, '_');

      switch (bson_cursor_type (c))
        {
        case BSON_TYPE_BOOLEAN:
          {
            gboolean vb;

            bson_cursor_get_boolean (c, &vb);
            v = vb;
            break;
          }
        case BSON_TYPE_INT32:
          {
            gint32 vi;

            bson_cursor_get_int32 (c, &vi);
            v = vi;
            break;
          }
        case BSON_TYPE_INT64:
          {
            gint64 vl;

            bson_cursor_get_int64 (c, &vl);
            v = vl;
            break;
          }
        case BSON_TYPE_DOUBLE:
          {
            gdouble vd;

            bson_cursor_get_double (c, &vd);
            v = (gint64)vd;
            break;
          }
        default:
          bson_cursor_free (c);
          g_string_free (name, TRUE);
          return NULL;
        }
      if (v != 0)
        g_string_append_printf (name, "%" G_GINT64_FORMAT "_", v);
    }
  bson_cursor_free (c);

  return name;
}

gboolean
mongo_sync_cmd_index_create (mongo_sync_connection *conn,
                             const gchar *ns,
                             const bson *key,
                             gint options)
{
  GString *name;
  gchar *idxns, *t;
  bson *cmd;

  if (!conn)
    {
      errno = ENOTCONN;
      return FALSE;
    }
  if (!ns || !key)
    {
      errno = EINVAL;
      return FALSE;
    }
  if (strchr (ns, '.') == NULL)
    {
      errno = EINVAL;
      return FALSE;
    }

  name = _mongo_index_gen_name (key);
  if (!name)
    {
      errno = ENOTSUP;
      return FALSE;
    }

  cmd = bson_new_sized (bson_size (key) + name->len + 128);
  bson_append_document (cmd, "key", key);
  bson_append_string (cmd, "ns", ns, -1);
  bson_append_string (cmd, "name", name->str, name->len);
  if (options & MONGO_INDEX_UNIQUE)
    bson_append_boolean (cmd, "unique", TRUE);
  if (options & MONGO_INDEX_DROP_DUPS)
    bson_append_boolean (cmd, "dropDups", TRUE);
  if (options & MONGO_INDEX_BACKGROUND)
    bson_append_boolean (cmd, "background", TRUE);
  if (options & MONGO_INDEX_SPARSE)
    bson_append_boolean (cmd, "sparse", TRUE);
  bson_finish (cmd);
  g_string_free (name, TRUE);

  t = g_strdup (ns);
  *(strchr (t, '.')) = '\0';
  idxns = g_strconcat (t, ".system.indexes", NULL);
  g_free (t);

  if (!mongo_sync_cmd_insert_n (conn, idxns, 1, (const bson **)&cmd))
    {
      int e = errno;

      bson_free (cmd);
      g_free (idxns);
      errno = e;
      return FALSE;
    }
  bson_free (cmd);
  g_free (idxns);

  return TRUE;
}

static gboolean
_mongo_sync_cmd_index_drop (mongo_sync_connection *conn,
                            const gchar *full_ns,
                            const gchar *index_name)
{
  bson *cmd;
  gchar *db, *ns;
  mongo_packet *p;

  if (!conn)
    {
      errno = ENOTCONN;
      return FALSE;
    }
  if (!full_ns || !index_name)
    {
      errno = EINVAL;
      return FALSE;
    }
  ns = strchr (full_ns, '.');
  if (ns == NULL)
    {
      errno = EINVAL;
      return FALSE;
    }
  ns++;

  cmd = bson_new_sized (256 + strlen (index_name));
  bson_append_string (cmd, "deleteIndexes", ns, -1);
  bson_append_string (cmd, "index", index_name, -1);
  bson_finish (cmd);

  db = g_strndup (full_ns, ns - full_ns - 1);
  p = mongo_sync_cmd_custom (conn, db, cmd);
  if (!p)
    {
      int e = errno;

      bson_free (cmd);
      g_free (db);
      errno = e;
      return FALSE;
    }
  mongo_wire_packet_free (p);
  g_free (db);
  bson_free (cmd);

  return TRUE;
}

gboolean
mongo_sync_cmd_index_drop (mongo_sync_connection *conn,
                           const gchar *ns,
                           const bson *key)
{
  GString *name;
  gboolean b;

  if (!key)
    {
      errno = EINVAL;
      return FALSE;
    }

  name = _mongo_index_gen_name (key);

  b = _mongo_sync_cmd_index_drop (conn, ns, name->str);
  g_string_free (name, TRUE);
  return b;
}

gboolean
mongo_sync_cmd_index_drop_all (mongo_sync_connection *conn,
                               const gchar *ns)
{
  return _mongo_sync_cmd_index_drop (conn, ns, "*");
}

mongo_sync_conn_recovery_cache *
mongo_sync_conn_recovery_cache_new (void)
{
  mongo_sync_conn_recovery_cache *cache;
  
  cache = g_new0 (mongo_sync_conn_recovery_cache, 1);

  return cache;
}

void
mongo_sync_conn_recovery_cache_free (mongo_sync_conn_recovery_cache *cache)
{
  mongo_sync_conn_recovery_cache_discard(cache);

  g_free(cache);
}

void
mongo_sync_conn_recovery_cache_discard (mongo_sync_conn_recovery_cache *cache)
{
  _mongo_auth_prop_destroy (&cache->auth.db);
  _mongo_auth_prop_destroy (&cache->auth.user);
  _mongo_auth_prop_destroy (&cache->auth.pw);

  _replica_set_free (&cache->rs);
}

gboolean
mongo_sync_conn_recovery_cache_seed_add (mongo_sync_conn_recovery_cache *cache,
                                         const gchar *host,
                                         gint port)
{
  if (!host || port < 0)
    {
      errno = EINVAL;
      return FALSE;
    }

  cache->rs.seeds = g_list_append (cache->rs.seeds, g_strdup_printf ("%s:%d", host, port));

  return TRUE;
}

static mongo_sync_connection *
_recovery_cache_pick_connect_from_list (mongo_sync_conn_recovery_cache *cache,
                                        GList *address_list,
                                        gboolean slaveok)
{
  gint port;
  guint i;
  gchar *host;
  mongo_sync_connection *c = NULL;

  if (address_list)
    {
      for (i = 0; i < g_list_length (address_list); i++)
        {
          gchar *addr = (gchar *)g_list_nth_data (address_list, i);

          if (!mongo_util_parse_addr (addr, &host, &port))
            continue;

          c = _recovery_cache_connect (cache, host, port, slaveok);
          g_free (host);
          if (c)
            {
              return slaveok ? c : mongo_sync_reconnect (c, !slaveok);
            }
        }
    }

  return NULL;
}

mongo_sync_connection *
mongo_sync_connect_recovery_cache (mongo_sync_conn_recovery_cache *cache,
                                   gboolean slaveok)
{
  mongo_sync_connection *c = NULL;
  gchar *host;
  gint port;

  if (cache->rs.primary && mongo_util_parse_addr (cache->rs.primary, &host, &port))
    {
      if ( (c = _recovery_cache_connect (cache, host, port, slaveok)) )
        {
          return slaveok ? c : mongo_sync_reconnect (c, !slaveok);
        }
    }

  c = _recovery_cache_pick_connect_from_list (cache, cache->rs.seeds, slaveok);

  if (!c)
    c = _recovery_cache_pick_connect_from_list (cache, cache->rs.hosts, slaveok);

  return c;
}

const gchar *
mongo_sync_conn_get_last_error (mongo_sync_connection *conn)
{
  return conn->last_error;
}
