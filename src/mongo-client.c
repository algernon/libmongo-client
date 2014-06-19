/* mongo-client.c - libmongo-client user API
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

/** @file src/mongo-client.c
 * MongoDB client API implementation.
 */

#include "config.h"
#include "mongo-client.h"
#include "bson.h"
#include "mongo-wire.h"
#include "libmongo-private.h"

#include <glib.h>

#include <string.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netdb.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>


#ifndef HAVE_MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

static const int one = 1;

mongo_connection *
mongo_tcp_connect (const char *host, int port)
{
  struct addrinfo *res = NULL, *r;
  struct addrinfo hints;
  int e, fd = -1;
  gchar *port_s;
  mongo_connection *conn;

  if (!host)
    {
      errno = EINVAL;
      return NULL;
    }

  memset (&hints, 0, sizeof (hints));
  hints.ai_socktype = SOCK_STREAM;

#ifdef __linux__
  hints.ai_flags = AI_ADDRCONFIG;
#endif

  port_s = g_strdup_printf ("%d", port);
  e = getaddrinfo (host, port_s, &hints, &res);
  if (e != 0)
    {
      int err = errno;

      g_free (port_s);
      errno = err;
      return NULL;
    }
  g_free (port_s);

  for (r = res; r != NULL; r = r->ai_next)
    {
      fd = socket (r->ai_family, r->ai_socktype, r->ai_protocol);
      if (fd != -1 && connect (fd, r->ai_addr, r->ai_addrlen) == 0)
        break;
      if (fd != -1)
        {
          close (fd);
          fd = -1;
        }
    }
  freeaddrinfo (res);

  if (fd == -1)
    {
      errno = EADDRNOTAVAIL;
      return NULL;
    }

  setsockopt (fd, IPPROTO_TCP, TCP_NODELAY, (char *)&one, sizeof (one));

  conn = g_new0 (mongo_connection, 1);
  conn->fd = fd;

  return conn;
}

static mongo_connection *
mongo_unix_connect (const char *path)
{
  int fd = -1;
  mongo_connection *conn;
  struct sockaddr_un remote;

  if (!path || strlen (path) >= sizeof (remote.sun_path))
    {
      errno = path ? ENAMETOOLONG : EINVAL;
      return NULL;
    }

  fd = socket (AF_UNIX, SOCK_STREAM, 0);
  if (fd == -1)
    {
      errno = EADDRNOTAVAIL;
      return NULL;
    }

  remote.sun_family = AF_UNIX;
  strncpy (remote.sun_path, path, sizeof (remote.sun_path));
  if (connect (fd, (struct sockaddr *)&remote, sizeof (remote)) == -1)
    {
      close (fd);
      errno = EADDRNOTAVAIL;
      return NULL;
    }

  conn = g_new0 (mongo_connection, 1);
  conn->fd = fd;

  return conn;
}

static
mongo_ssl_session_cache_entry *
_find_session (mongo_ssl_ctx *conf, const gchar *host, gint port)
{
  GList* l;
  gchar* t;
  mongo_ssl_session_cache_entry *ret = NULL;

  if (conf == NULL)
    {
      errno = EINVAL;
      return NULL;
    }

  if (conf->session_cache == NULL)
    {
      return NULL;
    }

  if (host == NULL)
    {
      return NULL;
    }

  if (strlen (host) == 0)
    {
      return NULL;
    }

  t = g_strdup_printf ("%s:%d", host, port);

  for (l = conf->session_cache; l != NULL; l = l->next)
    {
      mongo_ssl_session_cache_entry *ent = (mongo_ssl_session_cache_entry *) l->data;
      if (ent == NULL) continue;
      if (strcmp (ent->target, t) == 0) 
        {
          ret = ent;
          break;
        }
    }

    g_free (t);
    return ret;
}

mongo_connection * 
mongo_ssl_connect (const char *host, int port, mongo_ssl_ctx *conf) 
{
  if (conf == NULL)
    {
      errno = EINVAL;
      return NULL; 
    }

  if (conf->ctx == NULL)
    {
      errno = EINVAL;
      return NULL;
    }

  BIO *bio = NULL; 
  SSL *ssl = NULL;
  int fd, err;
  gboolean conn_ok = FALSE;
  mongo_ssl_session_cache_entry *se = NULL;
  gboolean reused_session = FALSE;
  gchar *t = NULL;
  mongo_ssl_verify_result rstat = MONGO_SSL_V_UNDEF;

  if ((bio = BIO_new_ssl_connect (conf->ctx)) == NULL) 
    {
      goto error;
    }


  BIO_get_ssl (bio, &ssl);
  if (!ssl)
    {
      goto error;
    }
 
  //SSL_set_mode (ssl, SSL_MODE_AUTO_RETRY); // Controlled on a per-CTX basis (see mongo_ssl_set_auto_retry)
    
  t = g_strdup_printf ("%s:%d", host, port);
  if (!BIO_set_conn_hostname (bio, t)) 
    {
      goto error;
    }

  if (!SSL_set_tlsext_host_name (ssl, host))
    {
      goto error;
    }

  // FIXME
  //se = _find_session (conf, host, port); // Session resumption does not seem to be working with MongoDB v2.6 (wtf?)
  
  if (se != NULL)
    {
      if (se->sess != NULL) 
        {
          if (SSL_set_session (ssl, se->sess) != 1)
            {
              conf->last_ssl_error = ERR_peek_last_error ();
              SSL_set_session (ssl, NULL);
            }
         }
    }
 

  if (BIO_do_connect (bio) != 1) 
    {
      goto error;
    }

  conn_ok = TRUE;
  reused_session = SSL_session_reused (ssl);
  
  if (!reused_session)
    {
      if (BIO_do_handshake (bio) != 1) 
        {
          goto error;
        }
    }
  
  rstat = mongo_ssl_verify_session (ssl, bio, conf);
  conf->last_verify_result = rstat;

  if ( ! (MONGO_SSL_SESSION_OK(rstat))  ) 
    {
      goto error;
    }
  
  mongo_connection *conn = g_new0 (mongo_connection, 1);
    
  fd = SSL_get_fd (ssl); 
    
  BIO_set_close (bio, BIO_CLOSE);

  conn->fd = fd;    
  conn->ssl = g_new0 (mongo_ssl_conn, 1); 
  conn->ssl->bio = bio;
  conn->ssl->conn = ssl;
  conn->ssl->verification_status = rstat;
  conn->ssl->super = conf;

  mongo_connection_set_timeout (conn, 2500); // try to set a lower default timeout
  
  if (se != NULL)
    {
      se->sess = SSL_get1_session (ssl);
    }
  else
    {
      SSL_SESSION *s = SSL_get1_session (ssl);
      if (s != NULL)
        {
          mongo_ssl_session_cache_entry *ent = g_new0 (mongo_ssl_session_cache_entry, 1);
          ent->target = g_strdup_printf("%s:%d", host, port);
          ent->sess = s;
          conf->session_cache = g_list_append (conf->session_cache, ent);
        }
    }

  g_free (t);

  return conn;

error:
  g_free (t);
  conf->last_ssl_error = ERR_peek_last_error ();
  if (ssl != NULL)
    {
      if (conn_ok) 
        SSL_shutdown (ssl);
      SSL_free (ssl);
    }
  else if (bio != NULL)
    {
      BIO_free_all (bio);
    }

  return NULL;
}

mongo_connection *
mongo_connect (const char *address, int port)
{
  if (port == MONGO_CONN_LOCAL)
    return mongo_unix_connect (address);

  return mongo_tcp_connect (address, port);
}

//mongo_connection *
//mongo_connect (const char *address, int port, mongo_ssl_ctx *conf)
//{
//  return mongo_ssl_connect (address, port, conf); 
//}

#if VERSIONED_SYMBOLS
__asm__(".symver mongo_tcp_connect,mongo_connect@LMC_0.1.0");
#endif

void
mongo_disconnect (mongo_connection *conn)
{
  if (!conn)
    {
      errno = ENOTCONN;
      return;
    }

  if (conn->ssl != NULL)
    {
      SSL_shutdown (conn->ssl->conn);
      SSL_free (conn->ssl->conn); 
    }
  
  if (conn->fd >= 0)
    close (conn->fd);

  g_free (conn);
  errno = 0;
}

gboolean
mongo_packet_send (mongo_connection *conn, const mongo_packet *p)
{
  const guint8 *data;
  gint32 data_size;
  mongo_packet_header h;
  struct iovec iov[2];
  struct msghdr msg;
  
  //sigset_t sigmask;

  if (!conn)
    {
      errno = ENOTCONN;
      return FALSE;
    }
  if (!p)
    {
      errno = EINVAL;
      return FALSE;
    }

  if (conn->fd < 0)
    {
      errno = EBADF;
      return FALSE;
    }

  if (!mongo_wire_packet_get_header_raw (p, &h))
    return FALSE;

  data_size = mongo_wire_packet_get_data (p, &data);

  if (data_size == -1)
    return FALSE;

  iov[0].iov_base = (void *)&h;
  iov[0].iov_len = sizeof (h);
  iov[1].iov_base = (void *)data;
  iov[1].iov_len = data_size;

  memset (&msg, 0, sizeof (struct msghdr));
  msg.msg_iov = iov;
  msg.msg_iovlen = 2;

  if (conn->ssl != NULL)
    {
      int err = 0;
      // UPDATE: SIG_IGN seems to be working now (maybe I fucked something up...)
      //sigemptyset (&sigmask);
      //sigaddset (&sigmask, SIGPIPE);

      //pthread_sigmask (SIG_BLOCK, &sigmask, NULL);

      guint8 *buf = g_new0 (guint8, sizeof(h) + data_size);
      memcpy (buf, iov[0].iov_base, sizeof (h));
      memcpy (buf + sizeof (h), iov[1].iov_base, data_size);

      if ( (err = BIO_write (conn->ssl->bio, buf, (gint32)sizeof (h) + data_size)) != ((gint32)sizeof (h) + data_size))
        {
         //fprintf (stderr, "[mongo_packet_send] BIO write (written: %d, expected: %d) libc_error = %s, ssl_error = %s",
         //           err, (gint32)sizeof (h) + data_size, strerror (errno), ERR_error_string (ERR_peek_last_error (), NULL) );
         g_free (buf);
         return FALSE;
        }
      g_free (buf);
    }
  else if (sendmsg (conn->fd, &msg, MSG_NOSIGNAL) != (gint32)sizeof (h) + data_size)
     return FALSE;

  conn->request_id = h.id;

  return TRUE;
}

mongo_packet *
mongo_packet_recv (mongo_connection *conn)
{
  mongo_packet *p;
  guint8 *data;
  guint32 size;
  mongo_packet_header h;

  if (!conn)
    {
      errno = ENOTCONN;
      return NULL;
    }

  if (conn->fd < 0)
    {
      errno = EBADF;
      return NULL;
    }

  memset (&h, 0, sizeof (h));
  if (conn->ssl == NULL)
    {
        if (recv (conn->fd, &h, sizeof (mongo_packet_header),
                MSG_NOSIGNAL | MSG_WAITALL) != sizeof (mongo_packet_header))
            {
                return NULL;
            }
    } 
  else
    {
        //fprintf(stderr, "[mongo_packet_recv] SSL mode is On\n");
        int c = 0;
        do 
            {
                int err = BIO_read (conn->ssl->bio, &h, sizeof (mongo_packet_header));
                if (err > 0) c += err;
                else ERR_print_errors_fp (stderr);
            } while (BIO_should_read (conn->ssl->bio));
        
        if (c != sizeof (mongo_packet_header))
            {
                conn->ssl->super->last_ssl_error = ERR_peek_last_error ();
                //fprintf(stderr, "[mongo_packet_recv][reading packet header] Data read: %d bytes Expected: %d Returning NULL\n", c, sizeof (mongo_packet_header) );
                return NULL;
            }
    }

  h.length = GINT32_FROM_LE (h.length);
  h.id = GINT32_FROM_LE (h.id);
  h.resp_to = GINT32_FROM_LE (h.resp_to);
  h.opcode = GINT32_FROM_LE (h.opcode);

  p = mongo_wire_packet_new ();

  if (!mongo_wire_packet_set_header_raw (p, &h))
    {
      int e = errno;

      mongo_wire_packet_free (p);
      errno = e;
      return NULL;
    }

  size = h.length - sizeof (mongo_packet_header);
  data = g_new0 (guint8, size);
  
  if (conn->ssl == NULL)
    {
        if ((guint32)recv (conn->fd, data, size, MSG_NOSIGNAL | MSG_WAITALL) != size)
            {
                int e = errno;

                g_free (data);
                mongo_wire_packet_free (p);
                errno = e;
                return NULL;
            }
    }
    else
        {
            int c = 0;
            do 
                {
                    int err = BIO_read (conn->ssl->bio, data, size);
                    if (err > 0) c += err;
                } while (BIO_should_read (conn->ssl->bio));
        
            if (c != size)
                {
                    conn->ssl->super->last_ssl_error = ERR_peek_last_error ();
                     fprintf(stderr, "[mongo_packet_recv] Data read: %d bytes Expected: %d Returning NULL\n", c, sizeof (mongo_packet_header) );
 
                    g_free (data);
                    mongo_wire_packet_free (p);
                    return NULL;
                }
        }

  if (!mongo_wire_packet_set_data (p, data, size))
    {
      int e = errno;

      g_free (data);
      mongo_wire_packet_free (p);
      errno = e;
      return NULL;
    }

  g_free (data);

  return p;
}

gint32
mongo_connection_get_requestid (const mongo_connection *conn)
{
  if (!conn)
    {
      errno = ENOTCONN;
      return -1;
    }

  return conn->request_id;
}

gboolean
mongo_connection_set_timeout (mongo_connection *conn, gint timeout)
{
  struct timeval tv;

  if (!conn)
    {
      errno = ENOTCONN;
      return FALSE;
    }
  if (timeout < 0)
    {
      errno = ERANGE;
      return FALSE;
    }

  tv.tv_sec = timeout / 1000;
  tv.tv_usec = (timeout % 1000) * 1000;

  if (setsockopt (conn->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof (tv)) == -1)
    return FALSE;
  if (setsockopt (conn->fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof (tv)) == -1)
    return FALSE;
  return TRUE;
}
