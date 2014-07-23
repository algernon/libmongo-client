#include "test.h"
#include "bson.h"
#include "mongo-utils.h"

#include <glib.h>
#include <string.h>

#ifndef HAVE_MSG_NOSIGNAL
#include <signal.h>
#endif


func_config_t config;

bson *
test_bson_generate_full (void)
{
  bson *b, *d, *a, *scope;
  guint8 oid[] = "1234567890ab";

  a = bson_new ();
  bson_append_int32 (a, "0", 32);
  bson_append_int64 (a, "1", (gint64)-42);
  bson_finish (a);

  d = bson_new ();
  bson_append_string (d, "name", "sub-document", -1);
  bson_append_int32 (d, "answer", 42);
  bson_finish (d);

  scope = bson_new ();
  bson_append_string (scope, "v", "hello world", -1);
  bson_finish (scope);

  b = bson_new ();
  bson_append_double (b, "double", 3.14);
  bson_append_string (b, "str", "hello world", -1);
  bson_append_document (b, "doc", d);
  bson_append_array (b, "array", a);
  bson_append_binary (b, "binary0", BSON_BINARY_SUBTYPE_GENERIC,
                      (guint8 *)"foo\0bar", 7);
  bson_append_oid (b, "_id", oid);
  bson_append_boolean (b, "TRUE", FALSE);
  bson_append_utc_datetime (b, "date", 1294860709000);
  bson_append_timestamp (b, "ts", 1294860709000);
  bson_append_null (b, "null");
  bson_append_regex (b, "foobar", "s/foo.*bar/", "i");
  bson_append_javascript (b, "alert", "alert (\"hello world!\");", -1);
  bson_append_symbol (b, "sex", "Marilyn Monroe", -1);
  bson_append_javascript_w_scope (b, "print", "alert (v);", -1, scope);
  bson_append_int32 (b, "int32", 32);
  bson_append_int64 (b, "int64", (gint64)-42);
  bson_finish (b);

  bson_free (d);
  bson_free (a);
  bson_free (scope);

  return b;
}

mongo_packet *
test_mongo_wire_generate_reply (gboolean valid, gint32 nreturn,
                                gboolean with_docs)
{
  mongo_reply_packet_header rh;
  mongo_packet_header h;
  mongo_packet *p;
  guint8 *data;
  gint data_size = sizeof (mongo_reply_packet_header);
  bson *b1 = NULL, *b2 = NULL;

  p = mongo_wire_packet_new ();

  h.opcode = (valid) ? GINT32_TO_LE (1) : GINT32_TO_LE (42);
  h.id = GINT32_TO_LE (1984);
  h.resp_to = GINT32_TO_LE (42);
  if (with_docs)
    {
      b1 = test_bson_generate_full ();
      b2 = test_bson_generate_full ();
      data_size += bson_size (b1) + bson_size (b2);
    }
  h.length = GINT32_TO_LE (sizeof (mongo_packet_header) + data_size);

  mongo_wire_packet_set_header (p, &h);

  data = g_try_malloc (data_size);

  rh.flags = 0;
  rh.cursor_id = GINT64_TO_LE ((gint64)12345);
  rh.start = 0;
  rh.returned = GINT32_TO_LE (nreturn);

  memcpy (data, &rh, sizeof (mongo_reply_packet_header));
  if (with_docs)
    {
      memcpy (data + sizeof (mongo_reply_packet_header),
              bson_data (b1), bson_size (b1));
      memcpy (data + sizeof (mongo_reply_packet_header) + bson_size (b1),
              bson_data (b2), bson_size (b2));
    }

  mongo_wire_packet_set_data (p, data, data_size);
  g_free (data);
  bson_free (b1);
  bson_free (b2);

  return p;
}

mongo_sync_connection *
test_make_fake_sync_conn (gint fd, gboolean slaveok)
{
  mongo_sync_connection *c;

  c = g_try_new0 (mongo_sync_connection, 1);
  if (!c)
    return NULL;

  c->super.fd = fd;
  c->slaveok = slaveok;
  c->safe_mode = FALSE;
  c->auto_reconnect = FALSE;
  c->max_insert_size = MONGO_SYNC_DEFAULT_MAX_INSERT_SIZE;

  return c;
}

gboolean
test_env_setup (void)
{
  config.primary_host = config.secondary_host = NULL;
  config.primary_port = config.secondary_port = 27017;
  config.db = g_strdup ("test");
  config.coll = g_strdup ("libmongo");

#if WITH_OPENSSL
  config.ssl_settings = g_new0 (mongo_ssl_ctx, 1);
#endif

  if (getenv ("TEST_DB"))
    {
      g_free (config.db);
      config.db = g_strdup (getenv ("TEST_DB"));
    }
  if (getenv ("TEST_COLLECTION"))
    {
      g_free (config.coll);
      config.coll = g_strdup (getenv ("TEST_COLLECTION"));
    }
  config.ns = g_strconcat (config.db, ".", config.coll, NULL);

  config.gfs_prefix = g_strconcat (config.ns, ".", "grid", NULL);

  if (!getenv ("TEST_PRIMARY") || strlen (getenv ("TEST_PRIMARY")) == 0)
    return FALSE;

  if (!mongo_util_parse_addr (getenv ("TEST_PRIMARY"), &config.primary_host,
                              &config.primary_port))
    return FALSE;

  if (getenv ("TEST_SECONDARY") && strlen (getenv ("TEST_SECONDARY")) > 0)
    mongo_util_parse_addr (getenv ("TEST_SECONDARY"), &config.secondary_host,
                           &config.secondary_port);

#if WITH_OPENSSL
  /*mongo_ssl_util_init_lib();*/
  if (getenv ("SSL_CERT_PATH") && strlen (getenv ("SSL_CERT_PATH")) > 0)
    {
      if (! mongo_ssl_init (config.ssl_settings))
        {
          perror ("mongo_ssl_init");
          return FALSE;
        }

      if (! mongo_ssl_set_cert (config.ssl_settings, g_strdup (getenv ("SSL_CERT_PATH"))))
        {
          perror ("mongo_ssl_set_cert");
          return FALSE;
        }


      if (getenv ("SSL_CA_PATH") && strlen (getenv ("SSL_CA_PATH")) > 0)
        {
          if (! mongo_ssl_set_ca (config.ssl_settings, g_strdup (getenv ("SSL_CA_PATH"))))
            {
              perror ("mongo_ssl_set_ca");
              return FALSE;
            }
        }


      if (getenv ("SSL_CRL_PATH") && strlen (getenv ("SSL_CRL_PATH")) > 0)
        {
          if (! mongo_ssl_set_crl (config.ssl_settings, g_strdup (getenv ("SSL_CRL_PATH"))))
            {
              perror ("mongo_ssl_set_crl");
              return FALSE;
            }
        }

      if (getenv ("SSL_KEY_PATH") && strlen (getenv ("SSL_KEY_PATH")) >0)
        {
         if (! mongo_ssl_set_key (config.ssl_settings, g_strdup (getenv ("SSL_KEY_PATH")), 
                g_strdup (getenv ("SSL_KEY_PW"))))
           {
             perror ("mongo_ssl_set_key");
             return FALSE;
           }
        }
      else 
         return FALSE;
    }
#endif
  
  return TRUE;
}

void
test_env_free (void)
{
  g_free (config.primary_host);
  g_free (config.secondary_host);
  g_free (config.db);
  g_free (config.coll);
  g_free (config.ns);
  g_free (config.gfs_prefix);

#if WITH_OPENSSL
  mongo_ssl_clear (config.ssl_settings);
  g_free (config.ssl_settings);
  /*mongo_ssl_util_cleanup_lib();*/
#endif
}

void
test_main_setup (void)
{
  signal(SIGPIPE, SIG_IGN); /* BIO_write */
}
