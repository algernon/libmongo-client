/* mongo-ssl.c - Libmongo-client's SSL support
 * Copyright 2014 György Demarcsek <dgy.jr92@gmail.com>
*/

/** @file src/mongo-ssl.c
 * SSL support main source file
 **/
#include "mongo-ssl.h"

#include <glib.h>
#include <assert.h>
#include <pthread.h>
#include <string.h>

#include <sys/stat.h>

#define HIGH_CIPHERS "HIGH:!EXPORT:!aNULL@STRENGTH"
#define AES_CIPHERS "AES256-GCM-SHA384:AES256-SHA256:AES128-GCM-SHA384:AES128-SHA-256:AES256-SHA:AES128-SHA"
#define TRIPLEDES_CIPHERS "DES-CBC3-SHA"
#define CAMELLIA_CIPHERS "CAMELLIA128-SHA"

static GStaticMutex *mongo_ssl_locks; // Internal mutexes for OpenSSL functions
static gint mongo_ssl_lock_count;

static int mongo_ssl_verify_callback (int, X509_STORE_CTX *);

static unsigned long
ssl_thread_id () 
{
  return (unsigned long) pthread_self ();
}

static void 
ssl_locking_callback (int mode, int type, const char *file, int line)
{
  if (mode & CRYPTO_LOCK) 
    {
      g_static_mutex_lock (&mongo_ssl_locks[type]);
    }
  else
    {
      g_static_mutex_unlock (&mongo_ssl_locks[type]);
    }
}

static void
crypto_init_threading(void)
{
  gint i;

  mongo_ssl_lock_count = CRYPTO_num_locks ();
  mongo_ssl_locks = g_new (GStaticMutex, mongo_ssl_lock_count);
  for (i = 0; i < mongo_ssl_lock_count; i++)
    {
      g_static_mutex_init (&mongo_ssl_locks[i]);
    }
  CRYPTO_set_id_callback (ssl_thread_id);
  CRYPTO_set_locking_callback (ssl_locking_callback);
}

static void
crypto_deinit_threading(void)
{
  gint i;

  for (i = 0; i < mongo_ssl_lock_count; i++)
    {
      g_static_mutex_free (&mongo_ssl_locks[i]);
    }
    
  g_free (mongo_ssl_locks);
}

gboolean 
mongo_ssl_set_auto_retry (mongo_ssl_ctx *c, gboolean auto_retry)
{
  g_assert (c != NULL);
  g_assert (c->ctx != NULL);

  glong mode_new, mode_curr;

  mode_curr = SSL_CTX_get_mode (c->ctx);

  mode_new = 0;

  if (mode_curr & SSL_MODE_ENABLE_PARTIAL_WRITE)
    mode_new |= SSL_MODE_ENABLE_PARTIAL_WRITE;
  if (mode_curr & SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER)
    mode_new |= SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER;
  if ((mode_curr & SSL_MODE_AUTO_RETRY) && auto_retry)
    mode_new |= SSL_MODE_AUTO_RETRY;
  if (mode_curr & SSL_MODE_RELEASE_BUFFERS)
    mode_new |= SSL_MODE_RELEASE_BUFFERS;


  SSL_CTX_set_mode (c->ctx, 0);
  SSL_CTX_set_mode (c->ctx, mode_new);

  return TRUE;
}

void __attribute__ ((destructor))
mongo_ssl_util_cleanup_lib ()
{
  crypto_deinit_threading ();
}

void
_ignore_signal (gint _sig) 
{
  struct sigaction sa;

  memset (&sa, 0, sizeof (sa));
  sa.sa_handler = SIG_IGN;
  sigaction (_sig, &sa, NULL);
}

void __attribute__ ((constructor))
mongo_ssl_util_init_lib ()
{
  _ignore_signal (SIGPIPE);
  SSL_load_error_strings ();
  SSL_library_init ();
  OpenSSL_add_all_algorithms();
  crypto_init_threading (); 
}

gboolean
mongo_ssl_init (mongo_ssl_ctx* c) 
{
  g_assert (c != NULL);
  
  g_static_mutex_init (&c->__guard);
  c->ca_path = NULL;
  c->cert_path = NULL;
  c->crl_path = NULL;
  c->key_path = NULL;
  c->key_pw = NULL;
  c->session_cache = NULL;
  c->trusted_fingerprints = NULL;
  c->trusted_DNs = NULL;
  c->trust_required = TRUE;
  c->cert_required = TRUE;
  c->last_verify_result = MONGO_SSL_V_UNDEF;
  c->last_verify_err_code = X509_V_OK;

  if (c->ctx == NULL) 
    {
      c->last_ssl_error = 1;
      c->ctx = SSL_CTX_new (SSLv23_client_method ());
      if (c->ctx == NULL) 
        {
          c->last_ssl_error = ERR_peek_last_error ();
          return FALSE;
        }
           
      SSL_CTX_set_options(c->ctx, 
                          SSL_OP_NO_SSLv2 | 
                          SSL_OP_NO_COMPRESSION | 
                          SSL_OP_ALL | 
                          SSL_OP_SINGLE_DH_USE | 
                          SSL_OP_EPHEMERAL_RSA); 

      if (!SSL_CTX_set_cipher_list (c->ctx, HIGH_CIPHERS))
        {
          c->last_ssl_error = ERR_peek_last_error ();
          return FALSE;
        }
           
      if (!SSL_CTX_set_default_verify_paths (c->ctx)) 
        {
          c->last_ssl_error = ERR_peek_last_error();
          return FALSE;
        }

      SSL_CTX_set_verify (c->ctx, SSL_VERIFY_PEER, mongo_ssl_verify_callback);          
      mongo_ssl_set_verify_depth (c, MONGO_SSL_CERT_CHAIN_VERIFY_DEPTH);
      mongo_ssl_set_auto_retry (c, TRUE);
    }

  return TRUE;
}

SSL_CTX*
mongo_ssl_get_context(const mongo_ssl_ctx *c)
{
  g_assert(c != NULL);
  return c->ctx;
}

void 
mongo_ssl_set_verify_depth (mongo_ssl_ctx *c, guint depth)
{
  g_assert (c != NULL);

  c->verify_depth = depth;
  SSL_CTX_set_verify_depth (c->ctx, depth);
}

guint
mongo_ssl_get_verify_depth (const mongo_ssl_ctx *c)
{
  g_assert (c != NULL);

  return c->verify_depth;
}

void
mongo_ssl_set_security (mongo_ssl_ctx *c, gboolean required, gboolean trusted)
{
  g_assert (c != NULL);

  c->cert_required = required;
  c->trust_required = trusted;
}


gboolean
mongo_ssl_is_trust_required (const mongo_ssl_ctx *c)
{
  g_assert (c != NULL);

  return c->trust_required;
}

gboolean
mongo_ssl_is_cert_required (const mongo_ssl_ctx *c)
{
  g_assert (c != NULL);

  return c->cert_required;
}

static void
free_session_cache_element (gpointer p)
{
  mongo_ssl_session_cache_entry *ent = (mongo_ssl_session_cache_entry *) p;
  if (ent != NULL)
    {
      g_free (ent->target);
      SSL_SESSION_free (ent->sess);
    }
}

void
mongo_ssl_clear (mongo_ssl_ctx *c)
{
  if (c == NULL) return;
  if (c->ctx == NULL) return;

  SSL_CTX_free (c->ctx); c->ctx = NULL;
  
  g_free (c->ca_path);  c->ca_path = NULL;
  g_free (c->cert_path); c->cert_path = NULL;
  g_free (c->key_path); c->key_path = NULL;
  g_free (c->key_pw); c->key_pw = NULL;
  g_free (c->cipher_list); c->cipher_list = NULL;
  g_list_free_full (c->session_cache, free_session_cache_element); c->session_cache = NULL;
  c->trusted_DNs = NULL;
  c->trusted_fingerprints = NULL;
}

static gboolean 
_file_exists (const gchar *path)
{
  struct stat s;
  if (path == NULL) return FALSE;

  if (stat ((const char*) path, &s) != 0)
    {
      return FALSE; /* errno is set */
    }

  return TRUE;
}

gboolean
mongo_ssl_set_ca (mongo_ssl_ctx *c, const gchar *ca_path) 
{
  g_assert (c != NULL);
  g_assert (c->ctx != NULL);
  g_assert (ca_path != NULL);

  if (!_file_exists (ca_path)) return FALSE;

  if (!SSL_CTX_load_verify_locations (c->ctx, ca_path, NULL))
    {
      if (!SSL_CTX_load_verify_locations (c->ctx, NULL, ca_path))
        {
          c->last_ssl_error = ERR_peek_last_error ();
          return FALSE;
        }
    }

  g_free (c->ca_path);
  c->ca_path = g_strdup (ca_path);
  
  return TRUE;
}

gchar*
mongo_ssl_get_ca (const mongo_ssl_ctx *c)
{
  g_assert (c != NULL);
  g_assert (c->ctx != NULL);

  return c->ca_path;
}

gboolean
mongo_ssl_set_cert (mongo_ssl_ctx *c, const gchar *cert_path) 
{
  g_assert (c != NULL);
  g_assert (c->ctx != NULL);
  g_assert (cert_path != NULL);

  if (!_file_exists (cert_path)) return FALSE;

  if (!SSL_CTX_use_certificate_file (c->ctx, cert_path, SSL_FILETYPE_PEM)) 
    {
      if (!SSL_CTX_use_certificate_chain_file (c->ctx, cert_path)) 
        {
          c->last_ssl_error = ERR_peek_last_error ();
          return FALSE;
        }
    }

  g_free (c->cert_path);

  c->cert_path = g_strdup (cert_path);

  return TRUE;
}

gchar*
mongo_ssl_get_cert (const mongo_ssl_ctx *c)
{
  g_assert (c != NULL);
  g_assert (c->ctx != NULL);

  return c->cert_path;
}

gboolean
mongo_ssl_set_crl (mongo_ssl_ctx *c, const gchar *crl_path) 
{
  g_assert (c != NULL);
  g_assert (c->ctx != NULL);

  if (crl_path == NULL)
    {
      X509_VERIFY_PARAM_clear_flags (c->ctx->param, 
                                     X509_V_FLAG_CRL_CHECK | 
                                     X509_V_FLAG_CRL_CHECK_ALL | 
                                     X509_V_FLAG_EXTENDED_CRL_SUPPORT);
      return TRUE;
    }

  if (!_file_exists (crl_path)) return FALSE;

  if (!SSL_CTX_load_verify_locations (c->ctx, crl_path, NULL))
    {
      if (!SSL_CTX_load_verify_locations (c->ctx, NULL, crl_path))
        {
          c->last_ssl_error = ERR_peek_last_error ();
           return FALSE;
        }
     }
                                                              
  X509_VERIFY_PARAM* p = X509_VERIFY_PARAM_new ();
  X509_VERIFY_PARAM_set_flags (p, X509_V_FLAG_CRL_CHECK | X509_V_FLAG_EXTENDED_CRL_SUPPORT); 
  SSL_CTX_set1_param (c->ctx, p);
  X509_VERIFY_PARAM_free (p);

  c->crl_path = g_strdup (crl_path);
                                                                                                            
  return TRUE;
}

gchar*
mongo_ssl_get_crl (const mongo_ssl_ctx *c)
{
  g_assert (c != NULL);
  g_assert (c->ctx != NULL);

  return c->crl_path;
}

gboolean
mongo_ssl_set_key (mongo_ssl_ctx *c, const gchar *key_path, const gchar *key_pw) 
{
  g_assert (c != NULL);
  g_assert (c->ctx != NULL);
  g_assert (key_path != NULL);
  
  EVP_PKEY* private_key = NULL;
  gboolean ok = TRUE;

  if (!_file_exists (key_path)) return FALSE;
    
  if ((key_pw == NULL) || (strlen (key_pw) == 0))
    {
      if (!SSL_CTX_use_PrivateKey_file (c->ctx, key_path, SSL_FILETYPE_PEM))
        {
          c->last_ssl_error = ERR_peek_last_error ();
          return FALSE;
        }
    }
    
  else
    {
      FILE* pKeyFile = fopen (key_path, "r");

      if (pKeyFile == NULL)
        {
          errno = ENOENT;
          ok = FALSE;
        }
        
      private_key = PEM_read_PrivateKey (pKeyFile, NULL, NULL, (void*) key_pw);
      
      if (private_key == NULL)
        {
          c->last_ssl_error = ERR_peek_last_error ();
          ok = FALSE;
        }     
      else if (!SSL_CTX_use_PrivateKey (c->ctx, private_key))
        {
          c->last_ssl_error = ERR_peek_last_error ();
          ok = FALSE;
        }
                
      if (pKeyFile != NULL) fclose(pKeyFile);
    }

  if ( ok )
    {
      if (!SSL_CTX_check_private_key (c->ctx))
        {
          c->last_ssl_error = ERR_peek_last_error ();
          ok = FALSE;
        }
    
      if ( ok ) 
       {
         g_free (c->key_path); c->key_path = NULL;

         c->key_path = g_strdup (key_path);

         if (key_pw != NULL)
           {
             g_free (c->key_pw); c->key_pw = NULL;

             c->key_pw = g_strdup (key_pw);
             mlock (c->key_pw, strlen (key_pw) + 1);
           }
       }
    }

  EVP_PKEY_free (private_key);
  return ok;
}

gchar*
mongo_ssl_get_key (const mongo_ssl_ctx *c)
{
  g_assert (c != NULL);
  g_assert (c->ctx != NULL);

  return c->key_path;
}

gboolean 
mongo_ssl_set_ciphers (mongo_ssl_ctx *c, mongo_ssl_ciphers ciphers) 
{
  g_assert (c != NULL);
  g_assert (c->ctx != NULL);
  
  gboolean ok = TRUE;
  gchar *cipher_list = NULL;
  
  switch (ciphers) 
    {
      case MONGO_SSL_CIPHERS_AES: 
        cipher_list = g_strdup (AES_CIPHERS);
        break;
      case MONGO_SSL_CIPHERS_3DES:
        cipher_list = g_strdup (TRIPLEDES_CIPHERS);
        break;
      case MONGO_SSL_CIPHERS_CAMELLIA:
        cipher_list = g_strdup (CAMELLIA_CIPHERS);
        break;
      default: 
        cipher_list = g_strdup (HIGH_CIPHERS);
        break;
    }

  if (!SSL_CTX_set_cipher_list (c->ctx, cipher_list)) 
    {
      c->last_ssl_error = ERR_peek_last_error ();
      ok = FALSE;
    }

  g_free (c->cipher_list);
  c->cipher_list = g_strdup (cipher_list);

  g_free (cipher_list);
  
  return ok;
}

mongo_ssl_ciphers
mongo_ssl_get_ciphers (const mongo_ssl_ctx *c)
{
  g_assert (c != NULL);
  g_assert (c->ctx != NULL);

  if (strcmp (c->cipher_list, AES_CIPHERS) == 0)
    return MONGO_SSL_CIPHERS_AES;
  else if (strcmp (c->cipher_list, TRIPLEDES_CIPHERS) == 0)
    return MONGO_SSL_CIPHERS_3DES;
  else if (strcmp (c->cipher_list, CAMELLIA_CIPHERS) == 0)
    return MONGO_SSL_CIPHERS_CAMELLIA;
  else if (strcmp (c->cipher_list, HIGH_CIPHERS) == 0)
    return MONGO_SSL_CIPHERS_DEFAULT;
  else
   g_assert (FALSE); /* the structure has been manipulated by hand */
}

void 
mongo_ssl_set_trusted_fingerprints (mongo_ssl_ctx *c, GList *fingerprints)
{
  g_assert (c != NULL);

  c->trusted_fingerprints = fingerprints;
}

GList*
mongo_ssl_get_trusted_fingerprints (const mongo_ssl_ctx *c)
{
  g_assert (c != NULL);

  return c->trusted_fingerprints;
}

void
mongo_ssl_set_trusted_DNs (mongo_ssl_ctx *c, GList *DNs)
{
  g_assert (c != NULL);

  c->trusted_DNs = DNs;
}

GList*
mongo_ssl_get_trusted_DNs (const mongo_ssl_ctx *c)
{
  g_assert (c != NULL);

  return c->trusted_DNs;
}

static void
_get_dn (X509_NAME *name, GString *dn, gboolean reverse)
{
  g_assert (name != NULL);
  g_assert (dn != NULL);
  
  BIO *bio;
  gchar *buf;
  long len;

  bio = BIO_new (BIO_s_mem ());
  X509_NAME_print_ex (bio, name, 0, 
                      ASN1_STRFLGS_ESC_2253 | 
                      ASN1_STRFLGS_UTF8_CONVERT | 
                      XN_FLAG_SEP_CPLUS_SPC | 
                      (reverse ? XN_FLAG_DN_REV : 0));
  len = BIO_get_mem_data (bio, &buf);
  g_string_truncate (dn, 0);
  g_string_append_len (dn, buf, len);
  BIO_free (bio);
}


static gboolean
check_cn (const X509 *cert, const gchar *target_hostname)
{
  g_assert (cert != NULL);
  g_assert (target_hostname != NULL);

  gboolean sni_match = FALSE;
  int i = 0;
  gchar **dn_parts;
  gchar **fields;
  gchar *curr_field, *curr_key, *curr_value;
  gchar **field_parts;
  GString *dn;

  dn = g_string_sized_new (128);
  _get_dn (X509_get_subject_name ((X509*) cert), dn, TRUE);  
    
  dn_parts = g_strsplit (dn->str, ",", 0);
  curr_field = dn_parts[0];

  gchar *_cn = g_locale_to_utf8 ("cn", -1, NULL, NULL, NULL);
  gchar *_cni = g_utf8_casefold (_cn, -1);

  while (curr_field != NULL)
    {
      field_parts = g_strsplit (curr_field, "=", 2);
      curr_key = g_strstrip (field_parts[0]);
      curr_value = g_strstrip (field_parts[1]);
      
      if (curr_key == NULL || curr_value == NULL) continue;

      gchar *curr_key_utf8 = g_utf8_casefold (curr_key, -1);
      if (strcmp ((const char*) curr_key_utf8, (const char*) _cni) == 0)
        {
          if (g_pattern_match_simple ((const gchar*) curr_value, (const gchar*) target_hostname))
            {
              sni_match = TRUE;
            }
        }
  
      g_strfreev (field_parts);
      g_free (curr_key_utf8);

      if (sni_match) break;
      
      i += 1;
      curr_field = dn_parts[i];
    }

  g_strfreev (dn_parts);
  g_string_free (dn, TRUE);
  g_free (_cn);
  g_free (_cni);

  return sni_match;
}

static gboolean
check_altnames (const X509 *cert, const gchar *target_hostname)
{
  g_assert (cert != NULL);
  g_assert (target_hostname != NULL);
  
  int i, num = -1;
  STACK_OF (GENERAL_NAME) *names = NULL;
  gboolean sni_match = FALSE;

  names = X509_get_ext_d2i ((X509*) cert, NID_subject_alt_name, NULL, NULL);

  if (names == NULL) return FALSE;

  num = sk_GENERAL_NAME_num (names);

  gchar *t = g_locale_to_utf8 (target_hostname, -1, NULL, NULL, NULL);
  if (t == NULL) t = (gchar*) target_hostname;

  for (i = 0; i < num; ++i)
    {
      const GENERAL_NAME *curr = sk_GENERAL_NAME_value (names, i);
      if (curr->type == GEN_DNS)
        {
          gchar *dns;
          int dns_len = -1;
          if ( (dns_len = ASN1_STRING_to_UTF8 ((unsigned char**) &dns, curr->d.dNSName)) < 0) continue;
          if (dns_len != strlen (dns)) continue;
          if (g_pattern_match_simple ((const gchar*) dns, (const gchar*) t))
            {
              sni_match = TRUE;
            }
          
          OPENSSL_free (dns);
          if (sni_match) break;
        }
    }

  if (t != target_hostname) g_free (t);
  sk_GENERAL_NAME_free (names);

  return sni_match;
}

static gboolean
_get_X509_digest (const X509 *x, GString *hash_string)
{
  gint j;
  unsigned int n;
  unsigned char md[EVP_MAX_MD_SIZE];

  g_assert (hash_string != NULL);

  if (!X509_digest (x, EVP_sha1(), md, &n))
    return FALSE;

  g_string_append (hash_string, "SHA1:");
  for (j = 0; j < (int) n; j++)
    g_string_append_printf (hash_string, "%02X%c", md[j], (j + 1 == (int) n) ? '\0' : ':');

  return TRUE;
}

static gboolean 
check_fingerprint (const X509* cert, const mongo_ssl_ctx *c)
{
  g_assert (c != NULL);
  g_assert (cert != NULL);
  
  GString *hash = g_string_sized_new (EVP_MAX_MD_SIZE * 3);
  GList *curr_fingerprint = c->trusted_fingerprints;
  gboolean match = FALSE;

  
  if (_get_X509_digest (cert, hash) && curr_fingerprint)
    {
      for (; curr_fingerprint != NULL; curr_fingerprint = g_list_next (curr_fingerprint))
        {
          if (strncasecmp ((const gchar *) (curr_fingerprint->data), hash->str, hash->len) == 0)
            {
              match = TRUE;
              break;
            }
        }
    }

  g_string_free (hash, TRUE);

  return match;
}

static gboolean
check_dn (const X509 *cert, const mongo_ssl_ctx *c)
{
  g_assert (c != NULL);
  g_assert (cert != NULL);

  GString *dn, *dn_rev;
  gchar* _dn, *_dn_rev, *t;
  GList *curr_dn = c->trusted_DNs;
  gboolean match = FALSE;

  dn = g_string_sized_new (128);
  _get_dn (X509_get_subject_name ((X509*) cert), dn, FALSE);
  dn_rev = g_string_sized_new (128);
  _get_dn (X509_get_subject_name ((X509*) cert), dn_rev, TRUE);
  

  _dn = g_utf8_casefold (dn->str, -1);
  _dn_rev = g_utf8_casefold (dn_rev->str, -1);


  for (; curr_dn != NULL; curr_dn = g_list_next (curr_dn))
    {
      t = g_utf8_casefold (curr_dn->data, -1); 

      if (g_pattern_match_simple ((const gchar*) t, (const gchar*) _dn) ||
          g_pattern_match_simple ((const gchar*) t, (const gchar*) _dn_rev))
            {
              match = TRUE;
              break;
            }
       g_free (t);
    }

  g_string_free (dn, TRUE);
  g_free (_dn);
  g_free (_dn_rev);

  return match;
}

/* TODO: Find a way to report details of X509 validation errors */
static
mongo_ssl_verify_result
mongo_ssl_verify_session (int prevok, 
                          int preverr, 
                          SSL *c, 
                          BIO *b, 
                          X509 *cert, 
                          mongo_ssl_ctx *ctx, 
                          int depth) {
  g_assert (c != NULL);
  g_assert (b != NULL);
  g_assert (ctx != NULL);

  /*X509 *cert;*/
  char *target_hostname;
    
  gboolean sni_match = FALSE;
  int err;
  
  /* For non-leaf certs, just depend on prevok */
  if (depth != 0)
    {
      if (prevok != 1)
        {
          ctx->last_ssl_error = ERR_peek_last_error ();
          return MONGO_SSL_V_ERR_PROTO;
        }

        return MONGO_SSL_V_OK_ALL;
    }

  /* cert = SSL_get_peer_certificate (c); */
  target_hostname = BIO_get_conn_hostname (b);
  
  if (ctx->cert_required && (cert == NULL))
    {
      return MONGO_SSL_V_ERR_NO_CERT;
    }

  if (!ctx->trust_required)
    {
      return MONGO_SSL_V_OK_NO_VERIFY;
    }

  /** Fingerprint whitelisting
    * IMPORTANT: When the received fingerprint is not present on the list: drop the connection, however, when it is,
    * accept the certificate without validation
  **/
  if (ctx->trusted_fingerprints)
    {
      if (!check_fingerprint (cert, ctx)) 
        return MONGO_SSL_V_ERR_UNTRUSTED_FP;
      else
        return MONGO_SSL_V_OK_TRUSTED_FP;
    }

  /** DN whitelisting
    * IMPORTANT: When received DN is not present on the list: drop the connection, however, when it is, 
    * continue certificate validation
  **/
  if (ctx->trusted_DNs)
    {
      if (!check_dn (cert, ctx))
        return MONGO_SSL_V_ERR_UNTRUSTED_DN;
    }
  
  if ((prevok != 1) && (preverr != X509_V_ERR_INVALID_PURPOSE))
    {
      ctx->last_ssl_error = ERR_peek_last_error ();
      return MONGO_SSL_V_ERR_PROTO;
    }
  

  /* Hostname check */
  if (target_hostname != NULL)
    {
      sni_match = (check_cn (cert, target_hostname)) || (check_altnames (cert, target_hostname));

      if (! sni_match) 
        {
          return MONGO_SSL_V_ERR_SNI;
        }
    } 
  else
    {
      return MONGO_SSL_V_OK_NO_HOSTNAME;
    }

  return MONGO_SSL_V_OK_ALL;
}


static int
mongo_ssl_verify_callback (int preverify_ok, X509_STORE_CTX *ctx)
{
  int err, depth;
  SSL *ssl;
  BIO *bio;
  mongo_ssl_ctx *_ctx;
  X509 *cert;
  mongo_ssl_verify_result rstat = MONGO_SSL_V_UNDEF;

  cert = X509_STORE_CTX_get_current_cert (ctx);
  err = X509_STORE_CTX_get_error (ctx);
  ssl = X509_STORE_CTX_get_ex_data (ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
  _ctx = (mongo_ssl_ctx *) SSL_get_app_data (ssl);
  depth = X509_STORE_CTX_get_error_depth (ctx);

  if (_ctx == NULL)
      return 0;

  _ctx->last_verify_err_code = err;

  bio = SSL_get_rbio (ssl);

  if (bio == NULL) 
    bio = SSL_get_wbio (ssl);

  if (bio == NULL)
      return 0;
  
  rstat = mongo_ssl_verify_session (preverify_ok, err, ssl, bio, cert, _ctx, depth);
  _ctx->last_verify_result = rstat;
  if ( ! MONGO_SSL_SESSION_OK (rstat) )
      return 0;

  return 1;
}


const gchar *
mongo_ssl_get_last_error (const mongo_ssl_ctx *c)
{
  g_assert (c != NULL);

  return (const gchar*) ERR_error_string (c->last_ssl_error, NULL);
}

mongo_ssl_verify_result 
mongo_ssl_get_last_verify_result (const mongo_ssl_ctx *c)
{
  g_assert (c != NULL);

  return c->last_verify_result;
}

const gchar *
mongo_ssl_get_last_verify_error (const mongo_ssl_ctx *c)
{
  g_assert (c != NULL);

  return (const gchar *) X509_verify_cert_error_string (c->last_verify_err_code);
}

void
mongo_ssl_lock (mongo_ssl_ctx *c)
{
  g_assert (c != NULL);

  g_static_mutex_lock (&c->__guard);
}

void mongo_ssl_unlock (mongo_ssl_ctx *c)
{
  g_assert (c != NULL);

  g_static_mutex_unlock (&c->__guard);
}
