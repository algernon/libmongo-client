#include "mongo-ssl.h"

#include <glib.h>
#include <assert.h>
#include <pthread.h>
#include <string.h>

#include <sys/stat.h>
#include <stdio.h> 


static const gchar *mongo_ssl_default_cipher_list = "HIGH";
static gboolean mongo_ssl_lib_initialized = FALSE;
static GStaticMutex *mongo_ssl_locks;
static gint mongo_ssl_lock_count;

// FIXME: Some portions come from the syslog-ng source code (to merge or not to merge, that is the question...)

// TODO: check_dn (), check_altnames () = SNI 
// TODO: rettype int --> gboolean (where only 0 or 1 returned : FALSE = 0, TRUE = (!FALSE)) 

static unsigned long
ssl_thread_id () 
{
  return (unsigned long) pthread_self (); // TODO: For now, I did not bother myself with Windows
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

int 
mongo_ssl_set_auto_retry (mongo_ssl_ctx *c)
{
  assert (c != NULL);
    
  if (c->ctx == NULL)
    {
      errno = EINVAL;
      return -1;
    }

  SSL_CTX_set_mode (c->ctx, SSL_MODE_AUTO_RETRY);
  return 1;
}

void 
mongo_ssl_util_cleanup_lib () 
{
  crypto_deinit_threading ();
  CONF_modules_free ();
  ERR_remove_state (0);
  ENGINE_cleanup ();	
  CONF_modules_unload (1);
  ERR_free_strings ();
  EVP_cleanup ();
  CRYPTO_cleanup_all_ex_data ();
  mongo_ssl_lib_initialized = FALSE;
}

static void
_ignore_signal (gint _sig) 
{
  struct sigaction sa;

  memset (&sa, 0, sizeof (sa));
  sa.sa_handler = SIG_IGN;
  if (sigaction (_sig, &sa, NULL) < 0)
    fprintf (stderr, "sigaction() error\n");
}

int
mongo_ssl_util_init_lib ()
{
  _ignore_signal (SIGPIPE);
  CRYPTO_malloc_init ();
  OPENSSL_config (NULL);
  SSL_load_error_strings ();
  ERR_load_BIO_strings ();
  SSL_library_init ();
  crypto_init_threading ();        
}

int 
mongo_ssl_conf_init (mongo_ssl_ctx* c) 
{
    c->ca_path = NULL;
    c->cert_path = NULL;
    c->crl_path = NULL;
    c->key_path = NULL;
    c->key_pw = NULL;

    if (c->ctx == NULL) 
        {
           c->last_ssl_error = 1;
           c->ctx = SSL_CTX_new (SSLv23_client_method ());
           if (c->ctx == NULL) 
            {
                c->last_ssl_error = ERR_peek_last_error ();
                return 0;
            }
           
           SSL_CTX_set_options(c->ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_COMPRESSION | SSL_OP_ALL | SSL_OP_SINGLE_DH_USE | SSL_OP_EPHEMERAL_RSA);

           if (!SSL_CTX_set_cipher_list (c->ctx, mongo_ssl_default_cipher_list))
            {
                c->last_ssl_error = ERR_peek_last_error ();
                return 0;
            }
           
           if (!SSL_CTX_set_default_verify_paths (c->ctx)) 
            {
                c->last_ssl_error = ERR_peek_last_error();
                return 0;
            }

          SSL_CTX_set_verify (c->ctx, SSL_VERIFY_PEER, NULL);
          /*
           * We could use our own verification callback here but it is just more simple to
           * use a dedicated function for server authentication aka. session verification (mongo_ssl_verify_session).
           * This technique has some disadvantages too:
           *  --> Handshake may complete before hostname checks
           *  --> X509_V_ERR_CERT_CHAIN_TOO_LONG cannot be detected properly
          **/
          c->verify_depth = MONGO_SSL_CERT_CHAIN_VERIFY_DEPTH;
          SSL_CTX_set_verify_depth (c->ctx, c->verify_depth); 
          mongo_ssl_set_auto_retry (c);
       }
       return 1;
}

void
mongo_ssl_conf_clear (mongo_ssl_ctx *c)
{
  if (c == NULL) return;
  if (c->ctx == NULL) return;

  SSL_CTX_free (c->ctx); c->ctx = NULL;
  g_free (c->ca_path);  c->ca_path = NULL;
  g_free (c->cert_path); c->cert_path = NULL;
  g_free (c->key_path); c->key_path = NULL;
  g_free (c->key_pw); c->key_pw = NULL;
}

static gboolean 
_file_exists (gchar *path)
{
  struct stat s;
  if (stat ((const char*) path, &s) != 0)
    {
      return FALSE; // errno is set
    }

  return TRUE;
}

int 
mongo_ssl_conf_set_ca (mongo_ssl_ctx *c, gchar *ca_path) 
{
  assert(c != NULL);
  assert(c->ctx != NULL);
  assert(ca_path != NULL);

  if (!_file_exists (ca_path)) return 0;

  if (!SSL_CTX_load_verify_locations (c->ctx, ca_path, NULL))
    {
      if (!SSL_CTX_load_verify_locations (c->ctx, NULL, ca_path))
        {
          c->last_ssl_error = ERR_peek_last_error();
          return 0;
        }
    }

  c->ca_path = g_strdup (ca_path);
  return 1;
}

int 
mongo_ssl_conf_set_cert (mongo_ssl_ctx *c, gchar *cert_path) 
{
  assert(c != NULL);
  assert(c->ctx != NULL);
  assert(cert_path != NULL);

  if (!_file_exists (cert_path)) return 0;

  if (!SSL_CTX_use_certificate_file (c->ctx, cert_path, SSL_FILETYPE_PEM)) 
    {
      if (!SSL_CTX_use_certificate_chain_file (c->ctx, cert_path)) 
        {
          c->last_ssl_error = ERR_peek_last_error ();
          return 0;
        }
    }

  c->cert_path = g_strdup (cert_path);
  return 1;
}

int 
mongo_ssl_conf_set_crl (mongo_ssl_ctx *c, gchar *crl_path) 
{
    assert (c != NULL);
    assert (c->ctx != NULL);
    assert (crl_path != NULL);

    if (!_file_exists (crl_path)) return 0;

    if (!SSL_CTX_load_verify_locations (c->ctx, crl_path, NULL))
      {
        if (!SSL_CTX_load_verify_locations (c->ctx, NULL, crl_path))
          {
            c->last_ssl_error = ERR_peek_last_error ();
            return 0;
          }
      }


    
    X509_VERIFY_PARAM* p = X509_VERIFY_PARAM_new ();
    X509_VERIFY_PARAM_set_flags (p, X509_V_FLAG_CRL_CHECK | X509_V_FLAG_EXTENDED_CRL_SUPPORT); 
    SSL_CTX_set1_param(c->ctx, p);
    X509_VERIFY_PARAM_free (p);
    
    return 1;
}

int 
mongo_ssl_conf_set_key (mongo_ssl_ctx *c, gchar *key_path, char *key_pw) 
{
    assert(c != NULL);
    assert(c->ctx != NULL);
    assert(key_path != NULL);

    if (!_file_exists (key_path)) return 0;
    
    if (key_pw == NULL)
        {
            if (!SSL_CTX_use_PrivateKey_file (c->ctx, key_path, SSL_FILETYPE_PEM))
                {
                    c->last_ssl_error = ERR_peek_last_error ();
                    return 0;
                }
        }
    else
        {
            FILE* pKeyFile = fopen (key_path, "r");
            if (pKeyFile == NULL)
                {
                    errno = ENOENT;
                    return 0;
                }
            EVP_PKEY* private_key = PEM_read_PrivateKey (pKeyFile, NULL, NULL, key_pw);
            if (private_key == NULL) 
                {
                        c->last_ssl_error = ERR_peek_last_error ();
                        return 0;
                }
                if (!SSL_CTX_use_PrivateKey (c->ctx, private_key)) {
                        c->last_ssl_error = ERR_peek_last_error ();
                        return 0;
                }
                fclose(pKeyFile);
        }

    if (!SSL_CTX_check_private_key (c->ctx))
        {
            c->last_ssl_error = ERR_peek_last_error ();
            return 0;
        }
    
    c->key_path = g_strdup (key_path);
    if (key_pw != NULL) 
        {
            c->key_pw = g_strdup (key_pw);
            mlock (c->key_pw, strlen (key_pw) + 1);
        }
    return 1;
}

int 
mongo_ssl_conf_set_ciphers (mongo_ssl_ctx *c, gchar *cipher_list) 
{
    assert (c != NULL);
    assert (c->ctx != NULL);
    assert (cipher_list != NULL);
    
    if (!SSL_CTX_set_cipher_list (c->ctx, cipher_list)) 
        {
            c->last_ssl_error = ERR_peek_last_error ();
            return 0;
        }

    return 1;
}


static void
_get_dn (X509_NAME *name, GString *dn)
{
  BIO *bio;
  gchar *buf;
  long len;

  bio = BIO_new (BIO_s_mem ());
  X509_NAME_print_ex (bio, name, 0, ASN1_STRFLGS_ESC_2253 | ASN1_STRFLGS_UTF8_CONVERT | XN_FLAG_SEP_CPLUS_SPC | XN_FLAG_DN_REV);
  len = BIO_get_mem_data (bio, &buf);
  g_string_truncate (dn, 0);
  g_string_append_len (dn, buf, len);
  BIO_free (bio);
}


static gboolean
check_dn (const X509 *cert, const gchar *target_hostname)
{
  gboolean sni_match = FALSE;
  int i = 0;
  gchar **dn_parts;
  gchar **fields;
  gchar *curr_field, *curr_key, *curr_value;
  gchar **field_parts;
  GString *dn;

  dn = g_string_sized_new (128);
  _get_dn (X509_get_subject_name ((X509*) cert), dn);
    
  dn_parts = g_strsplit (dn->str, ",", 0);
  curr_field = dn_parts[0];

  gchar *_cn = g_locale_to_utf8 ("CN", -1, NULL, NULL, NULL);

  while (curr_field != NULL)
    {
      field_parts = g_strsplit (curr_field, "=", 2);
      curr_key = g_strchomp (field_parts[0]);
      curr_value = g_strchomp (field_parts[1]);
      
      while ((*curr_key) == 0x20) curr_key++;
      while ((*curr_value) == 0x20) curr_value++;

      if (curr_key == NULL || curr_value == NULL) continue;
      if (strcmp ((const char*) g_utf8_casefold (curr_key, -1), (const char*) g_utf8_casefold (_cn, -1))== 0)
        {
          if (g_pattern_match_simple ((const gchar*) curr_value, (const gchar*) target_hostname))
            {
              sni_match = TRUE;
              g_strfreev (field_parts);
              break;
            }
        }
  
      g_strfreev (field_parts);
      i += 1;
      curr_field = dn_parts[i];
    }

  g_strfreev (dn_parts);
  g_string_free (dn, TRUE);

  return sni_match;
}

static gboolean
check_altnames (const X509 *cert, const gchar *target_hostname)
{
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
  
  return sni_match;
}

int 
mongo_ssl_verify_session (SSL *c, BIO *b) {
  assert (c != NULL);
  assert (b != NULL);

  X509 *cert;
  char *target_hostname;
    
  gboolean sni_match = FALSE;
  int err;
   
  cert = SSL_get_peer_certificate (c);
  target_hostname = BIO_get_conn_hostname (b);
    
  if (cert == NULL)
    {
      return X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT; // TODO: Find more suitable error code to return 
    }

  if (target_hostname == NULL)
    {
      errno = EINVAL;
      return -1;
    }


  if ((err = SSL_get_verify_result (c)) != X509_V_OK)
    {
      return err;
    }

  sni_match = (check_dn (cert, target_hostname)) || (check_altnames (cert, target_hostname));

  if (! sni_match) 
    {
      err = X509_V_ERR_SUBJECT_ISSUER_MISMATCH;
      return err;
    }

  return 1;
}

int 
mongo_ssl_conf_free (mongo_ssl_ctx *c)
{
    assert (c != NULL);

    SSL_CTX_free (c->ctx);
    g_free (c);
    return 1;
}
