/* mongo-ssl.h - libmongo client's SSL support
* Copyright 2014 Gyorgy Demarcsek <dgy.jr92@gmail.com>
*/

/** @file src/mongo-ssl.h
 * SSL support main header
**/

#ifndef _LIBMONGO_CLIENT_MONGO_SSL_H
#define _LIBMONGO_CLIENT_MONGO_SSL_H 1

#include <glib.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/engine.h>
#include <openssl/conf.h>

#define MONGO_SSL_CERT_CHAIN_VERIFY_DEPTH 5

//#ifndef debug_print
//#define debug_print(fmt, ...) \
//        do { fprintf(stderr, "%s:%d:%s(): " fmt, __FILE__, \
                                        __LINE__, __func__, ##__VA_ARGS__); } while (0)
//#endif

G_BEGIN_DECLS

typedef struct {
    gchar *ca_path;
    gchar *cert_path;
    gchar *crl_path; 
    gchar *key_path;
    gchar *cipher_list; // not used yet
    gchar *key_pw;
    int verify_depth;

    SSL_CTX *ctx;
    X509_VERIFY_PARAM *params;
    long last_ssl_error;
} mongo_ssl_ctx;

typedef struct {
    BIO* bio;
    SSL* conn;
    mongo_ssl_ctx *super;
} mongo_ssl_conn;

int mongo_ssl_util_init_lib ();
void mongo_ssl_util_cleanup_lib ();
int mongo_ssl_conf_init (mongo_ssl_ctx *ctx);
void mongo_ssl_conf_clear (mongo_ssl_ctx *ctx);
int mongo_ssl_conf_set_ca (mongo_ssl_ctx *ctx, gchar *ca_path);
int mongo_ssl_conf_set_cert (mongo_ssl_ctx *ctx, gchar *cert_path);
int mongo_ssl_conf_set_crl (mongo_ssl_ctx *ctx, gchar *crl_path);
int mongo_ssl_conf_set_key (mongo_ssl_ctx *ctx, gchar *key_path, gchar *key_pw); 
int mongo_ssl_conf_set_ciphers (mongo_ssl_ctx *ctx, gchar *cipher_list);
int mongo_ssl_set_auto_retry (mongo_ssl_ctx *ctx);
int mongo_ssl_verify_session (SSL *c, BIO *b); 

G_END_DECLS

#endif


