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


G_BEGIN_DECLS

/** @defgroup mongo_ssl Mongo SSL support API
 *
 * These functions are used by the Mongo Cilient and Mongo Sync API components
 * to enable client to connect to MongoDB servers via SSL / TLS. 
 *
 *
 * However, they may not be called directly by the the library's user, instead, one should call
 * mongo_sync_ssl_connect () to establish a synchronous SSL connection to the MongoDB database.
**/

// TODO: Make mongo_ssl_ctx and mongo_ssl_conn thread safe !!!!

/** An internal context structure that is a wrapper for the SSL_CTX object. It also stores configuration parameters and last SSL related error code from the OpenSSL library. Multiple threads may use the same mongo_ssl_ctx, but only one should manipulate it
via setter functions at a time! (The internal SSL_CTX object is made thread-safe by the library, but the data fields in mongo_ssl_ctx are not so multiple writes from different threads may introduce inconsistency between these values in mongo_ssl_ctx and the actual state of the internal SSL_CTX object) **/
typedef struct {
    gchar *ca_path;
    gchar *cert_path;
    gchar *crl_path; 
    gchar *key_path;
    gchar *cipher_list;  
    gchar *key_pw;
    int verify_depth;

    SSL_CTX *ctx;
    X509_VERIFY_PARAM *params;
    long last_ssl_error;
    GStaticMutex __guard;
} mongo_ssl_ctx;

/** An SSL connection wrapper that consist of a connection (SSL) object and a bidirectional I/O object (BIO) that represents the channel itself. Never manipulate a mongo_ssl_conn object manually! **/
typedef struct {
    BIO* bio;
    SSL* conn;
    mongo_ssl_ctx *super;
} mongo_ssl_conn;

/** Available cipher sets supported by MongoDB (as of 2.6). Use MONGO_SSL_CIPHERS_DEFAULT unless you have a strong reason to use a different option **/
typedef enum {
    MONGO_SSL_CIPHERS_DEFAULT,
    MONGO_SSL_CIPHERS_AES,
    MONGO_SSL_CIPHERS_3DES,
    MONGO_SSL_CIPHERS_CAMELLIA
} mongo_ssl_ciphers;

/** Initializes OpenSSL for you
 * 
 * SSL support depends on the OpenSSL library which has to be initialized before calling any SSL-related functions. 
 * This utility function provides proper initialization of OpenSSL that suits the requirements of this library. It takes care of
 * loading ciphers, error strings, threading setup, etc.
**/
void mongo_ssl_util_init_lib ();

/** Cleans up OpenSSL for you
 *
 * When one does not use OpenSSL any more within a program, the memory allocated by the library should be freed, to avoid
 * memory leaks. This utility function takes care of the cleanup process.
**/
void mongo_ssl_util_cleanup_lib ();

/** Initializes a Mongo SSL context object
 * 
 * Sets all properties to their default values (mostly NULLs) and sets up the inner SSL_CTX object, also specifies some default
 * settings, like forbidding compression, default accepted ciphers list, default cert. paths, chain verification depth and 
 * additional SSL options.
 *
 * @param ctx A valid pointer to a properly allocated mongo_ssl_ctx structure
 * @returns TRUE on success, FALSE on failure
**/
gboolean mongo_ssl_conf_init (mongo_ssl_ctx *ctx);

/** Clears a Mongo SSL context object
 *
 * Resets a mongo_ssl_ctx object to its default state. Please note, that this function deallocates all internal
 * objects, so you should call mongo_ssl_conf_init () again if you want to re-use the object. It also implies, that
 * the structure itself does not get deallocated - that is the responsiblity of the user as well as allocation.
 * @param ctx A valid pointer to a properly allocated mongo_ssl_ctx structure
**/
void mongo_ssl_conf_clear (mongo_ssl_ctx *ctx);

/** Sets CA (Certificate Authority) certificate file path
 * 
 * The given path may point to a single certificate file, or a directory containing several certificates.
 * It stat()-s the given file before accessing it. Please note, that the file(s) must be in PEM format. 
 * @param ctx A valid pointer to a properly allocated and initialized mongo_ssl_ctx structure
 * @param ca_path CA path (string)
 * @returns TRUE on success, FALSE on failure
**/
gboolean mongo_ssl_conf_set_ca (mongo_ssl_ctx *ctx, gchar *ca_path);

/** Sets client certificate file path
 * 
 * The client will present this certificate upon request. The file should contain either a single certificate or an
 * entire certificate chain and it must be in PEM format. The function stat()-s the given file before accessing it.
 * @param ctx A valid pointer to a properly allocated and initialized mongo_ssl_ctx sturcture
 * @param cert_path Certificate file path (string)
 * @returns TRUE on success, FALSE on failure
**/
gboolean mongo_ssl_conf_set_cert (mongo_ssl_ctx *ctx, gchar *cert_path);

/** Sets CRL (Certificate Revocation List) file path
 *
 * If specified, the client performs CRL check against the server's certificate on the basis of the provided file.
 * The path can either point to a directory containing CRL files or a single CRL file. Only PEM format is supported.
 * The function stat()-s the given file before accessing it. 
 * @param ctx A valid pointer to a properly allocated and initialized mongo_ssl_ctx structure
 * @param crl_path Path to CRL file or directory (string)
 * @returns TRUE on success, FALSE on failure
**/
gboolean mongo_ssl_conf_set_crl (mongo_ssl_ctx *ctx, gchar *crl_path);

/** Sets client private key file
 *
 * The user must specify the client's private key. The key file must be PEM-formatted, although, may be encrypted.
 * When encrypted, the caller must pass the password. The function stat()-s the given file before accessing it.
 * @param ctx A valid pointer to a properly allocated and initialized mongo_ssl_ctx structure
 * @param key_path Path to private key file (string)
 * @param key_pw If given, the private key file is assumed to be encrypted, and the password is used to decrypt it. If it is NULL, the key file is assumed to be - consequently, treated as - plain text
 * @returns TRUE on success, FALSE on failure
**/
gboolean mongo_ssl_conf_set_key (mongo_ssl_ctx *ctx, gchar *key_path, gchar *key_pw); 

/** Sets list of accepted ciphers
 *
 * Set ciphers that the client should accept during the handshake process.
 * @param ctx A valid pointer to a properly allocated and initialized mongo_ssl_ctx structure
 * @param ciphers Cipher list specification
 * @returns TRUE on success, FALSE on failure
**/
gboolean mongo_ssl_conf_set_ciphers (mongo_ssl_ctx *ctx, mongo_ssl_ciphers chipers);

/** Puts further connections corresponding to the given context in auto-retry mode
 *
 * Auto-retry: low-level write and read functions return only if a valid handshake has been completed as well as the operation.
 * When a renegotation is taking place, the library attempts to perform the operation later and blocks until completion. 
 * Please note, that auto-retry mode is the default behavior within this library.
 * @param ctx A valid pointer to a properly allocated and initialized mongo_ssl_ctx structure
 * @param auto_retry Should be TRUE to turn on auto-retry, FALSE to turn off
 * @returns TRUE on success, FALSE on failure
**/
gboolean mongo_ssl_set_auto_retry (mongo_ssl_ctx *ctx, gboolean auto_retry);

/** Performs session verification
 *
 * Checks the certificate provided by the server. The check includes the OpenSSL built-in process
 * (fingerprint, expiration, CRL, recursive...) and SNI (based on either CN and SubjectAltNames) for the
 * first certificate in the chain. This function is called from mongo_ssl_connect () right after the handshake.
 * Do not call this function directly.
 * @param c A pointer to the SSL object representing the connection
 * @param b A pointer to a BIO object representing the channel
**/
int mongo_ssl_verify_session (SSL *c, BIO *b); 

/** Retrieves the last SSL-related error message 
 *
 * Gets the latest OpenSSL library error message
 * @param ctx A valid pointer to a properly allocated and initialized mongo_ssl_ctx structure
 * @return An OpenSSL error string (should never be NULL)
**/
const gchar* mongo_ssl_last_error (mongo_ssl_ctx *ctx);

G_END_DECLS

#endif


