/* mongo-ssl.h - libmongo-client's SSL support
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

/** Available cipher sets supported by MongoDB (as of 2.6). Use MONGO_SSL_CIPHERS_DEFAULT unless you have a strong reason to use a different option **/
typedef enum {
  MONGO_SSL_CIPHERS_DEFAULT,
  MONGO_SSL_CIPHERS_AES,
  MONGO_SSL_CIPHERS_3DES,
  MONGO_SSL_CIPHERS_CAMELLIA
} mongo_ssl_ciphers;

typedef enum {
  /** Verification is not done yet - no result available **/
  MONGO_SSL_V_UNDEF = 1,
  /** The peer has not presented a certificate despite it is required **/
  MONGO_SSL_V_ERR_NO_CERT = 2,
  /** Hostname verification failed **/
  MONGO_SSL_V_ERR_SNI = 3,
  /** Trusted fingerprints list specified, but the received fingerprint is not on the list **/
  MONGO_SSL_V_ERR_UNTRUSTED_FP = 4,
  /** Trusted DNs list specified, but the received DN is not on the list **/
  MONGO_SSL_V_ERR_UNTRUSTED_DN = 5,
  /** Certificate chain verification failed (see last_ssl_error for details) **/
  MONGO_SSL_V_ERR_PROTO = 10,
  /** Session verified OK, because the certificate fingerprint is on trusted list (certificate MAY be invalid) **/
  MONGO_SSL_V_OK_TRUSTED_FP = 11,
  /** Session verified OK, but hostname verification has been skipped due to the inability to resolve the server's address **/
  MONGO_SSL_V_OK_NO_HOSTNAME = 12,
  /** Session verified OK, but only because any X509 certificate is automatically trusted**/
  MONGO_SSL_V_OK_NO_VERIFY = 13,
  /** Session verified OK - all checks passed **/
  MONGO_SSL_V_OK_ALL = 14
} mongo_ssl_verify_result;

#define MONGO_SSL_SESSION_OK(s) ( ((int) s > (int) MONGO_SSL_V_ERR_PROTO) )

typedef struct {
  gchar *target;
  SSL_SESSION *sess;
} mongo_ssl_session_cache_entry;

/** An internal context structure that is a wrapper for the SSL_CTX object. It also stores configuration parameters and last SSL related error code from the OpenSSL library. Multiple threads may use the same mongo_ssl_ctx, but only one should manipulate it
via setter functions at a time! (The internal SSL_CTX object is made thread-safe by the library, but the data fields in mongo_ssl_ctx are not so multiple writes from different threads may introduce inconsistency between these values in mongo_ssl_ctx and the actual state of the internal SSL_CTX object) However, you may use mongo_ssl_lock () and mongo_ssl_conf_unlock () to initiate mutual exclusion (not really efficient; I still recommend deep copying mongo_ssl_ctx objects, one copy for each thread). Even better, call any setter functions sequentially, from one thread, then use the context (with no manipulation) from multiple threads simultaneously without locking.  **/
typedef struct {
  gchar *ca_path;
  gchar *cert_path;
  gchar *crl_path; 
  gchar *key_path;
  gchar *cipher_list;  
  gchar *key_pw;
  gint verify_depth;

  SSL_CTX *ctx;
  X509_VERIFY_PARAM *params;
  glong last_ssl_error;
  mongo_ssl_verify_result last_verify_result;
  glong last_verify_err_code;
  GList *session_cache;
  GList *trusted_fingerprints;
  GList *trusted_DNs;
  gboolean /*server_*/cert_required;
  gboolean trust_required;
  GStaticMutex __guard;
} mongo_ssl_ctx;

/** An SSL connection wrapper that consist of a connection (SSL) object and a bidirectional I/O object (BIO) that represents the channel itself. Never manipulate a mongo_ssl_conn object manually! Also note that this wrapper is not thread safe! One particular mongo_ssl_conn object should be manipulated only by one thread at a time. **/
typedef struct {
  BIO* bio;
  SSL* conn;
  mongo_ssl_verify_result verification_status;
  mongo_ssl_ctx *super;
} mongo_ssl_conn;


/** Initializes a Mongo SSL context object
 * 
 * Sets all properties to their default values (mostly NULLs) and sets up the inner SSL_CTX object, also specifies some default
 * settings, like forbidding compression, default accepted ciphers list, default cert. paths, chain verification depth and 
 * additional SSL options.
 *
 * @param ctx A valid pointer to a properly allocated mongo_ssl_ctx structure
 * @returns TRUE on success, FALSE on failure
**/
gboolean mongo_ssl_init (mongo_ssl_ctx *ctx);

/** Clears a Mongo SSL context object
 *
 * Resets a mongo_ssl_ctx object to its default state. Please note, that this function deallocates all internal
 * objects, so you should call mongo_ssl_init () again if you want to re-use the object. It also implies, that
 * the structure itself does not get deallocated - that is the responsiblity of the user as well as allocation. Also, 
 * trusted fingerprints and DNs lists do not get deallocated, however their pointers get reset, so you need another pointer
 * refering to them so you can deallocate them properly if needed - this is the responsibility of the caller.
 * @param ctx A valid pointer to a properly allocated mongo_ssl_ctx structure
**/
void mongo_ssl_clear (mongo_ssl_ctx *ctx);

/** Sets trusted DNs list
 *
 * If set, the client only accepts certificates containing a DN matching one of those in the list. Actually, it only 
 * sets an internal pointer to the given address (no deep copy). The validity of that address and the data located in 
 * there is the responsibility of the caller. This implies, that you may pass NULL as well, to 'clear' the list.
 * @param ctx A valid pointer to a properly allocated and initialized mongo_ssl_ctx structure
 * @param DNs A list of g_char* strings storing trusted distinguished names
**/
void mongo_ssl_set_trusted_DNs (mongo_ssl_ctx *ctx, GList *DNs);

/** Gets the trusted DNs list
 * @returns A pointer to the first element of the list (may be NULL)
**/
GList *mongo_ssl_get_trusted_DNs ();

/** Sets trusted fingerprints list
 * If set, the client only accepts certificates having one of those SHA-1 fingerprints on the list. Actually, it only 
 * sets an internal pointer to the given address (no deep copy). The validity of that address and the data located in 
 * there is the responsibility of the caller. This implies, that you may pass NULL as well, to 'clear' the list.
 * @param ctx A valid pointer to a properly allocated and initialized mongo_ssl_ctx structure
 * @param fingerprints A list of g_char* strings storing trusted SHA-1 fingerprints; each one is required to be in the following format: SHA1:XX:XX:XX:XX:XX:XX:XX:XX:XX:XX:XX:XX:XX:XX:XX:XX:XX:XX:XX:XX 
**/
void mongo_ssl_set_trusted_fingerprints (mongo_ssl_ctx *ctx, GList *fingerprints);

/** Retrieves trusted fingerprints list
 * @returns A pointer to the first element of the list (may be NULL)
**/
GList *mongo_ssl_get_trusted_fingerprints (const mongo_ssl_ctx *ctx);

/** Sets CA (Certificate Authority) certificate file path
 * 
 * The given path may point to a single certificate file, or a directory containing several certificates.
 * It stat()-s the given file before accessing it. Please note, that the file(s) must be in PEM format. 
 * @param ctx A valid pointer to a properly allocated and initialized mongo_ssl_ctx structure
 * @param ca_path CA path (string)
 * @returns TRUE on success, FALSE on failure
**/
gboolean mongo_ssl_set_ca (mongo_ssl_ctx *ctx, const gchar *ca_path);

/** Gets CA (Certificate Authority) certificate file path
 *
 * Retrieves a previously set CA cert. file path defined within the given context.
 * @param ctx A valid pointer to a properly allocated and initialized mongo_ssl_ctx structure
 * @returns CA path (string); NULL if not set
**/
gchar *mongo_ssl_get_ca (const mongo_ssl_ctx *ctx);

/** Sets client certificate file path
 * 
 * The client will present this certificate upon request. The file should contain either a single certificate or an
 * entire certificate chain and it must be in PEM format. The function stat()-s the given file before accessing it.
 * @param ctx A valid pointer to a properly allocated and initialized mongo_ssl_ctx sturcture
 * @param cert_path Certificate file path (string)
 * @returns TRUE on success, FALSE on failure
**/
gboolean mongo_ssl_set_cert (mongo_ssl_ctx *ctx, const gchar *cert_path);

/** Sets client certificate file path
 * 
 * Retrieves a previously set client cert. file path defined within the given context.
 * @param ctx A valid pointer to a properly allocated and initialized mongo_ssl_ctx structure
 * @returns Client cert. path (string); NULL if not set
**/
gchar *mongo_ssl_get_cert (const mongo_ssl_ctx *ctx);

/** Sets CRL (Certificate Revocation List) file path
 *
 * If specified, the client performs CRL check against the server's certificate on the basis of the provided file.
 * The path can either point to a directory containing CRL files or a single CRL file. Only PEM format is supported.
 * The function stat()-s the given file before accessing it. 
 * @param ctx A valid pointer to a properly allocated and initialized mongo_ssl_ctx structure
 * @param crl_path Path to CRL file or directory (string)
 * @returns TRUE on success, FALSE on failure
**/
gboolean mongo_ssl_set_crl (mongo_ssl_ctx *ctx, const gchar *crl_path);

/** Gets CRL (Certificate Revocation List) file path
 * 
 * Retrieves a previously set CRL file path defined within the given context.
 * @param ctx A valid pointer to a properly allocated and initialized mongo_ssl_ctx structure
 * @returns CRL file path (string); NULL if not set
**/
gchar *mongo_ssl_get_crl (const mongo_ssl_ctx *ctx);

/** Sets client private key file
 *
 * The user must specify the client's private key. The key file must be PEM-formatted, although, may be encrypted.
 * When encrypted, the caller must pass the password. The function stat()-s the given file before accessing it.
 * @param ctx A valid pointer to a properly allocated and initialized mongo_ssl_ctx structure
 * @param key_path Path to private key file (string)
 * @param key_pw If given, the private key file is assumed to be encrypted, and the password is used to decrypt it. If it is NULL, the key file is assumed to be - consequently, treated as - plain text
 * @returns TRUE on success, FALSE on failure
**/
gboolean mongo_ssl_set_key (mongo_ssl_ctx *ctx, const gchar *key_path, const gchar *key_pw); 

/** Gets client private key file path
 *
 * Retrieves a previously set client private key file path defined within the given context.
 * @param ctx A valid pointer to a properly allocated and initialized mongo_ssl_ctx structure
 * @returns Private key file path (string); NULL if not set
**/
gchar *mongo_ssl_get_key (const mongo_ssl_ctx *ctx);

/** Sets list of accepted ciphers
 *
 * Set ciphers that the client should accept during the handshake process.
 * @param ctx A valid pointer to a properly allocated and initialized mongo_ssl_ctx structure
 * @param ciphers Cipher list specification
 * @returns TRUE on success, FALSE on failure
**/
gboolean mongo_ssl_set_ciphers (mongo_ssl_ctx *ctx, mongo_ssl_ciphers chipers);


/** Gets list of accepted ciphers
 *
 * Retrieves a previously set list of accepted ciphers defined within the given context.
 * @param ctx A valid pointer to a properly allocated and initialized mongo_ssl_ctx structure
 * @returns An enumeration representing the cipher set
**/
mongo_ssl_ciphers mongo_ssl_get_ciphers (const mongo_ssl_ctx* ctx);

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

/** Retrieves the last SSL-related error message 
 *
 * Gets the latest OpenSSL library error message
 * @param ctx A valid pointer to a properly allocated and initialized mongo_ssl_ctx structure
 * @returns An OpenSSL error string (should never be NULL)
**/
const gchar* mongo_ssl_get_last_error (const mongo_ssl_ctx *ctx);

/** Gets the result of the latest session verification process
 *
 * In the case of MONGO_SSL_V_ERR_PROTO, you may use mongo_ssl_get_last_error () to find out more about the
 * underlying SSL protocol error.
 * @param ctx A valid pointer to a properly allocated and initialized mongo_ssl_ctx structure
 * @returns A mongo_ssl_verify_result enum that indicates the verification result
**/
mongo_ssl_verify_result mongo_ssl_get_last_verify_result (const mongo_ssl_ctx *ctx);

/** Returns the description of the latest certificate verification error
 *
 * If no verification has been performed yet, X509_V_OK (=the operation was successful) is set by default
 * @param ctx A valid pointer to a properly allocated and initialized mongo_ssl_ctx structure
 * @returns OpenSSL X509_V_* error string
**/
const gchar *mongo_ssl_get_last_verify_error (const mongo_ssl_ctx *ctx);

/** Sets maximal depth of certificate chain verification
 *
 * @param ctx A valid pointer to a properly allocated and initialized mongo_ssl_ctx structure
 * @param depth Maximal verification depth
**/
void mongo_ssl_set_verify_depth (mongo_ssl_ctx *ctx, guint depth);

/** Gets the maximal depth of certificate chain verification
 * 
 * @param ctx A valid pointer to a properly allocated and initialized mongo_ssl_ctx structure
 * @returns Verification depth
**/
guint mongo_ssl_get_verify_depth (const mongo_ssl_ctx *ctx);

/** Sets security mode 
 *
 * Possible security mode combinations (ordered by strength):
 *  (<server certificate is...>-<presented certificate must be...>)
 *  required-trusted (TRUE, TRUE):     the server must present a valid certificate to start communication
 *  optional-trusted (FALSE, TRUE):    the server may present a certificate which gets validated (if that fails, the connection gets dropped)
 *  required-untrusted (TRUE, FALSE):  the server must present a certificate which does not get validated
 *  optional-untrusted (FALSE, FALSE): the server may present a certificate, but it is completely ignored anyway
 * Note, that default security level is (TRUE, TRUE).
 * @param ctx A valid pointer to a properly allocated and initialized mongo_ssl_ctx structure
 * @param required Semantics: TRUE = require a certificate from the server, FALSE = server certificate is optional
 * @param trusted Semantics: TRUE = the server certificate (if presented) gets validated, FALSE = the server certificate does not get validated
**/
void mongo_ssl_set_security (mongo_ssl_ctx *ctx, gboolean required, gboolean trusted);

/** Gets the previously set trust requirement
 *
 * The default value is TRUE.
 * @param ctx A valid pointer to a properly allocated and initialized mongo_ssl_ctx structure
 * @returns Trust requirement setting (TRUE/FALSE)
**/
gboolean mongo_ssl_is_trust_required (const mongo_ssl_ctx *ctx);

/** Gets the previously set server certification requirement
 *
 * @param ctx A valid pointer to a properly allocated and initialized mongo_ssl_ctx structure
 * @returns TRUE if the server must present a certificate according to the current setting, FALSE otherwise
**/
gboolean mongo_ssl_is_cert_required (const mongo_ssl_ctx *ctx);

/** Locks a mongo_ssl_ctx by calling g_static_mutex_lock ()
 *
 * The current thread blocks until it can acquire the lock.
 * @param ctx A valid pointer to a properly allocated and initialized mongo_ssl_ctx structure
**/
void mongo_ssl_lock (mongo_ssl_ctx *ctx);

/** Unlocks a mongo_ssl_ctx by calling g_static_mutex_unlock ()
 *
 *  @param ctx A valid pointer to a properly allocated and initialized mongo_ssl_ctx structure
**/
void mongo_ssl_unlock (mongo_ssl_ctx *ctx);

/** Gets the underlying SSL_CTX object wrapped by mongo_ssl_ctx so one can acess 
 * and manipulate it by using various OpenSSL functions.
 *
 * @returns The underlying SSL_CTX object
**/
SSL_CTX *mongo_ssl_get_context(const mongo_ssl_ctx *ctx);

G_END_DECLS

#endif


