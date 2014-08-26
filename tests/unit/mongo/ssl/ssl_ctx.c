#include "test.h"
#include "tap.h"
#include "mongo-client.h"
#include "mongo-sync.h"
#include "mongo-ssl.h"

#include <errno.h>

void test_mongo_ssl_ctx (void)
{
  mongo_ssl_ctx *ssl_context = mongo_ssl_ctx_new ();
  GList *dummy_list = NULL;

  dummy_list = g_list_append (dummy_list, "eggs");
  dummy_list = g_list_append (dummy_list, "milk");
  dummy_list = g_list_append (dummy_list, "butter");
  dummy_list = g_list_append (dummy_list, "Captain America");

  ok (mongo_ssl_init (ssl_context) &&
      !mongo_ssl_init (NULL) &&
      errno == EINVAL,
      "mongo_ssl_init works");

  ok (mongo_ssl_get_context (ssl_context) &&
      !mongo_ssl_get_context (NULL),
      "mongo_ssl_get_context works");

  ok (!mongo_ssl_set_auto_retry (NULL, FALSE) &&
      mongo_ssl_set_auto_retry (ssl_context, TRUE),
      "mongo_ssl_set_auto_retry works");

  ok (
    !mongo_ssl_set_ca (NULL, NULL) &&
    !mongo_ssl_set_ca (ssl_context, NULL) &&
    !mongo_ssl_set_ca (NULL, "whatever") &&
    (!mongo_ssl_set_ca (ssl_context, "/no/such/file") && errno == ENOENT) &&
    mongo_ssl_set_ca (ssl_context, "./ssl/3party/ca.pem"),
    "mongo_ssl_set_ca works");

  ok (
    !strcmp(mongo_ssl_get_ca (ssl_context), "./ssl/3party/ca.pem"),
    "mongo_ssl_get_ca works");

 ok (
    !mongo_ssl_set_cert (NULL, NULL) &&
    !mongo_ssl_set_cert (ssl_context, NULL) &&
    !mongo_ssl_set_cert (NULL, "whatever") &&
    (!mongo_ssl_set_cert (ssl_context, "/no/such/file") && errno == ENOENT) &&
    mongo_ssl_set_cert (ssl_context, "./ssl/3party/client.pem"),
    "mongo_ssl_set_cert works");

  ok (
    !strcmp(mongo_ssl_get_cert (ssl_context), "./ssl/3party/client.pem"),
    "mongo_ssl_get_cert works");

 ok (
    !mongo_ssl_set_crl (NULL, NULL) &&
    mongo_ssl_set_crl (ssl_context, NULL) && /* CRL path can be set to NULL */
    !mongo_ssl_set_crl (NULL, "whatever") &&
    (!mongo_ssl_set_crl (ssl_context, "/no/such/file") && errno == ENOENT) &&
    mongo_ssl_set_crl (ssl_context, "./ssl/3party/ca_crl.pem"),
    "mongo_ssl_set_crl works");

  ok (
    !strcmp(mongo_ssl_get_crl (ssl_context), "./ssl/3party/ca_crl.pem"),
    "mongo_ssl_get_crl works");

  ok (
    !mongo_ssl_set_key (NULL, NULL, NULL) &&
    !mongo_ssl_set_key (ssl_context, NULL, NULL) &&
    !mongo_ssl_set_key (NULL, "whatever", NULL) &&
    (!mongo_ssl_set_key (ssl_context, "/no/such/file", NULL) && errno == ENOENT) &&
    mongo_ssl_set_key (ssl_context, "./ssl/3party/client.key", NULL),
    "mongo_ssl_set_key works");

  ok (
    !strcmp(mongo_ssl_get_key (ssl_context), "./ssl/3party/client.key"),
    "mongo_ssl_get_key works");

  ok (
    !mongo_ssl_set_ciphers (NULL, 127) &&
    mongo_ssl_set_ciphers (ssl_context, MONGO_SSL_CIPHERS_AES),
    "mongo_ssl_set_ciphers works");

  ok (
    mongo_ssl_get_ciphers (ssl_context) == MONGO_SSL_CIPHERS_AES,
    "mongo_ssl_get_ciphers works");

  mongo_ssl_set_verify_depth (ssl_context, 3);

  ok (
    mongo_ssl_get_verify_depth (ssl_context) == 3,
    "mongo_ssl_set/get_verify_depth works");

  mongo_ssl_set_security (ssl_context, FALSE, TRUE);

  ok (mongo_ssl_is_trust_required (ssl_context) &&
      !mongo_ssl_is_cert_required (ssl_context),
      "mongo_ssl_set_security works");

  ok (!mongo_ssl_is_trust_required (NULL),
      "mongo_ssl_is_trust_required works");

  ok (!mongo_ssl_is_cert_required (NULL),
      "mongo_ssl_is_cert_required works");

  mongo_ssl_set_trusted_DNs (ssl_context, dummy_list);


  ok (mongo_ssl_get_trusted_DNs (ssl_context) == dummy_list,
      "mongo_ssl_set_trusted_DNs works");

  dummy_list = g_list_remove (dummy_list, g_list_nth_data (dummy_list, 0));

  mongo_ssl_set_trusted_fingerprints (ssl_context, dummy_list);

  ok (mongo_ssl_get_trusted_fingerprints (ssl_context) == dummy_list,
      "mongo_ssl_set_trusted_fingerprints works");

  ok (!mongo_ssl_get_trusted_DNs (NULL),
      "mongo_ssl_get_trusted_DNs works");

  ok (!mongo_ssl_get_trusted_fingerprints (NULL),
      "mongo_ssl_get_trusted_fingerprints works");

  mongo_ssl_clear (ssl_context);
  g_free (ssl_context);
  g_list_free (dummy_list);
}

RUN_TEST (21, mongo_ssl_ctx);
