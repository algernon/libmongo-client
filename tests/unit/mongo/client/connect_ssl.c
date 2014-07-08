#include "test.h"
#include "tap.h"
#include "mongo-client.h"

#include <errno.h>

void
test_mongo_connect_ssl (void)
{
  mongo_connection *c;

  ok (mongo_ssl_connect (NULL, 27010, config.ssl_settings) == NULL,
      "mongo_connect() fails with a NULL host");
  ok (errno == EINVAL,
      "mongo_connect() should fail with EINVAL if host is NULL");

  begin_ssl_tests(3);

  ok (mongo_ssl_connect ("invalid.example.com", 27017, config.ssl_settings) == NULL,
      "Connecting to an invalid host fails");
  ok (mongo_ssl_connect ("example.com", 27017, config.ssl_settings) == NULL,
      "Connecting to an unavailable host/port fails");
  //ok (mongo_connect ("/does/not/exist.sock", MONGO_CONN_LOCAL) == NULL,
  //    "Connecting to an unavailable unix socket fails");

  ok ((c = mongo_ssl_connect (config.primary_host,
                          config.primary_port, config.ssl_settings)) != NULL,
      "Connecting to the primary server works");
  mongo_disconnect (c);
 
 end_ssl_tests ();
}

RUN_TEST (5, mongo_connect_ssl);
