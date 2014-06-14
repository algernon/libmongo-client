#include "test.h"
#include "mongo.h"

#include <errno.h>
#include <sys/socket.h>

#include "libmongo-private.h"

void
test_mongo_packet_recv_ssl (void)
{
  mongo_connection c, *conn;
  mongo_packet *p;
  bson *b;

  c.fd = -1;

  ok (mongo_packet_recv (NULL) == NULL,
      "mongo_packet_recv() fails with a NULL connection");
  ok (errno == ENOTCONN,
      "mongo_packet_recv() sets errno to ENOTCONN if connection is NULL");

  ok (mongo_packet_recv (&c) == NULL,
      "mongo_packet_recv() fails if the FD is less than zero");
  ok (errno == EBADF,
      "mongo_packet_recv() sets errno to EBADF is the FD is bad");

  begin_ssl_tests (2);

  b = bson_new ();
  bson_append_int32 (b, "getnonce", 1);
  bson_finish (b);

  p = mongo_wire_cmd_custom (42, config.db, 0, b);
  bson_free (b);

  conn = mongo_ssl_connect (config.primary_host, config.primary_port, config.ssl_settings);
  mongo_packet_send (conn, p);
  mongo_wire_packet_free (p);

  ok ((p = mongo_packet_recv (conn)) != NULL,
      "mongo_packet_recv() works");
  mongo_wire_packet_free (p);

  close (conn->fd);
  sleep (3);

  ok (mongo_packet_recv (conn) == NULL,
      "mongo_packet_recv() fails on a closed socket");

  mongo_disconnect (conn);

  end_ssl_tests ();
}

RUN_TEST (6, mongo_packet_recv_ssl);
