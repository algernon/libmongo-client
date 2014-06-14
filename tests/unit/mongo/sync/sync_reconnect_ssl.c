#include "test.h"
#include "mongo.h"

#include <errno.h>
#include <sys/socket.h>
#include "libmongo-private.h"

void
test_mongo_sync_reconnect_ssl (void)
{
  mongo_sync_connection *conn, *o;
  GList *l;

  ok (mongo_sync_reconnect (NULL, FALSE) == NULL,
      "mongo_sync_reconnect() fails with a NULL connection");
  cmp_ok (errno, "==", ENOTCONN,
          "errno is ENOTCONN");

  conn = test_make_fake_sync_conn (-1, FALSE);
  ok (mongo_sync_reconnect (conn, FALSE) == NULL,
      "mongo_sync_reconnect() fails with a bogus FD");
  cmp_ok (errno, "==", EHOSTUNREACH,
          "errno is EHOSTUNREACH");

  mongo_sync_disconnect (conn);

  begin_ssl_tests (15);

  /* Connect & reconnect to master */
  o = conn = mongo_sync_ssl_connect (config.primary_host,
                                 config.primary_port, TRUE, config.ssl_settings);
  ok ((conn = mongo_sync_reconnect (conn, TRUE)) != NULL,
      "mongo_sync_reconnect() works when reconnecting to self");
  ok (o == conn,
      "Reconnect to an existing master results in the same object");
  mongo_sync_disconnect (conn);
  
  /* Connect to master, kill FD, reconnect */
  conn = mongo_sync_ssl_connect (config.primary_host,
                             config.primary_port, TRUE, config.ssl_settings);
  mongo_sync_cmd_is_master (conn);
  shutdown (conn->super.fd, SHUT_RDWR);
  sleep (3);
  ok ((conn = mongo_sync_reconnect (conn, TRUE)) != NULL,
       "mongo_sync_reconnect() succeed when the connection drops");
  mongo_sync_disconnect (conn);

  /* Connect, kill, reconnect; w/o knowing other hosts */
  o = conn = mongo_sync_ssl_connect (config.primary_host,
                                 config.primary_port, TRUE, config.ssl_settings);
  shutdown (conn->super.fd, SHUT_RDWR);
  sleep (3);
  l = conn->rs.hosts;
  while (l)
    {
      g_free (l->data);
      l = g_list_delete_link (l, l);
    }
  conn->rs.hosts = NULL;

  l = conn->rs.seeds;
  while (l)
    {
      g_free (l->data);
      l = g_list_delete_link (l, l);
    }
  conn->rs.seeds = NULL;

  conn = mongo_sync_reconnect (conn, FALSE);

  ok (conn != o && conn == NULL,
      "mongo_sync_reconnect() fails if it can't reconnect anywhere");
  mongo_sync_disconnect (o);
  
  /* Gracefully ignore unparsable hosts during reconnect */
  
  o = conn = mongo_sync_ssl_connect (config.primary_host,
                                 config.primary_port, TRUE, config.ssl_settings);
  mongo_sync_cmd_is_master (conn);
  conn->rs.hosts = g_list_prepend (conn->rs.hosts,
                                   g_strdup ("invalid:-42"));
  shutdown (conn->super.fd, SHUT_RDWR);
  sleep (3);
  conn = mongo_sync_reconnect (conn, TRUE);

  ok (conn == o,
      "mongo_sync_reconnect() gracefully ignores unparsable hosts "
      "during reconnect");
  mongo_sync_disconnect (conn);
  
  /* Ignore unreachable hosts during reconnect */
  
  o = conn = mongo_sync_ssl_connect (config.primary_host,
                                 config.primary_port, TRUE, config.ssl_settings);
  mongo_sync_cmd_is_master (conn);
  conn->rs.hosts = g_list_prepend (conn->rs.hosts,
                                   g_strdup ("example.com:27017"));
  shutdown (conn->super.fd, SHUT_RDWR);
  sleep (3);
  conn = mongo_sync_reconnect (conn, TRUE);

  ok (conn == o,
      "mongo_sync_reconnect() gracefully ignores unparsable hosts "
      "during reconnect");
  mongo_sync_disconnect (conn);
  
  /*
   * Tests involving a secondary
   */
  
  skip (!config.secondary_host, 9,
        "Secondary host not set up");
  
  /* Connect to secondary & reconnect to master */
  o = conn = mongo_sync_ssl_connect (config.secondary_host,
                                 config.secondary_port, TRUE, config.ssl_settings);
  ok (conn != NULL, "Connecting to secondary");
  ok (mongo_sync_cmd_is_master (conn) == FALSE,
      "Connected to a secondary");
  ok ((conn = mongo_sync_reconnect (conn, TRUE)) != NULL,
      "Reconnecting from slave to master succeeds");
  ok (conn == o, "Connection object updated in-place");
  ok (mongo_sync_cmd_is_master (conn),
      "Correctly reconnected to master");
  mongo_sync_disconnect (conn);
  
  /* Connect to secondary & reconnect to self */
  
  o = conn = mongo_sync_ssl_connect (config.secondary_host,
                                 config.secondary_port, TRUE, config.ssl_settings);
  ok (conn != NULL, "Connecting to secondary");
  ok ((conn = mongo_sync_reconnect (conn, FALSE)) != NULL,
      "Reconnecting from slave to self succeeds");
  ok (conn == o, "Connection object updated in-place");
  ok (mongo_sync_cmd_is_master (conn) == FALSE,
      "Correctly reconnected to self");
  mongo_sync_disconnect (conn);

  endskip;
  
  end_ssl_tests ();
}

RUN_TEST (19, mongo_sync_reconnect_ssl);
