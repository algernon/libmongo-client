/* mongo-client.h - libmongo-client user API
 * Copyright 2011, 2012 Gergely Nagy <algernon@balabit.hu>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/** @file src/mongo-client.h
 * MongoDB client API public header.
 */

#ifndef LIBMONGO_CLIENT_H
#define LIBMONGO_CLIENT_H 1

#include <bson.h>
#include <mongo-wire.h>
#include <mongo-ssl.h>

#include <glib.h>

G_BEGIN_DECLS

/** @defgroup mongo_client Mongo Client
 *
 * @addtogroup mongo_client
 * @{
 */

/** Opaque MongoDB connection object type. */
typedef struct _mongo_connection mongo_connection;

/** Constant to signal that a connection is local (unix socket).
 *
 * When passed to mongo_connect() or mongo_sync_connect() as the port
 * parameter, it signals that the address is to be interpreted as a
 * unix socket path, not a hostname or IP.
 */
#define MONGO_CONN_LOCAL -1

/** Connect to a MongoDB server.
 *
 * Connects to a single MongoDB server.
 *
 * @param address is the address of the server (IP or unix socket path).
 * @param port is the port to connect to, or #MONGO_CONN_LOCAL if
 * address is a unix socket.
 *
 * @returns A newly allocated mongo_connection object or NULL on
 * error. It is the responsibility of the caller to free it once it is
 * not used anymore.
 */
mongo_connection *mongo_connect (const char *address, int port);

/** Connect to MongoDB server via SSL.
 *
 * Connects to a single MongoDB server via an SSL-enabled secure connection.
 *
 * @param address is the address of the server (IP or hostname)
 * @param port is the port to connect to
 * @param conf stores SSL configuration and context
 *
 * @returns A newly allocated mongo_connection object or NULL on
 * error. It is the responsibility of the caller to free it once it is
 * not used anymore.
 */
mongo_connection *mongo_ssl_connect (const char *address, int port, mongo_ssl_ctx *conf); 

/** Disconnect from a MongoDB server.
 *
 * @param conn is the connection object to disconnect from.
 *
 * @note This also frees up the object.
 */
void mongo_disconnect (mongo_connection *conn);

/** Sends an assembled command packet to MongoDB.
 *
 * @param conn is the connection to use for sending.
 * @param p is the packet to send.
 *
 * @returns TRUE on success, when the whole packet was sent, FALSE
 * otherwise.
 */
gboolean mongo_packet_send (mongo_connection *conn, const mongo_packet *p);

/** Receive a packet from MongoDB.
 *
 * @param conn is the connection to use for receiving.
 *
 * @returns A response packet, or NULL upon error.
 */
mongo_packet *mongo_packet_recv (mongo_connection *conn);

/** Get the last requestID from a connection object.
 *
 * @param conn is the connection to get the requestID from.
 *
 * @returns The last requestID used, or -1 on error.
 */
gint32 mongo_connection_get_requestid (const mongo_connection *conn);

/** Set a timeout for read/write operations on a connection
 *
 * On systems that support it, set a timeout for read/write operations
 * on a socket.
 *
 * @param conn is the connection to set a timeout on.
 * @param timeout is the timeout to set, in milliseconds.
 *
 * @returns TRUE on success, FALSE otherwise.
 *
 * @note The timeout is not preserved accross reconnects, if using the
 * Sync API, however. It only applies to the active connection, and
 * nothing else.
 */
gboolean mongo_connection_set_timeout (mongo_connection *conn, gint timeout);

/** @} */

G_END_DECLS

#endif
