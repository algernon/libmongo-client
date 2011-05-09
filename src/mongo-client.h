/* mongo-client.h - libmongo-client user API
 * Copyright 2011 Gergely Nagy <algernon@balabit.hu>
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

#ifndef LIBMONGO_CLIENT_H
#define LIBMONGO_CLIENT_H 1

#include <bson.h>
#include <mongo-wire.h>

#include <glib.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @defgroup mongo_client Mongo Client
 *
 * @addtogroup mongo_client
 * @{
 */

/** Opaque MongoDB connection object type. */
typedef struct _mongo_connection mongo_connection;

/** Connect to a MongoDB server.
 *
 * Connects to a single MongoDB server.
 *
 * @param host is the IP address of the server.
 * @param port is the port to connect to.
 *
 * @returns A newly allocated mongo_connection object or NULL on
 * error. It is the responsibility of the caller to free it once it is
 * not used anymore.
 */
mongo_connection *mongo_connect (const char *host, int port);

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

/** @} */

#ifdef __cplusplus
}
#endif

#endif
