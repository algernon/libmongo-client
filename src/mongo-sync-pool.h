/* mongo-sync-pool.h - libmongo-client connection pool API
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

/** @file src/mongo-sync-pool.h
 * MongoDB connection pool API public header.
 *
 * @addtogroup mongo_sync
 * @{
 */

#ifndef LIBMONGO_POOL_H
#define LIBMONGO_POOL_H 1

#include <mongo-sync.h>
#include <glib.h>

G_BEGIN_DECLS

/** @defgroup mongo_sync_pool_api Mongo Sync Pool API
 *
 * These commands implement connection pooling over the mongo_sync
 * family of commands.
 *
 * Once a pool is set up, one can pick and return connections at one's
 * leisure. Picking is done in a round-robin fashion (excluding
 * connections that have been picked but not returned yet).
 *
 * @addtogroup mongo_sync_pool_api
 * @{
 */

/** Opaque synchronous connection pool object.
 *
 * This represents a single connection within the pool.
 */
typedef struct _mongo_sync_pool_connection mongo_sync_pool_connection;

/** Opaque synchronous pool object.
 *
 * This is the entire connection pool, with all its meta-data.
 */
typedef struct _mongo_sync_pool mongo_sync_pool;

/** Create a new synchronous connection pool.
 *
 * Sets up a connection pool towards a given MongoDB server, and all
 * its secondaries (if any).
 *
 * @param host is the address of the server.
 * @param port is the port to connect to.
 * @param nmasters is the number of connections to make towards the
 * master.
 * @param nslaves is the number of connections to make towards the
 * secondaries.
 *
 * @note Either @a nmasters or @a nslaves can be zero, but not both at
 * the same time.
 *
 * @note The @a host MUST be a master, otherwise the function will
 * return an error.
 *
 * @returns A newly allocated mongo_sync_pool object, or NULL on
 * error. It is the responsibility of the caller to close and free the
 * pool when appropriate.
 */
mongo_sync_pool *mongo_sync_pool_new (const gchar *host,
                                      gint port,
                                      gint nmasters, gint nslaves);


/** Create a new synchronous connection pool.
 *
 * Sets up a connection pool towards a given MongoDB server, and all
 * its secondaries (if any).
 *
 * @param host is the address of the server.
 * @param port is the port to connect to.
 * @param nmasters is the number of connections to make towards the
 * master.
 * @param nslaves is the number of connections to make towards the
 * secondaries.
 * @param ssl_config Mongo SSL configuration & context (leave it NULL if not using SSL)
 *
 * @note Either @a nmasters or @a nslaves can be zero, but not both at
 * the same time.
 *
 * @note The @a host MUST be a master, otherwise the function will
 * return an error.
 *
 * @returns A newly allocated mongo_sync_pool object, or NULL on
 * error. It is the responsibility of the caller to close and free the
 * pool when appropriate.
 */
mongo_sync_pool *mongo_sync_pool_new_ssl (const gchar *host,
                                      gint port,
                                      gint nmasters, gint nslaves, 
                                      mongo_ssl_ctx *ssl_config);

/** Close and free a synchronous connection pool.
 *
 * @param pool is the pool to shut down.
 *
 * @note The object will be freed, and shall not be used afterwards!
 */
void mongo_sync_pool_free (mongo_sync_pool *pool);

/** Pick a connection from a synchronous connection pool.
 *
 * Based on given preferences, selects a free connection object from
 * the pool, and returns it.
 *
 * @param pool is the pool to select from.
 * @param want_master flags whether the caller wants a master connection,
 * or secondaries are acceptable too.
 *
 * @note For write operations, always select a master!
 *
 * @returns A connection object from the pool.
 *
 * @note The returned object can be safely casted to
 * mongo_sync_connection, and passed to any of the mongo_sync family
 * of commands. Do note however, that one shall not close or otherwise
 * free a connection object returned by this function.
 */
mongo_sync_pool_connection *mongo_sync_pool_pick (mongo_sync_pool *pool,
                                                  gboolean want_master);

/** Return a connection to the synchronous connection pool.
 *
 * Once one is not using a connection anymore, it should be returned
 * to the pool using this function.
 *
 * @param pool is the pool to return to.
 * @param conn is the connection to return.
 *
 * @returns TRUE on success, FALSE otherwise.
 *
 * @note The returned connection should not be used afterwards.
 */
gboolean mongo_sync_pool_return (mongo_sync_pool *pool,
                                 mongo_sync_pool_connection *conn);

/** @} */

/** @} */

G_END_DECLS

#endif
