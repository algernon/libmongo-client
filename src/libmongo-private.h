/* libmongo-private.h - private headers for libmongo-client
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

/** @file libmongo-private.h
 *
 * Private types and functions, for internal use in libmongo-client only.
 */

#ifndef LIBMONGO_PRIVATE_H
#define LIBMONGO_PRIVATE_H 1

#include "mongo.h"
#include "compat.h"

/** @internal BSON structure.
 */
struct _bson
{
  GByteArray *data; /**< The actual data of the BSON object. */
  gboolean finished; /**< Flag to indicate whether the object is open
                        or finished. */
};

/** @internal Mongo Connection state object. */
struct _mongo_connection
{
  gint fd; /**< The file descriptor associated with the connection. */
  gint32 request_id; /**< The last sent command's requestID. */
  mongo_ssl_conn *ssl; /**< SSL connection */
};

/** @internal Mongo Replica Set object. */
typedef struct _replica_set
{
  GList *seeds; /**< Replica set seeds, as a list of strings. */
  GList *hosts; /**< Replica set members, as a list of strings. */
  gchar *primary; /**< The replica master, if any. */
} replica_set;  /**< Replica Set properties. */

/** @internal MongoDb Authentication Credentials object.
 * These values are mlock()'ed.
 */
typedef struct _auth_credentials
{
  gchar *db; /**< The database to authenticate against. */
  gchar *user; /**< The username to authenticate with. */
  gchar *pw; /**< The password to authenticate with. */
} auth_credentials;

/** @internal Connection Recovery Cache for MongoDb. */
struct _mongo_sync_conn_recovery_cache
{
  replica_set rs;  /**< The replica set. */
  auth_credentials auth; /**< The authentication credentials.*/
};

/** @internal Synchronous connection object. */
struct _mongo_sync_connection
{
  mongo_connection super; /**< The parent object. */
  gboolean slaveok; /**< Whether queries against slave nodes are
                       acceptable. */
  gboolean safe_mode; /**< Safe-mode signal flag. */
  gboolean auto_reconnect; /**< Auto-reconnect flag. */

  gchar *last_error; /**< The last error from the server, caught
                        during queries. */
  gint32 max_insert_size; /**< Maximum number of bytes an insert
                             command can be before being split to
                             smaller chunks. Used for bulk inserts. */

  replica_set rs; /**< Replica set. */
  auth_credentials auth; /**< Authentication credentials. */

  mongo_sync_conn_recovery_cache *recovery_cache; /**< Reference to the externally managed recovery cache. */
};

/** @internal MongoDB cursor object.
 *
 * The cursor object can be used to conveniently iterate over a query
 * result set.
 */
struct _mongo_sync_cursor
{
  mongo_sync_connection *conn; /**< The connection associated with
                                  the cursor. Owned by the caller. */
  gchar *ns; /**< The namespace of the cursor. */
  mongo_packet *results; /**< The current result set, as a mongo
                            packet. */

  gint32 offset; /**< Offset of the cursor within the active result
                    set. */
  mongo_reply_packet_header ph; /**< The reply headers extracted from
                                   the active result set. */
};

/** @internal Synchronous pool connection object. */
struct _mongo_sync_pool_connection
{
  mongo_sync_connection super; /**< The parent object. */

  gint pool_id; /**< ID of the connection. */
  gboolean in_use; /**< Whether the object is in use or not. */
};

/** @internal GridFS object */
struct _mongo_sync_gridfs
{
  mongo_sync_connection *conn; /**< Connection the object is
                                  associated to. */

  struct
  {
    gchar *prefix; /**< The namespace prefix. */
    gchar *files; /**< The file metadata namespace. */
    gchar *chunks; /**< The chunk namespace. */

    gchar *db; /**< The database part of the namespace. */
  } ns; /**< Namespaces */

  gint32 chunk_size; /**< The default chunk size. */
};

/** @internal GridFS file types. */
typedef enum
{
  LMC_GRIDFS_FILE_CHUNKED, /**< Chunked file. */
  LMC_GRIDFS_FILE_STREAM_READER, /**< Streamed file, reader. */
  LMC_GRIDFS_FILE_STREAM_WRITER, /**< Streamed file, writer. */
} _mongo_gridfs_type;

/** @internal GridFS common file properties.
 *
 * This is shared between chunked and streamed files.
 */
typedef struct
{
  gint32 chunk_size; /**< Maximum chunk size for this file. */
  gint64 length; /**< Total length of the file. */

  union
  {
    /** Chunked file data. */
    struct
    {
      const guint8 *oid; /**< The file's ObjectID. */
      const gchar *md5; /**< MD5 sum of the file. */
      gint64 date; /**< The upload date. */
      bson *metadata; /**< Full file metadata, including user-set
                         keys. */
    };

    /** Streamed file data */
    struct
    {
      gint64 offset; /**< Offset we're into the file. */
      gint64 current_chunk; /**< The current chunk we're on. */
      guint8 *id; /**< A copy of the file's ObjectID. */
    };
  };

  _mongo_gridfs_type type; /**< The type of the GridFS file. */
} mongo_sync_gridfs_file_common;

/** @internal GridFS file object. */
struct _mongo_sync_gridfs_chunked_file
{
  mongo_sync_gridfs_file_common meta; /**< The file metadata. */
  mongo_sync_gridfs *gfs; /**< The GridFS the file is on. */
};

/** @internal GridFS file stream object. */
struct _mongo_sync_gridfs_stream
{
  mongo_sync_gridfs_file_common file; /**< Common file data. */
  mongo_sync_gridfs *gfs; /**< The GridFS the file is on. */

  /** Reader & Writer structure union.
   */
  union
  {
    /** Reader-specific data.
     */
    struct
    {
      bson *bson; /**< The current chunk as BSON. */

      /** Chunk state information.
       */
      struct
      {
        const guint8 *data; /**< The current chunk data, pointing
                               into ->reader.bson. */
        gint32 start_offset; /**< Offset to start reading data from,
                               needed to support the binary subtype. */
        gint32 size; /**< Size of the current chunk. */
        gint32 offset; /**< Offset we're into the chunk. */
      } chunk;
    } reader;

    /** Writer-specific data.
     */
    struct
    {
      bson *metadata; /**< Copy of the user-supplied metadata. */
      guint8 *buffer; /**< The current output buffer. */
      gint32 buffer_offset; /**< Offset into the output buffer. */

      GChecksum *checksum; /**< The running checksum of the output
                              file. */
    } writer;
  };
};

/** @internal Construct a kill cursors command, using a va_list.
 *
 * @param id is the sequence id.
 * @param n is the number of cursors to delete.
 * @param ap is the va_list of cursors to kill.
 *
 * @note One must supply exaclty @a n number of cursor IDs.
 *
 * @returns A newly allocated packet, or NULL on error. It is the
 * responsibility of the caller to free the packet once it is not used
 * anymore.
 */
mongo_packet *mongo_wire_cmd_kill_cursors_va (gint32 id, gint32 n,
                                              va_list ap);

/** @internal Get the header data of a packet, without conversion.
 *
 * Retrieve the mongo packet's header data, but do not convert the
 * values from little-endian. Use only when the source has the data in
 * the right byte order already.
 *
 * @param p is the packet which header we seek.
 * @param header is a pointer to a variable which will hold the data.
 *
 * @note Allocating the @a header is the responsibility of the caller.
 *
 * @returns TRUE on success, FALSE otherwise.
 */
gboolean
mongo_wire_packet_get_header_raw (const mongo_packet *p,
                                  mongo_packet_header *header);

/** @internal Set the header data of a packet, without conversion.
 *
 * Override the mongo packet's header data, but do not convert the
 * values from little-endian. Use only when the source has the data in
 * the right byte order already.
 *
 * @note No sanity checks are done, use this function with great care.
 *
 * @param p is the packet whose header we want to override.
 * @param header is the header structure to use.
 *
 * @returns TRUE on success, FALSE otherwise.
 */
gboolean
mongo_wire_packet_set_header_raw (mongo_packet *p,
                                  const mongo_packet_header *header);

#endif
