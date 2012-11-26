/* sync-gridfs-chunk.c - libmongo-client GridFS chunk access implementation
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

/** @file src/sync-gridfs-chunk.c
 * MongoDB GridFS chunk access implementation.
 */

#include "sync-gridfs-chunk.h"
#include "libmongo-private.h"

#include <unistd.h>
#include <errno.h>

void
mongo_sync_gridfs_chunked_file_free (mongo_sync_gridfs_chunked_file *gfile)
{
  if (!gfile)
    {
      errno = ENOTCONN;
      return;
    }
  bson_free (gfile->meta.metadata);
  g_free (gfile);

  errno = 0;
}

mongo_sync_gridfs_chunked_file *
mongo_sync_gridfs_chunked_find (mongo_sync_gridfs *gfs, const bson *query)
{
  mongo_sync_gridfs_chunked_file *f;
  mongo_packet *p;
  bson_cursor *c;

  if (!gfs)
    {
      errno = ENOTCONN;
      return NULL;
    }
  if (!query)
    {
      errno = EINVAL;
      return NULL;
    }

  p = mongo_sync_cmd_query (gfs->conn, gfs->ns.files, 0, 0, 1, query, NULL);
  if (!p)
    return NULL;

  f = g_new0 (mongo_sync_gridfs_chunked_file, 1);
  f->gfs = gfs;
  f->meta.type = LMC_GRIDFS_FILE_CHUNKED;

  mongo_wire_reply_packet_get_nth_document (p, 1, &f->meta.metadata);
  bson_finish (f->meta.metadata);
  mongo_wire_packet_free (p);

  c = bson_find (f->meta.metadata, "_id");
  if (!bson_cursor_get_oid (c, &f->meta.oid))
    {
      mongo_sync_gridfs_chunked_file_free (f);
      bson_cursor_free (c);
      errno = EPROTO;
      return NULL;
    }

  bson_cursor_find (c, "length");
  bson_cursor_get_int64 (c, &f->meta.length);

  if (f->meta.length == 0)
    {
      gint32 i = 0;

      bson_cursor_get_int32 (c, &i);
      f->meta.length = i;
    }

  bson_cursor_find (c, "chunkSize");
  bson_cursor_get_int32 (c, &f->meta.chunk_size);

  if (f->meta.length == 0 || f->meta.chunk_size == 0)
    {
      bson_cursor_free (c);
      mongo_sync_gridfs_chunked_file_free (f);
      errno = EPROTO;
      return NULL;
    }

  bson_cursor_find (c, "uploadDate");
  if (!bson_cursor_get_utc_datetime (c, &f->meta.date))
    {
      mongo_sync_gridfs_chunked_file_free (f);
      bson_cursor_free (c);
      errno = EPROTO;
      return NULL;
    }

  bson_cursor_find (c, "md5");
  if (!bson_cursor_get_string (c, &f->meta.md5))
    {
      mongo_sync_gridfs_chunked_file_free (f);
      bson_cursor_free (c);
      errno = EPROTO;
      return NULL;
    }
  bson_cursor_free (c);

  return f;
}

mongo_sync_cursor *
mongo_sync_gridfs_chunked_file_cursor_new (mongo_sync_gridfs_chunked_file *gfile,
					   gint start, gint num)
{
  bson *q;
  mongo_sync_cursor *cursor;
  mongo_packet *p;

  if (!gfile)
    {
      errno = ENOTCONN;
      return NULL;
    }
  if (start < 0 || num < 0)
    {
      errno = EINVAL;
      return NULL;
    }

  q = bson_new_sized (32);
  bson_append_oid (q, "files_id", gfile->meta.oid);
  bson_finish (q);

  p = mongo_sync_cmd_query (gfile->gfs->conn, gfile->gfs->ns.chunks, 0,
			    start, num, q, NULL);
  cursor = mongo_sync_cursor_new (gfile->gfs->conn,
				  gfile->gfs->ns.chunks, p);
  bson_free (q);

  return cursor;
}

guint8 *
mongo_sync_gridfs_chunked_file_cursor_get_chunk (mongo_sync_cursor *cursor,
						 gint32 *size)
{
  bson *b;
  bson_cursor *c;
  const guint8 *d;
  guint8 *data;
  gint32 s;
  bson_binary_subtype sub = BSON_BINARY_SUBTYPE_USER_DEFINED;
  gboolean r;

  if (!cursor)
    {
      errno = ENOTCONN;
      return NULL;
    }

  b = mongo_sync_cursor_get_data (cursor);
  c = bson_find (b, "data");
  r = bson_cursor_get_binary (c, &sub, &d, &s);
  if (!r || (sub != BSON_BINARY_SUBTYPE_GENERIC &&
             sub != BSON_BINARY_SUBTYPE_BINARY))
    {
      bson_cursor_free (c);
      errno = EPROTO;
      return NULL;
    }
  bson_cursor_free (c);

  if (sub == BSON_BINARY_SUBTYPE_BINARY)
    {
      s -= 4;
      data = g_malloc (s);
      memcpy (data, d + 4, s);
    }
  else
    {
      data = g_malloc (s);
      memcpy (data, d, s);
    }

  if (size)
    *size = s;

  bson_free (b);
  return data;
}

mongo_sync_gridfs_chunked_file *
mongo_sync_gridfs_chunked_file_new_from_buffer (mongo_sync_gridfs *gfs,
						const bson *metadata,
						const guint8 *data,
						gint64 size)
{
  mongo_sync_gridfs_chunked_file *gfile;
  bson *meta;
  bson_cursor *c;
  guint8 *oid;
  gint64 pos = 0, chunk_n = 0, upload_date;
  GTimeVal tv;
  GChecksum *chk;

  if (!gfs)
    {
      errno = ENOTCONN;
      return NULL;
    }
  if (!data || size <= 0)
    {
      errno = EINVAL;
      return NULL;
    }

  oid = mongo_util_oid_new
    (mongo_connection_get_requestid ((mongo_connection *)gfs->conn));
  if (!oid)
    {
      errno = EFAULT;
      return NULL;
    }

  chk = g_checksum_new (G_CHECKSUM_MD5);

  /* Insert chunks first */
  while (pos < size)
    {
      bson *chunk;
      gint32 csize = gfs->chunk_size;

      if (size - pos < csize)
	csize = size - pos;

      chunk = bson_new_sized (gfs->chunk_size + 128);
      bson_append_oid (chunk, "files_id", oid);
      bson_append_int64 (chunk, "n", (gint64)chunk_n);
      bson_append_binary (chunk, "data", BSON_BINARY_SUBTYPE_GENERIC,
			  data + pos, csize);
      bson_finish (chunk);

      g_checksum_update (chk, data + pos, csize);

      if (!mongo_sync_cmd_insert (gfs->conn, gfs->ns.chunks, chunk, NULL))
	{
	  int e = errno;

	  bson_free (chunk);
	  g_free (oid);
	  errno = e;
	  return NULL;
	}
      bson_free (chunk);

      pos += csize;
      chunk_n++;
    }

  /* Insert metadata */
  if (metadata)
    meta = bson_new_from_data (bson_data (metadata),
			       bson_size (metadata) - 1);
  else
    meta = bson_new_sized (128);

  g_get_current_time (&tv);
  upload_date =  (((gint64) tv.tv_sec) * 1000) + (gint64)(tv.tv_usec / 1000);

  bson_append_int64 (meta, "length", size);
  bson_append_int32 (meta, "chunkSize", gfs->chunk_size);
  bson_append_utc_datetime (meta, "uploadDate", upload_date);
  bson_append_string (meta, "md5", g_checksum_get_string (chk), -1);
  bson_append_oid (meta, "_id", oid);
  bson_finish (meta);

  g_checksum_free (chk);

  if (!mongo_sync_cmd_insert (gfs->conn, gfs->ns.files, meta, NULL))
    {
      int e = errno;

      bson_free (meta);
      g_free (oid);
      errno = e;
      return NULL;
    }

  /* Return the resulting gfile.
   * No need to check cursor errors here, as we constructed the BSON
   * just above, and all the fields exist and have the appropriate
   * types.
   */
  gfile = g_new0 (mongo_sync_gridfs_chunked_file, 1);
  gfile->gfs = gfs;

  gfile->meta.metadata = meta;
  gfile->meta.length = size;
  gfile->meta.chunk_size = gfs->chunk_size;
  gfile->meta.date = 0;
  gfile->meta.type = LMC_GRIDFS_FILE_CHUNKED;

  c = bson_find (meta, "_id");
  bson_cursor_get_oid (c, &gfile->meta.oid);

  bson_cursor_find (c, "md5");
  bson_cursor_get_string (c, &gfile->meta.md5);
  bson_cursor_free (c);

  g_free (oid);

  return gfile;
}
