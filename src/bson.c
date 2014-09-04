/* bson.c - libmongo-client's BSON implementation
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

/** @file src/bson.c
 * Implementation of the BSON API.
 */

#include <glib.h>
#include <errno.h>
#include <string.h>
#include <stdarg.h>

#include "bson.h"
#include "libmongo-macros.h"
#include "libmongo-private.h"

/** @internal BSON cursor structure.
 */
struct _bson_cursor
{
  const bson *obj; /**< The BSON object this is a cursor for. */
  const gchar *key; /**< Pointer within the BSON object to the
                       current key. */
  size_t pos; /**< Position within the BSON object, pointing at the
                 element type. */
  size_t value_pos; /**< The start of the value within the BSON
                       object, pointing right after the end of the
                       key. */
};

/** @internal Append a byte to a BSON stream.
 *
 * @param b is the BSON stream to append to.
 * @param byte is the byte to append.
 */
static inline void
_bson_append_byte (bson *b, const guint8 byte)
{
  b->data = g_byte_array_append (b->data, &byte, sizeof (byte));
}

/** @internal Append a 32-bit integer to a BSON stream.
 *
 * @param b is the BSON stream to append to.
 * @param i is the integer to append.
 */
static inline void
_bson_append_int32 (bson *b, const gint32 i)
{
  b->data = g_byte_array_append (b->data, (const guint8 *)&i, sizeof (gint32));
}

/** @internal Append a 64-bit integer to a BSON stream.
 *
 * @param b is the BSON stream to append to.
 * @param i is the integer to append.
 */
static inline void
_bson_append_int64 (bson *b, const gint64 i)
{
  b->data = g_byte_array_append (b->data, (const guint8 *)&i, sizeof (gint64));
}

/** @internal Append an element header to a BSON stream.
 *
 * The element header is a single byte, signaling the type of the
 * element, followed by a NULL-terminated C string: the key (element)
 * name.
 *
 * @param b is the BSON object to append to.
 * @param type is the element type to append.
 * @param name is the key name.
 *
 * @returns TRUE on success, FALSE otherwise.
 */
static inline gboolean
_bson_append_element_header (bson *b, bson_type type, const gchar *name)
{
  if (!name || !b)
    return FALSE;

  if (b->finished)
    return FALSE;

  _bson_append_byte (b, (guint8) type);
  b->data = g_byte_array_append (b->data, (const guint8 *)name,
                                 strlen (name) + 1);

  return TRUE;
}

/** @internal Append a string-like element to a BSON object.
 *
 * There are a few string-like elements in the BSON spec that differ
 * only in type, not in structure. This convenience function is used
 * to append them with the appropriate type.
 *
 * @param b is the BSON object to append to.
 * @param type is the string-like type to append.
 * @param name is the key name.
 * @param val is the value to append.
 * @param length is the length of the value.
 *
 * @note Passing @a -1 as length will use the full length of @a
 * val.
 *
 * @returns TRUE on success, FALSE otherwise.
 */
static gboolean
_bson_append_string_element (bson *b, bson_type type, const gchar *name,
                             const gchar *val, gint32 length)
{
  size_t len;

  if (!val || !length || length < -1)
    return FALSE;

  len = (length != -1) ? (size_t)length + 1: strlen (val) + 1;

  if (!_bson_append_element_header (b, type, name))
    return FALSE;

  _bson_append_int32 (b, GINT32_TO_LE (len));

  b->data = g_byte_array_append (b->data, (const guint8 *)val, len - 1);
  _bson_append_byte (b, 0);

  return TRUE;
}

/** @internal Append a document-like element to a BSON object.
 *
 * Arrays and documents are both similar, and differ very little:
 * different type, and arrays have restrictions on key names (which
 * are not enforced by this library).
 *
 * This convenience function can append both types.
 *
 * @param b is the BSON object to append to.
 * @param type is the document-like type to append.
 * @param name is the key name.
 * @param doc is the document-like object to append.
 *
 * @note The @a doc must be a finished BSON object.
 *
 * @returns TRUE on success, FALSE otherwise.
 */
static gboolean
_bson_append_document_element (bson *b, bson_type type, const gchar *name,
                               const bson *doc)
{
  if (bson_size (doc) < 0)
    return FALSE;

  if (!_bson_append_element_header (b, type, name))
    return FALSE;

  b->data = g_byte_array_append (b->data, bson_data (doc), bson_size (doc));
  return TRUE;
}

/** @internal Append a 64-bit integer to a BSON object.
 *
 * @param b is the BSON object to append to.
 * @param type is the int64-like type to append.
 * @param name is the key name.
 * @param i is the 64-bit value to append.
 *
 * @returns TRUE on success, FALSE otherwise.
 */
static inline gboolean
_bson_append_int64_element (bson *b, bson_type type, const gchar *name,
                            gint64 i)
{
  if (!_bson_append_element_header (b, type, name))
    return FALSE;

  _bson_append_int64 (b, GINT64_TO_LE (i));
  return TRUE;
}

/********************
 * Public interface *
 ********************/

const gchar *
bson_type_as_string (bson_type type)
{
  switch (type)
    {
    case BSON_TYPE_NONE:
      return "BSON_TYPE_NONE";
    case BSON_TYPE_DOUBLE:
      return "BSON_TYPE_DOUBLE";
    case BSON_TYPE_STRING:
      return "BSON_TYPE_STRING";
    case BSON_TYPE_DOCUMENT:
      return "BSON_TYPE_DOCUMENT";
    case BSON_TYPE_ARRAY:
      return "BSON_TYPE_ARRAY";
    case BSON_TYPE_BINARY:
      return "BSON_TYPE_BINARY";
    case BSON_TYPE_UNDEFINED:
      return "BSON_TYPE_UNDEFINED";
    case BSON_TYPE_OID:
      return "BSON_TYPE_OID";
    case BSON_TYPE_BOOLEAN:
      return "BSON_TYPE_BOOLEAN";
    case BSON_TYPE_UTC_DATETIME:
      return "BSON_TYPE_UTC_DATETIME";
    case BSON_TYPE_NULL:
      return "BSON_TYPE_NULL";
    case BSON_TYPE_REGEXP:
      return "BSON_TYPE_REGEXP";
    case BSON_TYPE_DBPOINTER:
      return "BSON_TYPE_DBPOINTER";
    case BSON_TYPE_JS_CODE:
      return "BSON_TYPE_JS_CODE";
    case BSON_TYPE_SYMBOL:
      return "BSON_TYPE_SYMBOL";
    case BSON_TYPE_JS_CODE_W_SCOPE:
      return "BSON_TYPE_JS_CODE_W_SCOPE";
    case BSON_TYPE_INT32:
      return "BSON_TYPE_INT32";
    case BSON_TYPE_TIMESTAMP:
      return "BSON_TYPE_TIMESTAMP";
    case BSON_TYPE_INT64:
      return "BSON_TYPE_INT64";
    case BSON_TYPE_MIN:
      return "BSON_TYPE_MIN";
    case BSON_TYPE_MAX:
      return "BSON_TYPE_MAX";
    default:
      return NULL;
  }
}

bson *
bson_new (void)
{
  return bson_new_sized (0);
}

bson *
bson_new_sized (gint32 size)
{
  bson *b = g_new0 (bson, 1);

  b->data = g_byte_array_sized_new (size + sizeof (gint32) + sizeof (guint8));
  _bson_append_int32 (b, 0);

  return b;
}

bson *
bson_new_from_data (const guint8 *data, gint32 size)
{
  bson *b;

  if (!data || size <= 0 || size > MAX_DATA_LEN)
    return NULL;

  b = g_new0 (bson, 1);
  b->data = g_byte_array_sized_new (size + sizeof (guint8));
  b->data = g_byte_array_append (b->data, data, size);

  return b;
}

/** @internal Add a single element of any type to a BSON object.
 *
 * Used internally by bson_build() and bson_build_full(), this
 * function adds a single element of any supported type to the target
 * BSON object.
 *
 * @param b is the target BSON object.
 * @param type is the element type to add.
 * @param name is the key name.
 * @param free_after signals whether to free the values after adding
 * them.
 * @param ap is the list of remaining parameters.
 *
 * @returns TRUE in @a single_result on success, FALSE otherwise.
 */
#define _bson_build_add_single(b,type,name,free_after,ap)		\
  {									\
    single_result = TRUE;						\
    switch (type)							\
      {									\
      case BSON_TYPE_NONE:						\
      case BSON_TYPE_UNDEFINED:						\
      case BSON_TYPE_DBPOINTER:						\
        single_result = FALSE;						\
        break;								\
      case BSON_TYPE_MIN:						\
      case BSON_TYPE_MAX:						\
      default:								\
        single_result = FALSE;						\
        break;								\
      case BSON_TYPE_DOUBLE:						\
        {								\
          gdouble d = (gdouble)va_arg (ap, gdouble);			\
          bson_append_double (b, name, d);				\
          break;							\
        }								\
      case BSON_TYPE_STRING:						\
        {								\
          gchar *s = (gchar *)va_arg (ap, gpointer);			\
          gint32 l = (gint32)va_arg (ap, gint32);			\
          bson_append_string (b, name, s, l);				\
          if (free_after)						\
            g_free (s);							\
          break;							\
        }								\
      case BSON_TYPE_DOCUMENT:						\
        {								\
          bson *d = (bson *)va_arg (ap, gpointer);			\
          if (free_after && bson_size (d) < 0)				\
            bson_finish (d);						\
          bson_append_document (b, name, d);				\
          if (free_after)						\
            bson_free (d);						\
          break;							\
        }								\
      case BSON_TYPE_ARRAY:						\
        {								\
          bson *d = (bson *)va_arg (ap, gpointer);			\
          if (free_after && bson_size (d) < 0)				\
            bson_finish (d);						\
          bson_append_array (b, name, d);				\
          if (free_after)						\
            bson_free (d);						\
          break;							\
        }								\
      case BSON_TYPE_BINARY:						\
        {								\
          bson_binary_subtype s =					\
            (bson_binary_subtype)va_arg (ap, guint);			\
          guint8 *d = (guint8 *)va_arg (ap, gpointer);			\
          gint32 l = (gint32)va_arg (ap, gint32);			\
          bson_append_binary (b, name, s, d, l);			\
          if (free_after)						\
            g_free (d);							\
          break;							\
        }								\
      case BSON_TYPE_OID:						\
        {								\
          guint8 *oid = (guint8 *)va_arg (ap, gpointer);		\
          bson_append_oid (b, name, oid);				\
          if (free_after)						\
            g_free (oid);						\
          break;							\
        }								\
      case BSON_TYPE_BOOLEAN:						\
        {								\
          gboolean v = (gboolean)va_arg (ap, guint);			\
          bson_append_boolean (b, name, v);				\
          break;							\
        }								\
      case BSON_TYPE_UTC_DATETIME:					\
        {								\
          gint64 ts = (gint64)va_arg (ap, gint64);			\
          bson_append_utc_datetime (b, name, ts);			\
          break;							\
        }								\
      case BSON_TYPE_NULL:						\
        {								\
          bson_append_null (b, name);					\
          break;							\
        }								\
      case BSON_TYPE_REGEXP:						\
        {								\
          gchar *r = (gchar *)va_arg (ap, gpointer);			\
          gchar *o = (gchar *)va_arg (ap, gpointer);			\
          bson_append_regex (b, name, r, o);				\
          if (free_after)						\
            {								\
              g_free (r);						\
              g_free (o);						\
            }								\
          break;							\
      }									\
      case BSON_TYPE_JS_CODE:						\
        {								\
          gchar *s = (gchar *)va_arg (ap, gpointer);			\
          gint32 l = (gint32)va_arg (ap, gint32);			\
          bson_append_javascript (b, name, s, l);			\
          if (free_after)						\
            g_free (s);							\
          break;							\
        }								\
      case BSON_TYPE_SYMBOL:						\
        {								\
          gchar *s = (gchar *)va_arg (ap, gpointer);			\
          gint32 l = (gint32)va_arg (ap, gint32);			\
          bson_append_symbol (b, name, s, l);				\
          if (free_after)						\
            g_free (s);							\
          break;							\
        }								\
      case BSON_TYPE_JS_CODE_W_SCOPE:					\
        {								\
          gchar *s = (gchar *)va_arg (ap, gpointer);			\
          gint32 l = (gint32)va_arg (ap, gint32);			\
          bson *scope = (bson *)va_arg (ap, gpointer);			\
          if (free_after && bson_size (scope) < 0)			\
            bson_finish (scope);					\
          bson_append_javascript_w_scope (b, name, s, l, scope);	\
          if (free_after)						\
            bson_free (scope);						\
          break;							\
        }								\
      case BSON_TYPE_INT32:						\
        {								\
          gint32 l = (gint32)va_arg (ap, gint32);			\
          bson_append_int32 (b, name, l);				\
          break;							\
        }								\
      case BSON_TYPE_TIMESTAMP:						\
        {								\
          gint64 ts = (gint64)va_arg (ap, gint64);			\
          bson_append_timestamp (b, name, ts);				\
          break;							\
        }								\
      case BSON_TYPE_INT64:						\
        {								\
          gint64 l = (gint64)va_arg (ap, gint64);			\
          bson_append_int64 (b, name, l);				\
          break;							\
        }								\
      }									\
  }

bson *
bson_build (bson_type type, const gchar *name, ...)
{
  va_list ap;
  bson_type t;
  const gchar *n;
  bson *b;
  gboolean single_result;

  b = bson_new ();
  va_start (ap, name);
  _bson_build_add_single (b, type, name, FALSE, ap);

  if (!single_result)
    {
      bson_free (b);
      va_end (ap);
      return NULL;
    }

  while ((t = (bson_type)va_arg (ap, gint)))
    {
      n = (const gchar *)va_arg (ap, gpointer);
      _bson_build_add_single (b, t, n, FALSE, ap);
      if (!single_result)
        {
          bson_free (b);
          va_end (ap);
          return NULL;
        }
    }
  va_end (ap);

  return b;
}

bson *
bson_build_full (bson_type type, const gchar *name, gboolean free_after, ...)
{
  va_list ap;
  bson_type t;
  const gchar *n;
  gboolean f;
  bson *b;
  gboolean single_result;

  b = bson_new ();
  va_start (ap, free_after);
  _bson_build_add_single (b, type, name, free_after, ap);
  if (!single_result)
    {
      bson_free (b);
      va_end (ap);
      return NULL;
    }

  while ((t = (bson_type)va_arg (ap, gint)))
    {
      n = (const gchar *)va_arg (ap, gpointer);
      f = (gboolean)va_arg (ap, gint);
      _bson_build_add_single (b, t, n, f, ap);
      if (!single_result)
        {
          bson_free (b);
          va_end (ap);
          return NULL;
        }
    }
  va_end (ap);

  return b;
}

gboolean
bson_finish (bson *b)
{
  gint32 *i;

  if (!b)
    return FALSE;

  if (b->finished)
    return TRUE;

  _bson_append_byte (b, 0);

  i = (gint32 *) (&b->data->data[0]);
  *i = GINT32_TO_LE ((gint32) (b->data->len));

  b->finished = TRUE;

  return TRUE;
}

gint32
bson_size (const bson *b)
{
  if (!b)
    return -1;

  if (b->finished)
    return b->data->len;
  else
    return -1;
}

const guint8 *
bson_data (const bson *b)
{
  if (!b)
    return NULL;

  if (b->finished)
    return b->data->data;
  else
    return NULL;
}

gboolean
bson_reset (bson *b)
{
  if (!b)
    return FALSE;

  b->finished = FALSE;
  g_byte_array_set_size (b->data, 0);
  _bson_append_int32 (b, 0);

  return TRUE;
}

void
bson_free (bson *b)
{
  if (!b)
    return;

  if (b->data)
    g_byte_array_free (b->data, TRUE);
  g_free (b);
}

gboolean
bson_validate_key (const gchar *key, gboolean forbid_dots,
                   gboolean no_dollar)
{
  if (!key)
    {
      errno = EINVAL;
      return FALSE;
    }
  errno = 0;

  if (no_dollar && key[0] == '$')
    return FALSE;

  if (forbid_dots && strchr (key, '.') != NULL)
    return FALSE;

  return TRUE;
}

/*
 * Append elements
 */

gboolean
bson_append_double (bson *b, const gchar *name, gdouble val)
{
  gdouble d = GDOUBLE_TO_LE (val);

  if (!_bson_append_element_header (b, BSON_TYPE_DOUBLE, name))
    return FALSE;

  b->data = g_byte_array_append (b->data, (const guint8 *)&d, sizeof (val));
  return TRUE;
}

gboolean
bson_append_string (bson *b, const gchar *name, const gchar *val,
                    gint32 length)
{
  return _bson_append_string_element (b, BSON_TYPE_STRING, name, val, length);
}

gboolean
bson_append_document (bson *b, const gchar *name, const bson *doc)
{
  return _bson_append_document_element (b, BSON_TYPE_DOCUMENT, name, doc);
}

gboolean
bson_append_array (bson *b, const gchar *name, const bson *array)
{
  return _bson_append_document_element (b, BSON_TYPE_ARRAY, name, array);
}

gboolean
bson_append_binary (bson *b, const gchar *name, bson_binary_subtype subtype,
                    const guint8 *data, gint32 size)
{
  if (!data || !size || size <= 0)
    return FALSE;

  if (!_bson_append_element_header (b, BSON_TYPE_BINARY, name))
    return FALSE;

  _bson_append_int32 (b, GINT32_TO_LE (size));
  _bson_append_byte (b, (guint8)subtype);

  b->data = g_byte_array_append (b->data, data, size);
  return TRUE;
}

gboolean
bson_append_oid (bson *b, const gchar *name, const guint8 *oid)
{
  if (!oid)
    return FALSE;

  if (!_bson_append_element_header (b, BSON_TYPE_OID, name))
    return FALSE;

  b->data = g_byte_array_append (b->data, oid, 12);
  return TRUE;
}

gboolean
bson_append_boolean (bson *b, const gchar *name, gboolean value)
{
  if (!_bson_append_element_header (b, BSON_TYPE_BOOLEAN, name))
    return FALSE;

  _bson_append_byte (b, (guint8)value);
  return TRUE;
}

gboolean
bson_append_utc_datetime (bson *b, const gchar *name, gint64 ts)
{
  return _bson_append_int64_element (b, BSON_TYPE_UTC_DATETIME, name, ts);
}

gboolean
bson_append_null (bson *b, const gchar *name)
{
  return _bson_append_element_header (b, BSON_TYPE_NULL, name);
}

gboolean
bson_append_regex (bson *b, const gchar *name, const gchar *regexp,
                   const gchar *options)
{
  if (!regexp || !options)
    return FALSE;

  if (!_bson_append_element_header (b, BSON_TYPE_REGEXP, name))
    return FALSE;

  b->data = g_byte_array_append (b->data, (const guint8 *)regexp,
                                 strlen (regexp) + 1);
  b->data = g_byte_array_append (b->data, (const guint8 *)options,
                                 strlen (options) + 1);

  return TRUE;
}

gboolean
bson_append_javascript (bson *b, const gchar *name, const gchar *js,
                        gint32 len)
{
  return _bson_append_string_element (b, BSON_TYPE_JS_CODE, name, js, len);
}

gboolean
bson_append_symbol (bson *b, const gchar *name, const gchar *symbol,
                    gint32 len)
{
  return _bson_append_string_element (b, BSON_TYPE_SYMBOL, name, symbol, len);
}

gboolean
bson_append_javascript_w_scope (bson *b, const gchar *name,
                                const gchar *js, gint32 len,
                                const bson *scope)
{
  gint size;
  size_t length;

  if (!js || !scope || bson_size (scope) < 0 || len < -1)
    return FALSE;

  if (!_bson_append_element_header (b, BSON_TYPE_JS_CODE_W_SCOPE, name))
    return FALSE;

  length = (len != -1) ? (size_t)len + 1: strlen (js) + 1;

  size = length + sizeof (gint32) + sizeof (gint32) + bson_size (scope);

  _bson_append_int32 (b, GINT32_TO_LE (size));

  /* Append the JS code */
  _bson_append_int32 (b, GINT32_TO_LE (length));
  b->data = g_byte_array_append (b->data, (const guint8 *)js, length - 1);
  _bson_append_byte (b, 0);

  /* Append the scope */
  b->data = g_byte_array_append (b->data, bson_data (scope),
                                 bson_size (scope));

  return TRUE;
}

gboolean
bson_append_int32 (bson *b, const gchar *name, gint32 i)
{
  if (!_bson_append_element_header (b, BSON_TYPE_INT32, name))
    return FALSE;

  _bson_append_int32 (b, GINT32_TO_LE (i));
  return TRUE;
 }

gboolean
bson_append_timestamp (bson *b, const gchar *name, gint64 ts)
{
  return _bson_append_int64_element (b, BSON_TYPE_TIMESTAMP, name, ts);
}

gboolean
bson_append_int64 (bson *b, const gchar *name, gint64 i)
{
  return _bson_append_int64_element (b, BSON_TYPE_INT64, name, i);
}

/*
 * Find & retrieve data
 */
bson_cursor *
bson_cursor_new (const bson *b)
{
  bson_cursor *c;

  if (bson_size (b) == -1)
    return NULL;

  c = (bson_cursor *)g_new0 (bson_cursor, 1);
  c->obj = b;

  return c;
}

void
bson_cursor_free (bson_cursor *c)
{
  g_free (c);
}

/** @internal Figure out the block size of a given type.
 *
 * Provided a #bson_type and some raw data, figures out the length of
 * the block, counted from rigth after the element name's position.
 *
 * @param type is the type of object we need the size for.
 * @param data is the raw data (starting right after the element's
 * name).
 *
 * @returns The size of the block, or -1 on error.
 */
static gint32
_bson_get_block_size (bson_type type, const guint8 *data)
{
  glong l;

  switch (type)
    {
    case BSON_TYPE_STRING:
    case BSON_TYPE_JS_CODE:
    case BSON_TYPE_SYMBOL:
      return bson_stream_doc_size (data, 0) + sizeof (gint32);
    case BSON_TYPE_DOCUMENT:
    case BSON_TYPE_ARRAY:
    case BSON_TYPE_JS_CODE_W_SCOPE:
      return bson_stream_doc_size (data, 0);
    case BSON_TYPE_DOUBLE:
      return sizeof (gdouble);
    case BSON_TYPE_BINARY:
      return bson_stream_doc_size (data, 0) +
        sizeof (gint32) + sizeof (guint8);
    case BSON_TYPE_OID:
      return 12;
    case BSON_TYPE_BOOLEAN:
      return 1;
    case BSON_TYPE_UTC_DATETIME:
    case BSON_TYPE_TIMESTAMP:
    case BSON_TYPE_INT64:
      return sizeof (gint64);
    case BSON_TYPE_NULL:
    case BSON_TYPE_UNDEFINED:
    case BSON_TYPE_MIN:
    case BSON_TYPE_MAX:
      return 0;
    case BSON_TYPE_REGEXP:
      l = strlen((gchar *)data);
      return l + strlen((gchar *)(data + l + 1)) + 2;
    case BSON_TYPE_INT32:
      return sizeof (gint32);
    case BSON_TYPE_DBPOINTER:
      return bson_stream_doc_size (data, 0) + sizeof (gint32) + 12;
    case BSON_TYPE_NONE:
    default:
      return -1;
    }
}

gboolean
bson_cursor_next (bson_cursor *c)
{
  const guint8 *d;
  gint32 pos, bs;

  if (!c)
    return FALSE;

  d = bson_data (c->obj);

  if (c->pos == 0)
    pos = sizeof (guint32);
  else
    {
      bs = _bson_get_block_size (bson_cursor_type (c), d + c->value_pos);
      if (bs == -1)
        return FALSE;
      pos = c->value_pos + bs;
    }

  if (pos >= bson_size (c->obj) - 1)
    return FALSE;

  c->pos = pos;
  c->key = (gchar *) &d[c->pos + 1];
  c->value_pos = c->pos + strlen (c->key) + 2;

  return TRUE;
}

static inline gboolean
_bson_cursor_find (const bson *b, const gchar *name, size_t start_pos,
                   gint32 end_pos, gboolean wrap_over, bson_cursor *dest_c)
{
  gint32 pos = start_pos, bs;
  const guint8 *d;
  gint32 name_len;

  name_len = strlen (name);

  d = bson_data (b);

  while (pos < end_pos)
    {
      bson_type t = (bson_type) d[pos];
      const gchar *key = (gchar *) &d[pos + 1];
      gint32 key_len = strlen (key);
      gint32 value_pos = pos + key_len + 2;

      if (key_len == name_len && memcmp (key, name, key_len) == 0)
        {
          dest_c->obj = b;
          dest_c->key = key;
          dest_c->pos = pos;
          dest_c->value_pos = value_pos;

          return TRUE;
        }
      bs = _bson_get_block_size (t, &d[value_pos]);
      if (bs == -1)
        return FALSE;
      pos = value_pos + bs;
    }

  if (wrap_over)
    return _bson_cursor_find (b, name, sizeof (gint32), start_pos,
                              FALSE, dest_c);

  return FALSE;
}

gboolean
bson_cursor_find (bson_cursor *c, const gchar *name)
{
  if (!c || !name)
    return FALSE;

  return _bson_cursor_find (c->obj, name, c->pos, bson_size (c->obj) - 1,
                            TRUE, c);
}

gboolean
bson_cursor_find_next (bson_cursor *c, const gchar *name)
{
  if (!c || !name)
    return FALSE;

  return _bson_cursor_find (c->obj, name, c->pos, bson_size (c->obj) - 1,
                            FALSE, c);
}

bson_cursor *
bson_find (const bson *b, const gchar *name)
{
  bson_cursor *c;

  if (bson_size (b) == -1 || !name)
    return NULL;

  c = bson_cursor_new (b);
  if (_bson_cursor_find (b, name, sizeof (gint32), bson_size (c->obj) - 1,
                         FALSE, c))
    return c;
  bson_cursor_free (c);
  return NULL;
}

bson_type
bson_cursor_type (const bson_cursor *c)
{
  if (!c || c->pos < sizeof (gint32))
    return BSON_TYPE_NONE;

  return (bson_type)(bson_data (c->obj)[c->pos]);
}

const gchar *
bson_cursor_type_as_string (const bson_cursor *c)
{
  if (!c || c->pos < sizeof (gint32))
    return NULL;

  return bson_type_as_string (bson_cursor_type (c));
}

const gchar *
bson_cursor_key (const bson_cursor *c)
{
  if (!c)
    return NULL;

  return c->key;
}

/** @internal Convenience macro to verify a cursor's type.
 *
 * Verifies that the cursor's type is the same as the type requested
 * by the caller, and returns FALSE if there is a mismatch.
 */
#define BSON_CURSOR_CHECK_TYPE(c,type)		\
  if (bson_cursor_type(c) != type)		\
    return FALSE;

gboolean
bson_cursor_get_string (const bson_cursor *c, const gchar **dest)
{
  if (!dest)
    return FALSE;

  BSON_CURSOR_CHECK_TYPE (c, BSON_TYPE_STRING);

  *dest = (gchar *)(bson_data (c->obj) + c->value_pos + sizeof (gint32));

  return TRUE;
}

gboolean
bson_cursor_get_double (const bson_cursor *c, gdouble *dest)
{
  if (!dest)
    return FALSE;

  BSON_CURSOR_CHECK_TYPE (c, BSON_TYPE_DOUBLE);

  memcpy (dest, bson_data (c->obj) + c->value_pos, sizeof (gdouble));
  *dest = GDOUBLE_FROM_LE (*dest);

  return TRUE;
}

gboolean
bson_cursor_get_document (const bson_cursor *c, bson **dest)
{
  bson *b;
  gint32 size;

  if (!dest)
    return FALSE;

  BSON_CURSOR_CHECK_TYPE (c, BSON_TYPE_DOCUMENT);

  size = bson_stream_doc_size (bson_data(c->obj), c->value_pos) -
    sizeof (gint32) - 1;
  b = bson_new_sized (size);
  b->data = g_byte_array_append (b->data,
                                 bson_data (c->obj) + c->value_pos +
                                 sizeof (gint32), size);
  bson_finish (b);

  *dest = b;

  return TRUE;
}

gboolean
bson_cursor_get_array (const bson_cursor *c, bson **dest)
{
  bson *b;
  gint32 size;

  if (!dest)
    return FALSE;

  BSON_CURSOR_CHECK_TYPE (c, BSON_TYPE_ARRAY);

  size = bson_stream_doc_size (bson_data(c->obj), c->value_pos) -
    sizeof (gint32) - 1;
  b = bson_new_sized (size);
  b->data = g_byte_array_append (b->data,
                                 bson_data (c->obj) + c->value_pos +
                                 sizeof (gint32), size);
  bson_finish (b);

  *dest = b;

  return TRUE;
}

gboolean
bson_cursor_get_binary (const bson_cursor *c,
                        bson_binary_subtype *subtype,
                        const guint8 **data, gint32 *size)
{
  if (!subtype || !size || !data)
    return FALSE;

  BSON_CURSOR_CHECK_TYPE (c, BSON_TYPE_BINARY);

  *size = bson_stream_doc_size (bson_data(c->obj), c->value_pos);
  *subtype = (bson_binary_subtype)(bson_data (c->obj)[c->value_pos +
                                                      sizeof (gint32)]);
  *data = (guint8 *)(bson_data (c->obj) + c->value_pos + sizeof (gint32) + 1);

  return TRUE;
}

gboolean
bson_cursor_get_oid (const bson_cursor *c, const guint8 **dest)
{
  if (!dest)
    return FALSE;

  BSON_CURSOR_CHECK_TYPE (c, BSON_TYPE_OID);

  *dest = (guint8 *)(bson_data (c->obj) + c->value_pos);

  return TRUE;
}

gboolean
bson_cursor_get_boolean (const bson_cursor *c, gboolean *dest)
{
  if (!dest)
    return FALSE;

  BSON_CURSOR_CHECK_TYPE (c, BSON_TYPE_BOOLEAN);

  *dest = (gboolean)(bson_data (c->obj) + c->value_pos)[0];

  return TRUE;
}

gboolean
bson_cursor_get_utc_datetime (const bson_cursor *c,
                              gint64 *dest)
{
  if (!dest)
    return FALSE;

  BSON_CURSOR_CHECK_TYPE (c, BSON_TYPE_UTC_DATETIME);

  memcpy (dest, bson_data (c->obj) + c->value_pos, sizeof (gint64));
  *dest = GINT64_FROM_LE (*dest);

  return TRUE;
}

gboolean
bson_cursor_get_regex (const bson_cursor *c, const gchar **regex,
                       const gchar **options)
{
  if (!regex || !options)
    return FALSE;

  BSON_CURSOR_CHECK_TYPE (c, BSON_TYPE_REGEXP);

  *regex = (gchar *)(bson_data (c->obj) + c->value_pos);
  *options = (gchar *)(*regex + strlen(*regex) + 1);

  return TRUE;
}

gboolean
bson_cursor_get_javascript (const bson_cursor *c, const gchar **dest)
{
  if (!dest)
    return FALSE;

  BSON_CURSOR_CHECK_TYPE (c, BSON_TYPE_JS_CODE);

  *dest = (gchar *)(bson_data (c->obj) + c->value_pos + sizeof (gint32));

  return TRUE;
}

gboolean
bson_cursor_get_symbol (const bson_cursor *c, const gchar **dest)
{
  if (!dest)
    return FALSE;

  BSON_CURSOR_CHECK_TYPE (c, BSON_TYPE_SYMBOL);

  *dest = (gchar *)(bson_data (c->obj) + c->value_pos + sizeof (gint32));

  return TRUE;
}

gboolean
bson_cursor_get_javascript_w_scope (const bson_cursor *c,
                                    const gchar **js,
                                    bson **scope)
{
  bson *b;
  gint32 size, docpos;

  if (!js || !scope)
    return FALSE;

  BSON_CURSOR_CHECK_TYPE (c, BSON_TYPE_JS_CODE_W_SCOPE);

  docpos = bson_stream_doc_size (bson_data (c->obj),
                                  c->value_pos + sizeof (gint32)) +
    sizeof (gint32) * 2;
  size = bson_stream_doc_size (bson_data (c->obj), c->value_pos + docpos) -
    sizeof (gint32) - 1;
  b = bson_new_sized (size);
  b->data = g_byte_array_append (b->data,
                                 bson_data (c->obj) + c->value_pos + docpos +
                                 sizeof (gint32), size);
  bson_finish (b);

  *scope = b;
  *js = (gchar *)(bson_data (c->obj) + c->value_pos + sizeof (gint32) * 2);

  return TRUE;
}

gboolean
bson_cursor_get_int32 (const bson_cursor *c, gint32 *dest)
{
  if (!dest)
    return FALSE;

  BSON_CURSOR_CHECK_TYPE (c, BSON_TYPE_INT32);

  memcpy (dest, bson_data (c->obj) + c->value_pos, sizeof (gint32));
  *dest = GINT32_FROM_LE (*dest);

  return TRUE;
}

gboolean
bson_cursor_get_timestamp (const bson_cursor *c, gint64 *dest)
{
  if (!dest)
    return FALSE;

  BSON_CURSOR_CHECK_TYPE (c, BSON_TYPE_TIMESTAMP);

  memcpy (dest, bson_data (c->obj) + c->value_pos, sizeof (gint64));
  *dest = GINT64_FROM_LE (*dest);

  return TRUE;
}

gboolean
bson_cursor_get_int64 (const bson_cursor *c, gint64 *dest)
{
  if (!dest)
    return FALSE;

  BSON_CURSOR_CHECK_TYPE (c, BSON_TYPE_INT64);

  memcpy (dest, bson_data (c->obj) + c->value_pos, sizeof (gint64));
  *dest = GINT64_FROM_LE (*dest);

  return TRUE;
}
