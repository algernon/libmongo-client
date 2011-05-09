/* bson.h - libmongo-client's BSON implementation
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

#ifndef LIBMONGO_CLIENT_BSON_H
#define LIBMONGO_CLIENT_BSON_H 1

#include <glib.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @defgroup bson_mod BSON
 *
 * The types, functions and everything else within this module is
 * meant to allow one to work with BSON objects easily.
 *
 * @addtogroup bson_mod
 * @{
 */

/** @defgroup bson_types Types
 *
 * @addtogroup bson_types
 * @{
 */

/** An opaque BSON object.
 * A BSON object represents a full BSON document, as specified at
 * http://bsonspec.org/.
 *
 * Each object has two states: open and finished. While the document
 * is open, it can be appended to, but it cannot be read from. While
 * it is finished, it can be read from, and iterated over, but cannot
 * be appended to.
 */
typedef struct _bson bson;

/** Opaque BSON cursor.
 * Cursors are used to represent a single entry within a BSON object,
 * and to help iterating over said document.
 */
typedef struct _bson_cursor bson_cursor;

/** Supported BSON object types.
 */
typedef enum
  {
    BSON_TYPE_NONE = 0, /**< Only used for errors */
    BSON_TYPE_DOUBLE = 0x01, /**< 8byte double */
    BSON_TYPE_STRING, /**< 4byte length + NULL terminated string */
    BSON_TYPE_DOCUMENT, /**< 4byte length + NULL terminated document */
    BSON_TYPE_ARRAY, /**< 4byte length + NULL terminated document */
    BSON_TYPE_BINARY, /**< 4byte length + 1byte subtype + data */
    BSON_TYPE_UNDEFINED, /* Deprecated*/
    BSON_TYPE_OID, /**< 12byte ObjectID */
    BSON_TYPE_BOOLEAN, /**< 1byte boolean value */
    BSON_TYPE_UTC_DATETIME, /**< 8byte timestamp; milliseconds since
			       Unix epoch */
    BSON_TYPE_NULL, /**< NULL value, No following data. */
    BSON_TYPE_REGEXP, /**< Two NULL terminated C strings, the regex
			 itself, and the options. */
    BSON_TYPE_DBPOINTER, /* Deprecated */
    BSON_TYPE_JS_CODE, /**< 4byte length + NULL terminated string */
    BSON_TYPE_SYMBOL, /**< 4byte length + NULL terminated string */
    BSON_TYPE_JS_CODE_W_SCOPE, /**< 4byte length, followed by a
				  string and a document */
    BSON_TYPE_INT32, /**< 4byte integer */
    BSON_TYPE_TIMESTAMP, /**< 4bytes increment + 4bytes timestamp */
    BSON_TYPE_INT64, /**< 8byte integer */
    BSON_TYPE_MIN = 0xff,
    BSON_TYPE_MAX = 0x7f
  } bson_type;

/** Return a type's stringified name.
 *
 * @param type is the type to stringify.
 *
 * @returns The stringified type, or NULL on error.
 */
const gchar *bson_type_as_string (bson_type type);

/** Supported BSON binary subtypes.
 */
typedef enum
  {
    BSON_BINARY_SUBTYPE_GENERIC = 0x00, /**< The Generic subtype, the
					   default. */
    BSON_BINARY_SUBTYPE_FUNCTION = 0x01, /**< Binary representation
					    of a function. */
    BSON_BINARY_SUBTYPE_BINARY = 0x02, /**< Obsolete, do not use. */
    BSON_BINARY_SUBTYPE_UUID = 0x03, /**< Binary representation of an
					UUID. */
    BSON_BINARY_SUBTYPE_MD5 = 0x05, /**< Binary representation of an
				       MD5 sum. */
    BSON_BINARY_SUBTYPE_USER_DEFINED = 0x80 /**< User defined data,
					       nothing's known about
					       the structure. */
  } bson_binary_subtype;

/** @} */

/** @defgroup bson_object_access Object Access
 *
 * Functions that operate on whole BSON objects.
 *
 * @addtogroup bson_object_access
 * @{
 */

/** Create a new BSON object.
 *
 * @note The created object will have no memory pre-allocated for data,
 * resulting in possibly more reallocations than neccessary when
 * appending elements.
 *
 * @note If at all possible, use bson_new_sized() instead.
 *
 * @returns A newly allocated object, or NULL on error.
 */
bson *bson_new (void);

/** Create a new BSON object, preallocating a given amount of space.
 *
 * Creates a new BSON object, pre-allocating @a size bytes of space
 * for the data.
 *
 * @param size is the space to pre-allocate for data.
 *
 * @note It is not an error to pre-allocate either less, or more space
 * than what will really end up being added. Pre-allocation does not
 * set the size of the final object, it is merely a hint, a way to
 * help the system avoid memory reallocations.
 *
 * @returns A newly allocated object, or NULL on error.
 */
bson *bson_new_sized (gint32 size);

/** Create a BSON object from existing data.
 *
 * In order to be able to parse existing BSON, one must load it up
 * into a bson object - and this function does just that.
 *
 * @note Objects created by this function are not final objects, in
 * order to be able to extend them. As such, when importing existing
 * BSON data, which are terminated by a zero byte, specify the size as
 * one smaller than the original data stream.
 *
 * @note This is because bson_finis() will append a zero byte, thus
 * one would end up with an invalid document if it had an extra one.
 *
 * @param data is the BSON byte stream to import.
 * @param size is the size of the byte stream.
 *
 * @returns A newly allocated object, with a copy of @a data as its
 * contents.
 */
bson *bson_new_from_data (const guint8 *data, gint32 size);

/** Build a BSON object in one go, with full control.
 *
 * This function can be used to build a BSON object in one simple
 * step, chaining all the elements together (including sub-documents,
 * created by this same function - more about that later).
 *
 * One has to specify the type, the key name, and whether he wants to
 * see the added object free'd after addition. Each element type is
 * freed appropriately, and documents and arrays are finished before
 * addition, if they're to be freed afterwards.
 *
 * This way of operation allows one to build a full BSON object, even
 * with embedded documents, without leaking memory.
 *
 * After the three required parameters, one will need to list the data
 * itself, in the same order as one would if he'd add with the
 * bson_append family of functions.
 *
 * The list must be closed with a #BSON_TYPE_NONE element, and the @a
 * name and @a free_after parameters are not needed for the closing
 * entry.
 *
 * @param type is the element type we'll be adding.
 * @param name is the key name.
 * @param free_after determines whether the original variable will be
 * freed after adding it to the BSON object.
 *
 * @returns A newly allocated, unfinished BSON object, which must be
 * finalized and freed, once not needed anymore, by the caller. Or
 * NULL on error.
 */
bson *bson_build_full (bson_type type, const gchar *name,
		       gboolean free_after, ...);

/** Build a BSON object in one go.
 *
 * Very similar to bson_build_full(), so much so, that it's exactly
 * the same, except that the @a free_after parameter is always FALSE,
 * and must not be specified in this case.
 *
 * @param type is the element type we'll be adding.
 * @param name is the key name.
 *
 * @returns A newly allocated, unfinished BSON object, which must be
 * finalized and freed, once not needed anymore, by the caller. Or
 * NULL on error.
 */
bson *bson_build (bson_type type, const gchar *name, ...);

/** Finish a BSON object.
 *
 * Terminate a BSON object. This includes appending the trailing zero
 * byte and finalising the length of the object.
 *
 * The object cannot be appended to after it is finalised.
 *
 * @param b is the BSON object to close & finish.
 *
 * @returns TRUE on success, FALSE otherwise.
 */
gboolean bson_finish (bson *b);

/** Reset a BSON object.
 *
 * Resetting a BSON object clears the finished status, and sets its
 * size to zero. Resetting is most useful when wants to keep the
 * already allocated memory around for reuse.
 *
 * @param b is the BSON object to reset.
 *
 * @returns TRUE on success, FALSE otherwise.
 */
gboolean bson_reset (bson *b);

/** Free the memory associated with a BSON object.
 *
 * Frees up all memory associated with a BSON object. The variable
 * shall not be used afterwards.
 *
 * @param b is the BSON object to free.
 */
void bson_free (bson *b);

/** Return the size of a finished BSON object.
 *
 * @param b is the finished BSON object.
 *
 * @returns The size of the document, or -1 on error.
 *
 * @note Trying to get the size of a BSON object that has not been
 * closed by bson_finish() is considered an error.
 */
gint32 bson_size (const bson *b);
/** Return the raw bytestream form of the BSON object.
 *
 * @param b is the BSON object to retrieve data from.
 *
 * @returns The raw datastream or NULL on error. The stream s all not
 * be freed.
 *
 * @note Trying to retrieve the data of an unfinished BSON object is
 * considered an error.
 */
const guint8 *bson_data (const bson *b);

/** @} */

/** @defgroup bson_append Appending
 *
 * @brief Functions to append various kinds of elements to existing
 * BSON objects.
 *
 * Every such function expects the BSON object to be open, and will
 * return FALSE immediately if it finds that the object has had
 * bson_finish() called on it before.
 *
 * The only way to append to a finished BSON object is to @a clone it
 * with bson_new_from_data(), and append to the newly created object.
 *
 * @addtogroup bson_append
 * @{
 */

/** Append a string to a BSON object.
 *
 * @param b is the BSON object to append to.
 * @param name is the key name.
 * @param val is the value to append.
 * @param length is the length of value. Use @a -1 to use the full
 * string supplied as @a name.
 *
 * @returns TRUE on success, FALSE otherwise.
 */
gboolean bson_append_string (bson *b, const gchar *name, const gchar *val,
			     gint32 length);

/** Append a double to a BSON object.
 *
 * @param b is the BSON object to append to.
 * @param name is the key name.
 * @param d is the double value to append.
 *
 * @returns TRUE on success, FALSE otherwise.
 */
gboolean bson_append_double (bson *b, const gchar *name, gdouble d);

/** Append a BSON document to a BSON object.
 *
 * @param b is the BSON object to append to.
 * @param name is the key name.
 * @param doc is the BSON document to append.
 *
 * @note @a doc MUST be a finished BSON document.
 *
 * @returns TRUE on success, FALSE otherwise.
 */
gboolean bson_append_document (bson *b, const gchar *name, const bson *doc);

/** Append a BSON array to a BSON object.
 *
 * @param b is the BSON object to append to.
 * @param name is the key name.
 * @param array is the BSON array to append.
 *
 * @note @a array MUST be a finished BSON document.
 *
 * @note The difference between plain documents and arrays - as far as
 * this library is concerned, and apart from the type - is that array
 * keys must be numbers in increasing order. However, no extra care is
 * taken to verify that: it is the responsibility of the caller to set
 * the array up appropriately.
 *
 * @returns TRUE on success, FALSE otherwise.
 */
gboolean bson_append_array (bson *b, const gchar *name, const bson *array);

/** Append a BSON binary blob to a BSON object.
 *
 * @param b is the BSON object to append to.
 * @param name is the key name.
 * @param subtype is the BSON binary subtype to use.
 * @param data is a pointer to the blob data.
 * @param size is the size of the blob.
 *
 * @returns TRUE on success, FALSE otherwise.
 */
gboolean bson_append_binary (bson *b, const gchar *name,
			     bson_binary_subtype subtype,
			     const guint8 *data, gint32 size);

/** Append an ObjectID to a BSON object.
 *
 * ObjectIDs are 12 byte values, the first four being a timestamp in
 * big endian byte order, the next three a machine ID, then two bytes
 * for the PID, and finally three bytes of sequence number, in big
 * endian byte order again.
 *
 * @param b is the BSON object to append to.
 * @param name is the key name.
 * @param oid is the ObjectID to append.
 *
 * @note The OID must be 12 bytes long, and formatting it
 * appropriately is the responsiblity of the caller.
 *
 * @returns TRUE on success, FALSE otherwise.
 */
gboolean bson_append_oid (bson *b, const gchar *name, const guint8 *oid);

/** Append a boolean to a BSON object.
 *
 * @param b is the BSON object to append to.
 * @param name is the key name.
 * @param value is the boolean value to append.
 *
 * @returns TRUE on success, FALSE otherwise.
 */
gboolean bson_append_boolean (bson *b, const gchar *name, gboolean value);

/** Append an UTC datetime to a BSON object.
 *
 * @param b is the BSON object to append to.
 * @param name is the key name.
 * @param ts is the UTC timestamp: the number of milliseconds since
 * the Unix epoch.
 *
 * @returns TRUE on success, FALSE otherwise.
 */
gboolean bson_append_utc_datetime (bson *b, const gchar *name, gint64 ts);

/** Append a NULL value to a BSON object.
 *
 * @param b is the BSON object to append to.
 * @param name is the key name.
 *
 * @returns TRUE on success, FALSE otherwise.
 */
gboolean bson_append_null (bson *b, const gchar *name);

/** Append a regexp object to a BSON object.
 *
 * @param b is the BSON object to append to.
 * @param name is the key name.
 * @param regexp is the regexp string itself.
 * @param options represents the regexp options, serialised to a
 * string.
 *
 * @returns TRUE on success, FALSE otherwise.
 */
gboolean bson_append_regex (bson *b, const gchar *name, const gchar *regexp,
			    const gchar *options);

/** Append Javascript code to a BSON object.
 *
 * @param b is the BSON object to append to.
 * @param name is the key name.
 * @param js is the javascript code as a C string.
 * @param len is the length of the code, use @a -1 to use the full
 * length of the string supplised in @a js.
 *
 * @returns TRUE on success, FALSE otherwise.
 */
gboolean bson_append_javascript (bson *b, const gchar *name, const gchar *js,
				 gint32 len);

/** Append a symbol to a BSON object.
 *
 * @param b is the BSON object to append to.
 * @param name is the key name.
 * @param symbol is the symbol to append.
 * @param len is the length of the code, use @a -1 to use the full
 * length of the string supplised in @a symbol.
 *
 * @returns TRUE on success, FALSE otherwise.
 */
gboolean bson_append_symbol (bson *b, const gchar *name, const gchar *symbol,
			     gint32 len);

/** Append Javascript code (with scope) to a BSON object.
 *
 * @param b is the BSON object to append to.
 * @param name is the key name.
 * @param js is the javascript code as a C string.
 * @param len is the length of the code, use @a -1 to use the full
 * length of the string supplied in @a js.
 * @param scope is scope to evaluate the javascript code in.
 *
 * @returns TRUE on success, FALSE otherwise.
 */
gboolean bson_append_javascript_w_scope (bson *b, const gchar *name,
					 const gchar *js, gint32 len,
					 const bson *scope);

/** Append a 32-bit integer to a BSON object.
 *
 * @param b is the BSON object to append to.
 * @param name is the key name.
 * @param i is the integer to append.
 *
 * @returns TRUE on success, FALSE otherwise.
 */
gboolean bson_append_int32 (bson *b, const gchar *name, gint32 i);

/** Append a timestamp to a BSON object.
 *
 * @param b is the BSON object to append to.
 * @param name is the key name.
 * @param ts is the timestamp to append.
 *
 * @note The ts param should consists of 4 bytes of increment,
 * followed by 4 bytes of timestamp. It is the responsibility of the
 * caller to set the variable up appropriately.
 *
 * @returns TRUE on success, FALSE otherwise.
 */
gboolean bson_append_timestamp (bson *b, const gchar *name, gint64 ts);

/** Append a 64-bit integer to a BSON object.
 *
 * @param b is the BSON object to append to.
 * @param name is the key name.
 * @param i is the integer to append.
 *
 * @returns TRUE on success, FALSE otherwise.
 */
gboolean bson_append_int64 (bson *b, const gchar *name, gint64 i);

/** @} */

/** @defgroup bson_cursor Cursor & Retrieval
 *
 * This section documents the cursors, and the data retrieval
 * functions. Each and every function here operates on finished BSON
 * objects, and will return with an error if passed an open object.
 *
 * Data can be retrieved from cursors, which in turn point to a
 * specific part of the BSON object.
 *
 * The idea is to place the cursor to the appropriate key first, then
 * retrieve the data stored there. Trying to retrieve data that is of
 * different type than what the cursor is results in an error.
 *
 * Functions to iterate to the next key, and retrieve the current
 * keys name are also provided.
 *
 * @addtogroup bson_cursor
 * @{
 */

/** Create a new cursor.
 *
 * Creates a new cursor, and positions it to the beginning of the
 * supplied BSON object.
 *
 * @param b is the BSON object to create a cursor for.
 *
 * @returns A newly allocated cursor, or NULL on error.
 */
bson_cursor *bson_cursor_new (const bson *b);

/** Create a new cursor positioned at a given key.
 *
 * Creates a new cursor, and positions it to the supplied key within
 * the BSON object.
 *
 * @param b is the BSON object to create a cursor for.
 * @param name is the key name to position to.
 *
 * @returns A newly allocated cursor, or NULL on error.
 */
bson_cursor *bson_find (const bson *b, const gchar *name);

/** Delete a cursor, and free up all resources used by it.
 *
 * @param c is the cursor to free.
 */
void bson_cursor_free (bson_cursor *c);

/** Position the cursor to the next key.
 *
 * @param c is the cursor to move forward.
 *
 * @returns TRUE on success, FALSE otherwise.
 */
gboolean bson_cursor_next (bson_cursor *c);

/** Determine the type of the current element.
 *
 * @param c is the cursor pointing at the appropriate element.
 *
 * @returns The type of the element, or #BSON_TYPE_NONE on error.
 */
bson_type bson_cursor_type (const bson_cursor *c);

/** Retrieve the type of the current element, as string.
 *
 * @param c is the cursor pointing at the appropriate element.
 *
 * @returns The type of the element, as string, or NULL on error.
 *
 * @note The string points to an internal structure, it should not be
 * freed or modified.
 */
const gchar *bson_cursor_type_as_string (const bson_cursor *c);

/** Determine the name of the current elements key.
 *
 * @param c is the cursor pointing at the appropriate element.
 *
 * @returns The name of the key, or NULL on error.
 *
 * @note The name is a pointer to an internal string, one must NOT
 * free it.
 */
const gchar *bson_cursor_key (const bson_cursor *c);

/** Get the value stored at the cursor, as string.
 *
 * @param c is the cursor pointing at the appropriate element.
 * @param dest is a pointer to a variable where the value can be
 * stored.
 *
 * @note The @a dest pointer will be set to point to an internal
 * structure, and must not be freed or modified by the caller.
 *
 * @returns TRUE on success, FALSE otherwise.
 */
gboolean bson_cursor_get_string (const bson_cursor *c, const gchar **dest);

/** Get the value stored at the cursor, as a double.
 *
 * @param c is the cursor pointing at the appropriate element.
 * @param dest is a pointer to a variable where the value can be
 * stored.
 *
 * @returns TRUE on success, FALSE otherwise.
 */
gboolean bson_cursor_get_double (const bson_cursor *c, gdouble *dest);

/** Get the value stored at the cursor, as a BSON document.
 *
 * @param c is the cursor pointing at the appropriate element.
 * @param dest is a pointer to a variable where the value can be
 * stored.
 *
 * @note The @a dest pointer will be a newly allocated, finished
 * object: it is the responsibility of the caller to free it.
 *
 * @returns TRUE on success, FALSE otherwise.
 */
gboolean bson_cursor_get_document (const bson_cursor *c, bson **dest);

/** Get the value stored at the cursor, as a BSON array.
 *
 * @param c is the cursor pointing at the appropriate element.
 * @param dest is a pointer to a variable where the value can be
 * stored.
 *
 * @note The @a dest pointer will be a newly allocated, finished
 * object: it is the responsibility of the caller to free it.
 *
 * @returns TRUE on success, FALSE otherwise.
 */
gboolean bson_cursor_get_array (const bson_cursor *c, bson **dest);

/** Get the value stored at the cursor, as binary data.
 *
 * @param c is the cursor pointing at the appropriate element.
 * @param subtype is a pointer to store the binary subtype at.
 * @param data is a pointer to where the data shall be stored.
 * @param size is a pointer to store the size at.
 *
 * @note The @a data pointer will be pointing to an internal
 * structure, it must not be freed or modified.
 *
 * @returns TRUE on success, FALSE otherwise.
 */
gboolean bson_cursor_get_binary (const bson_cursor *c,
				 bson_binary_subtype *subtype,
				 const guint8 **data, gint32 *size);

/** Get the value stored at the cursor, as an ObjectID.
 *
 * @param c is the cursor pointing at the appropriate element.
 * @param dest is a pointer to a variable where the value can be
 * stored.
 *
 * @note The @a dest pointer will be set to point to an internal
 * structure, and must not be freed or modified by the caller.
 *
 * @returns TRUE on success, FALSE otherwise.
 */
gboolean bson_cursor_get_oid (const bson_cursor *c, const guint8 **dest);

/** Get the value stored at the cursor, as a boolean.
 *
 * @param c is the cursor pointing at the appropriate element.
 * @param dest is a pointer to a variable where the value can be
 * stored.
 *
 * @returns TRUE on success, FALSE otherwise.
 */
gboolean bson_cursor_get_boolean (const bson_cursor *c, gboolean *dest);

/** Get the value stored at the cursor, as an UTC datetime.
 *
 * @param c is the cursor pointing at the appropriate element.
 * @param dest is a pointer to a variable where the value can be
 * stored.
 *
 * @returns TRUE on success, FALSE otherwise.
 */
gboolean bson_cursor_get_utc_datetime (const bson_cursor *c, gint64 *dest);

/** Get the value stored at the cursor, as a regexp.
 *
 * @param c is the cursor pointing at the appropriate element.
 * @param regex is a pointer to a variable where the regex can be
 * stored.
 * @param options is a pointer to a variable where the options can be
 * stored.
 *
 * @note Both the @a regex and @a options pointers will be set to
 * point to an internal structure, and must not be freed or modified
 * by the caller.
 *
 * @returns TRUE on success, FALSE otherwise.
 */
gboolean bson_cursor_get_regex (const bson_cursor *c, const gchar **regex,
				const gchar **options);

/** Get the value stored at the cursor, as javascript code.
 *
 * @param c is the cursor pointing at the appropriate element.
 * @param dest is a pointer to a variable where the value can be
 * stored.
 *
 * @note The @a dest pointer will be set to point to an internal
 * structure, and must not be freed or modified by the caller.
 *
 * @returns TRUE on success, FALSE otherwise.
 */
gboolean bson_cursor_get_javascript (const bson_cursor *c, const gchar **dest);

/** Get the value stored at the cursor, as a symbol.
 *
 * @param c is the cursor pointing at the appropriate element.
 * @param dest is a pointer to a variable where the value can be
 * stored.
 *
 * @note The @a dest pointer will be set to point to an internal
 * structure, and must not be freed or modified by the caller.
 *
 * @returns TRUE on success, FALSE otherwise.
 */
gboolean bson_cursor_get_symbol (const bson_cursor *c, const gchar **dest);

/** Get the value stored at the cursor, as javascript code w/ scope.
 *
 * @param c is the cursor pointing at the appropriate element.
 * @param js is a pointer to a variable where the javascript code can
 * be stored.
 * @param scope is a pointer to a variable where the scope can be
 * stored.
 *
 * @note The @a scope pointer will be a newly allocated, finished
 * BSON object: it is the responsibility of the caller to free it.
 *
 * @returns TRUE on success, FALSE otherwise.
 */
gboolean bson_cursor_get_javascript_w_scope (const bson_cursor *c,
					     const gchar **js,
					     bson **scope);

/** Get the value stored at the cursor, as a 32-bit integer.
 *
 * @param c is the cursor pointing at the appropriate element.
 * @param dest is a pointer to a variable where the value can be
 * stored.
 *
 * @returns TRUE on success, FALSE otherwise.
 */
gboolean bson_cursor_get_int32 (const bson_cursor *c, gint32 *dest);

/** Get the value stored at the cursor, as a timestamp.
 *
 * @param c is the cursor pointing at the appropriate element.
 * @param dest is a pointer to a variable where the value can be
 * stored.
 *
 * @returns TRUE on success, FALSE otherwise.
 */
gboolean bson_cursor_get_timestamp (const bson_cursor *c, gint64 *dest);

/** Get the value stored at the cursor, as a 64-bit integer.
 *
 * @param c is the cursor pointing at the appropriate element.
 * @param dest is a pointer to a variable where the value can be
 * stored.
 *
 * @returns TRUE on success, FALSE otherwise.
 */
gboolean bson_cursor_get_int64 (const bson_cursor *c, gint64 *dest);

/** @} */

/** @} */

#ifdef __cplusplus
}
#endif

#endif
