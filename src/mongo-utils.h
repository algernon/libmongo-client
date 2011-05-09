/* mongo-utils.h - libmongo-client utility functions
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

#ifndef LIBMONGO_CLIENT_UTILS_H
#define LIBMONGO_CLIENT_UTILS_H 1

#include <glib.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @defgroup mongo_util Mongo Utils
 *
 * Various utility functions related to MongoDB.
 *
 * @addtogroup mongo_util
 * @{
 */

/** Intitialize the static ObjectID components.
 *
 * @param machine_id is the machine id to use, or zero to generate one
 * automatically.
 *
 * This function needs to be called once, before any OIDs are
 * generated. It is also a good idea to call it whenever the calling
 * program's PID might change.
 */
void mongo_util_oid_init (gint32 machine_id);

/** Generate a new ObjectID.
 *
 * Based on the current time, the pre-determined pid and machine ID
 * and a supplied sequence number, generate a new ObjectID.
 *
 * The machine id and the PID are updated whenever
 * mongo_util_oid_init() is called.
 *
 * @param seq is the sequence number to use.
 *
 * @note The ObjectID has space for only 24 bits of sequence bytes, so
 * it should be noted that while @a seq is 32 bits wide, only 24 of
 * that will be used.
 *
 * @returns A newly allocated ObjectID or NULL on error. Freeing it is
 * the responsibility of the caller.
 */
guint8 *mongo_util_oid_new (gint32 seq);

/** Generate a new ObjectID, with a predefined timestamp.
 *
 * Based on the suppiled time and sequence number, and the
 * pre-determined pid and machine ID, generate a new ObjectID.
 *
 * The machine id and the PID are updated whenever
 * mongo_util_oid_init() is called.
 *
 * @param time is the timestamp to use.
 * @param seq is the sequence number to use.
 *
 *
 * @note The ObjectID has space for only 24 bits of sequence bytes, so
 * it should be noted that while @a seq is 32 bits wide, only 24 of
 * that will be used.
 *
 * @returns A newly allocated ObjectID or NULL on error. Freeing it is
 * the responsibility of the caller.
 */
guint8 *mongo_util_oid_new_with_time (gint32 time, gint32 seq);

/** Parse a HOST:IP pair.
 *
 * Given a HOST:IP pair, split it up into a host and a port. IPv6
 * addresses supported, the function cuts at the last ":".
 *
 * @param addr is the address to split.
 * @param host is a pointer to a string where the host part will be
 * stored.
 * @param port is a pointer to an integer, where the port part will be
 * stored.
 *
 * @returns TRUE on success, FALSE otherwise. The @a host parameter
 * will contain a newly allocated string on succes. On failiure, host
 * will be set to NULL, and port to -1.
 */
gboolean mongo_util_parse_addr (const gchar *addr, gchar **host,
				gint *port);

/** @} */

#ifdef __cplusplus
}
#endif

#endif
