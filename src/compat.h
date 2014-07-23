/* compat.h - Various compatibility functions
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

#ifndef LIBMONGO_COMPAT_H
#define LIBMONGO_COMPAT_H 1

#include "config.h"

#include <sys/types.h>
#include <sys/socket.h>

#if NO_GLIB_HASH_FUNCTIONS
#include <openssl/md5.h>

typedef enum {
  G_CHECKSUM_MD5,
  G_CHECKSUM_SHA1,
  G_CHECKSUM_SHA256
} GChecksumType;

typedef struct _GChecksum GChecksum;

GChecksum *g_checksum_new (GChecksumType checksum_type);
void g_checksum_free (GChecksum *checksum);
void g_checksum_update (GChecksum *checksum,
                        const unsigned char *data,
                        ssize_t length);
const char *g_checksum_get_string (GChecksum *checksum);

#endif /* NO_GLIB_HASH_FUNCTIONS */

#ifndef MSG_WAITALL
#define MSG_WAITALL 0x40
#endif

#endif
