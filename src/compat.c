/* compat.c - Various compatibility functions
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

#include "config.h"

#if NO_GLIB_HASH_FUNCTIONS

#include "compat.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/md5.h>

struct _GChecksum
{
  GChecksumType type;
  char hex_digest[33];

  MD5_CTX context;
};

GChecksum *
g_checksum_new (GChecksumType checksum_type)
{
  GChecksum *chk;

  if (checksum_type != G_CHECKSUM_MD5)
    {
      errno = ENOSYS;
      return NULL;
    }

  chk = calloc (1, sizeof (GChecksum));
  chk->type = checksum_type;

  MD5_Init (&chk->context);

  return chk;
}

void
g_checksum_free (GChecksum *checksum)
{
  if (checksum)
    free (checksum);
}

void
g_checksum_update (GChecksum *checksum,
                   const unsigned char *data,
                   ssize_t length)
{
  size_t l = length;

  if (!checksum || !data || length == 0)
    {
      errno = EINVAL;
      return;
    }
  errno = 0;

  if (length < 0)
    l = strlen ((const char *)data);

  MD5_Update (&checksum->context, (const void *)data, l);
}

const char *
g_checksum_get_string (GChecksum *checksum)
{
  unsigned char digest[16];
  static const char hex[16] =
    {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
     'a', 'b', 'c', 'd', 'e', 'f'};
  int i;

  if (!checksum)
    {
      errno = EINVAL;
      return NULL;
    }

  MD5_Final (digest, &checksum->context);

  for (i = 0; i < 16; i++)
    {
      checksum->hex_digest[2 * i] = hex[(digest[i] & 0xf0) >> 4];
      checksum->hex_digest[2 * i + 1] = hex[digest[i] & 0x0f];
    }
  checksum->hex_digest[32] = '\0';

  return checksum->hex_digest;
}

#endif /* NO_GLIB_HASH_FUNCTIONS */
