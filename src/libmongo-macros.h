/* libmongo-macros.h - helper macros for libmongo-client.
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

#ifndef LIBMONGO_MACROS_H
#define LIBMONGO_MACROS_H 1

#include <glib.h>

//#define MAX_DATA_LEN 32505856
#define MAX_DATA_LEN 3290287

inline static gdouble
GDOUBLE_SWAP_LE_BE(gdouble in)
{
  union
  {
    guint64 i;
    gdouble d;
  } u;

  u.d = in;
  u.i = GUINT64_SWAP_LE_BE (u.i);
  return u.d;
}

#if G_BYTE_ORDER == G_LITTLE_ENDIAN
#define GDOUBLE_TO_LE(val)   ((gdouble) (val))
#define GDOUBLE_TO_BE(val)   (GDOUBLE_SWAP_LE_BE (val))

#elif G_BYTE_ORDER == G_BIG_ENDIAN
#define GDOUBLE_TO_LE(val)   (GDOUBLE_SWAP_LE_BE (val))
#define GDOUBLE_TO_BE(val)   ((gdouble) (val))

#else /* !G_LITTLE_ENDIAN && !G_BIG_ENDIAN */
#error unknown ENDIAN type
#endif /* !G_LITTLE_ENDIAN && !G_BIG_ENDIAN */

#define GDOUBLE_FROM_LE(val) (GDOUBLE_TO_LE (val))
#define GDOUBLE_FROM_BE(val) (GDOUBLE_TO_BE (val))

#endif
