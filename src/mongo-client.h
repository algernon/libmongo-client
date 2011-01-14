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

#include "bson.h"
#include "mongo-wire.h"

#include <glib.h>

gint mongo_connect (const char *host, int port);
void mongo_disconnect (gint fd);

gboolean mongo_packet_send (gint fd, const mongo_packet *p);

#endif