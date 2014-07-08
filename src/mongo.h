/* mongo.h - libmongo-client general header
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

/** @file src/mongo.h
 * libmongo-client meta-header.
 *
 * This header includes all the rest, it is advised for applications
 * to include this header, and this header only.
 */

#include <bson.h>
#include <mongo-wire.h>
#include <mongo-client.h>
#include <mongo-ssl.h>
#include <mongo-utils.h>
#include <mongo-sync.h>
#include <mongo-sync-cursor.h>
#include <mongo-sync-pool.h>
#include <sync-gridfs.h>
#include <sync-gridfs-chunk.h>
#include <sync-gridfs-stream.h>

/** @mainpage libmongo-client
 *
 * @section Introduction
 *
 * libmongo-client is an alternative MongoDB driver for the C
 * language, with clarity, correctness and completeness in mind.
 *
 * Contents:
 * @htmlonly
 *  <ul>
 *   <li><a href="modules.html"><b>API Documentation</b></a></li>
 *   <li><a href="tutorial.html"><b>Tutorial</b></a></li>
 * </ul>
 * @endhtmlonly
 */
