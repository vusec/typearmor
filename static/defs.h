/*
 * Copyright 2017, Victor van der Veen
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

#ifndef __CFG_DEFS__
#define __CFG_DEFS__

#include "BPatch.h"

typedef uint64_t address_t; 
const address_t DUMMY_ADDR = 0x2910; 

#ifdef DYNINST_8_2
#define PARSE_API_RET_BLOCKLIST ParseAPI::Function::const_blocklist
#else
#define PARSE_API_RET_BLOCKLIST ParseAPI::Function::blocklist
#endif

#endif 
