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

#ifndef __ICALL_RESOLVER__
#define __ICALL_RESOLVER__

#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <stdlib.h>

#include "env.h"


/* Slightly different from the icall-resolver used by PathArmor. This one
 * assumes a settings.llvm/icall-info/profiling.map file that contains a
 * callsite/callee pair on each line, separate by whitespace:
 * ...
 * <callsite a> <callee X>
 * <callsite a> <callee Y>
 * <callsite b> <callee X>
 * <callsite b> <callee Z>
 * ...
 */

static inline int arms_icall_resolver(void *callSiteAddr, std::vector<void*> &targets)
{
    std::ifstream infile("settings.llvm/icall-info/profiling.map");
    std::string line;
    while (std::getline(infile, line)) {
        std::istringstream iss(line);
        void *callsite, *callee;
        if (!(iss >> callsite >> callee)) { break; } // error

        if (callsite == callSiteAddr) {
//          fprintf(stderr,"found callsite %p -> %p\n", callsite, callee);
            targets.push_back(callee);
        }
    }

//  fprintf(stderr,"icall resolver found %lu callees for %p\n", targets.size(), callSiteAddr);

    return 0;
}

#endif

