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

#ifndef __AUTILS__
#define __AUTILS__

//#define TEST_DYNINST_ONLY 
#define TEST_PATH_ANALYSIS_ONLY

//#define DDEBUG_ASIA 
#ifdef DDEBUG_ASIA
#define adebug_fprintf(...)		fprintf(__VA_ARGS__)  
#define adebug_assert(cond)		assert(cond) 
#else
#define adebug_fprintf(...) 
#define adebug_assert(cond)	
#endif

//#define TRACK_CFG_BUILDING 
#ifdef TRACK_CFG_BUILDING
#define cfg_building_fprintf(...)		fprintf(__VA_ARGS__)  
#else 
#define cfg_building_fprintf(...)		
#endif 

std::string string_format(const std::string fmt_str, ...); 

#endif
 
