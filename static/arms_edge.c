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

#include <stdio.h>
#include <stdint.h> 

using namespace std; 

#include <string> 
#include <vector>
#include <set> 

#include "defs.h" 
#include "arms_utils.h" 
#include "arms_bb.h" 
#include "arms_edge.h" 

const char* arms_edge_type_strings[] = {
	"direct_call",
	"indirect_call",
	"inter_direct_jump", 
	"inter_indirect_jump",
	"cond_taken",
	"cond_not_taken",
	"direct_jmp",
	"indirect_jmp",
	"fallthrough", 
	"catch", 
	"call_ft", 	
	"ret", 
	"no_edge", 
	"unknown"   
};

unsigned int ArmsEdge::id_seq_ = 0; 

bool 
edge_type_is_call(arms_edge_type_t type) 
{
	return ((type == arms_direct_call) || (type == arms_indirect_jmp));	
}

bool 
edge_type_is_direct_call(arms_edge_type_t type) 
{
	return (type == arms_direct_call);
}

bool 
edge_type_is_indirect_call(arms_edge_type_t type) 
{
	return (type == arms_indirect_call);
}

bool
edge_type_is_return(arms_edge_type_t type)
{
	return (type == arms_ret);
}

bool 
edge_type_is_inter_direct_jmp(arms_edge_type_t type)
{
	return (type == arms_inter_direct_jmp);
}

bool 
edge_type_is_inter_indirect_jmp(arms_edge_type_t type)
{
	return false;
}

bool
edge_type_is_indirect(arms_edge_type_t type)
{
	return (type == arms_indirect_jmp) || (type == arms_indirect_call || (type == arms_inter_indirect_jmp)); 
}

void 
ArmsEdge::set_type(arms_edge_type_t type) { 
	type_ = type; 

	if ((type == arms_direct_call) || (type == arms_indirect_call) || (type == arms_ret) || 
		(type == arms_inter_indirect_jmp) || (type == arms_inter_direct_jmp)) {
		set_interprocedural(); 
	}
}

string ArmsEdge::to_string(void) {
	return string_format("(%s) %s -> %s", arms_edge_type_strings[type()], 
		get_source()->to_string().c_str(), get_target()->to_string().c_str()); 
}

void
ArmsEdge::unlink() {
	source()->delete_outgoing_edge(this);
	target()->delete_incoming_edge(this);
}

