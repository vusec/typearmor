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
#include <stdlib.h>
#include <assert.h> 
#include <stdint.h> 

using namespace std; 

#include <set>
#include <map> 
#include <string> 
#include <vector> 

#include "defs.h"
#include "arms_utils.h"
#include "arms_bb.h"
#include "arms_edge.h"
#include "arms_cfg.h" 

#include "arms_function.h" 

string ArmsFunction::fun_dummy_name = string("NA"); 

void
ArmsFunction::add_bb(ArmsBasicBlock *bb)
{
	basic_blocks.insert(bb);
}

void 
ArmsFunction::add_entry_block(address_t bb_addr) 
{
	ArmsBasicBlock *bb = cfg->find_bb(bb_addr);
	if (!bb) return; 
	entry_points.insert(bb);	
}

void 
ArmsFunction::add_entry_block(ArmsBasicBlock *bb) 
{
	entry_points.insert(bb);	
}
	
std::set<ArmsFunction*> 
ArmsFunction::get_callers(void)
{
    std::set<ArmsFunction *> result;

    for (std::set<ArmsBasicBlock *>::iterator it  = entry_points.begin();
                                              it != entry_points.end();
                                              it++) {
        ArmsBasicBlock *entry_block = *it;

        for (size_t i = 0; i < entry_block->incoming_edge_count(); i++) {
            ArmsEdge *edge = entry_block->get_incoming_edge(i);

            ArmsBasicBlock *caller_block = edge->get_source();

            std::vector<ArmsFunction*> caller_functions = caller_block->get_containing_functions();

            result.insert(caller_functions.begin(), caller_functions.end());
	
        }



    
    }
        return result;

}

ArmsBasicBlock*
ArmsFunction::get_entry_point(size_t i)
{
  typedef std::set<ArmsBasicBlock*>::iterator block_iter;

  block_iter iter;

  iter = entry_points.begin();
  std::advance(iter, i);

  return (*iter);
}

ArmsBasicBlock*
ArmsFunction::get_exit_point(size_t i)
{
  typedef std::set<ArmsBasicBlock*>::iterator block_iter;

  block_iter iter;

  iter = exit_points.begin();
  std::advance(iter, i);

  return (*iter);
}

int
ArmsFunction::foreach_entry_block(int (*callback)(ArmsBasicBlock*,void*), void *arg)
{
    typedef std::set<ArmsBasicBlock*>::iterator block_iter;

    int ret;
    block_iter iter;
    ArmsBasicBlock *entry;

    if(entry_points.size() < 1) {
        return 0;
    }

    for(iter = entry_points.begin(); iter != entry_points.end(); iter++) {
        entry = *iter;
        if((ret = callback(entry, arg))) {
            return ret;
        }
    }

    return 0;
}

int
ArmsFunction::foreach_inbound_edge(int (*callback)(ArmsEdge*,void*), void *arg)
{
    typedef std::set<ArmsBasicBlock*>::iterator block_iter;

    int ret;
    size_t i;
    block_iter iter;
    ArmsBasicBlock *entry;

    if(entry_points.size() < 1) {
        return 0;
    }

    for(iter = entry_points.begin(); iter != entry_points.end(); iter++) {
        entry = *iter;
        for(i = 0; i < entry->incoming_edge_count(); i++) {
            if((ret = callback(entry->get_incoming_edge(i), arg))) {
                return ret;
            }
        }
    }

    return 0;
}

void 
ArmsFunction::debug_confirm_entry_block(address_t bb_addr) 
{
#ifdef DDEBUG_ASIA
	ArmsBasicBlock *bb = cfg->find_bb(bb_addr);
	if (!bb) {
		adebug_fprintf(stderr, "[XXX] debug_confirm_entry_block: bb at %p doesn't exist\n", (void*)bb_addr);
		return;
	}
	assert(bb->is_entry_block()); 	
#endif 
}

void 
ArmsFunction::add_exit_block(address_t bb_last_insn_addr) 
{
	ArmsBasicBlock *bb = cfg->find_bb_by_last_insn_address(bb_last_insn_addr);
	if (!bb) return; 
	exit_points.insert(bb);	
}

void 
ArmsFunction::add_exit_block(ArmsBasicBlock *bb) 
{
	exit_points.insert(bb);	
}

void 
ArmsFunction::debug_confirm_exit_block(address_t bb_last_insn_addr) 
{
#ifdef DDEBUG_ASIA
	ArmsBasicBlock *bb = cfg->find_bb_by_last_insn_address(bb_last_insn_addr);
	if (!bb) {
		adebug_fprintf(stderr, "[XXX] debug_confirm_exit_block: bb at %p doesn't exist\n", (void*)bb_last_insn_addr);
		return;
	}
	if (!(bb->is_exit_block())) {
		adebug_fprintf(stderr, "[XXX] debug_confirm_exit_block: bb at %p is not an exit block\n", (void*)bb_last_insn_addr);
	}
#endif 
}

std::map <ArmsBasicBlock *, int>
ArmsFunction::get_icall_args(void)
{
    std::map<ArmsBasicBlock *, int> result;
    for (std::set<ArmsBasicBlock *>::iterator it  = basic_blocks.begin();
                                              it != basic_blocks.end();
                                              it++) {
        ArmsBasicBlock *block = *it;
        int icall_args = block->get_icall_args();
        if (icall_args != -1) {
            result[block] = icall_args;
        }
    }
    return result;
}

string 
ArmsFunction::to_string(void)
{
	return string_format("Fun(%p)", (void*)base_addr);
}
