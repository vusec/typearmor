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
#include <assert.h> 

#include <string> 
#include <vector>
#include <set> 
#include <map>
using namespace std; 

#include "defs.h"
#include "arms_utils.h"
#include "arms_edge.h" 
#include "arms_bb.h" 
#include "arms_function.h"  

#include "arms_cfg.h"

bool
CFG::addr_in_cfg(address_t addr)
{
	ArmsFunction *f;
	ArmsBasicBlock *bb;

	if((addr >= start_addr_) && (addr < end_addr_)) {
		return true;
	} else if((f = find_function(addr)) != NULL) {
		return f->is_plt();
	} else if((bb = find_bb(addr)) != NULL) {
		return !bb->is_dummy();
	}

	return false;
}

void 
CFG::store_function(ArmsFunction *fun) 
{
#ifdef DDEBUG_ASIA
	std::map<address_t, ArmsFunction *>::iterator it = functions.find(fun->get_base_addr());
	assert(it == functions.end());  
#endif 
	functions[fun->get_base_addr()] = fun; 
}

ArmsFunction* 
CFG::find_function(address_t base_address) 
{
	std::map<address_t, ArmsFunction *>::iterator it = functions.find(base_address);
	if (it == functions.end()) 
		return NULL; 

	return it->second; 
}

void 
CFG::mark_function_as_plt(address_t base_address) 
{
	ArmsFunction *fun = find_function(base_address);
	if (!fun) return;

	fun->set_is_plt();
}

static int
mark_function_if_at(ArmsFunction *f, void *arg)
{
	size_t i, j;
	ArmsBasicBlock *bb;
	CFG *cfg;

	cfg = (CFG*)arg;

	if(f->is_lib_dummy()) {
		/* Ignore lib dummies, these only have inbound PLT edges. */
		return 0;
	}

	for(i = 0; i < f->nentry_points(); i++) {
		bb = f->get_entry_point(i);
		for(j = 0; j < bb->incoming_edge_count(); j++) {
			if(bb->get_incoming_edge(j)->is_indirect()) {
				printf("Found function 0x%jx with address taken\n", f->get_base_addr());
				f->set_addr_taken();
				break;
			}
     	   	}
		if(f->addr_taken()) {
			break;
		}
	}

	return 0;
}

void
CFG::mark_at_functions()
{
    foreach_function(mark_function_if_at, this);
}

int
CFG::foreach_function(int (*callback)(ArmsFunction*, void*), void *arg)
{
    typedef std::map<address_t, ArmsFunction*>::iterator func_iter;

    int ret;
    func_iter iter;
    ArmsFunction *func;

    if(functions.size() < 1) {
        return 0;
    }

    for(iter = functions.begin(); iter != functions.end(); iter++) {
        func = iter->second;
        if((ret = callback(func, arg))) {
            return ret;
        }
    }

    return 0;
}

ArmsFunction*
CFG::create_dummy_function(address_t base_address)
{
	return create_dummy_function(string_format("%p", (void*)base_address), base_address);
}

ArmsFunction*
CFG::create_dummy_function(string funname, address_t base_address)
{
	ArmsFunction *fun = find_function(base_address); 
	if (fun) return fun; 

	fun = new ArmsFunction(base_address, string(funname.c_str()), this);
    fun->setMangledName(funname.c_str());
	store_function(fun);

	ArmsBasicBlock *bb = ArmsBasicBlock::create_dummy_basic_block(base_address, fun, this); 
	store_bb(bb);
	fun->add_entry_block(bb);
	fun->add_exit_block(bb); 

	return fun; 
}

ArmsFunction*
CFG::create_plt_function(string funname, address_t base_address)
{
	ArmsFunction *fun = create_dummy_function(funname, base_address);
	fun->set_is_plt();

	return fun; 
}

void 
CFG::store_bb(ArmsBasicBlock *bb) 
{
#ifdef DDEBUG_ASIA
	std::map<address_t, ArmsBasicBlock *>::iterator it = start2bb.find(bb->get_start_address());
	assert(it == start2bb.end()); 
#endif 
	start2bb[bb->get_start_address()] = bb;
	last2bb[bb->get_last_insn_address()] = bb;
	num_bb++; 		
}

ArmsFunction*
CFG::find_lib_dummy_by_name(std::string name)
{
    typedef std::map<address_t, ArmsFunction*>::iterator func_iter;

    func_iter iter;
    ArmsFunction *func;

    if(functions.size() < 1) {
        return NULL;
    }

    for(iter = functions.begin(); iter != functions.end(); iter++) {
        func = iter->second;
        if(!func->is_lib_dummy()) {
            continue;
        }
        if(!func->get_name().compare(name)) {
            return func;
        }
    }

    return NULL;
}

ArmsBasicBlock* 
CFG::find_bb(address_t start_address) 
{
	std::map<address_t, ArmsBasicBlock *>::iterator it = start2bb.find(start_address);
	if (it == start2bb.end()) 
		return NULL; 

	return it->second; 
}

ArmsBasicBlock* 
CFG::find_bb_by_last_insn_address(address_t last_address) 
{
	std::map<address_t, ArmsBasicBlock *>::iterator it = last2bb.find(last_address);
	if (it == last2bb.end()) 
		return NULL; 

	return it->second; 
}

ArmsEdge*
CFG::find_edge(address_t src, address_t dst)
{
	size_t i;
	ArmsBasicBlock *bb;
	ArmsEdge *e;

	if(!(bb = find_bb_by_last_insn_address(src))) {
		return NULL;
	}

	for(i = 0; i < bb->outgoing_edge_count(); i++) {
		e = bb->get_outgoing_edge(i);
		if(e->target()->get_start_address() == dst) {
			return e;
		}
	}

	return NULL;
}


void 
CFG::handle_interprocedural(ArmsBasicBlock *call_site, address_t call_target, arms_edge_type_t type)
{
	if (edge_type_is_direct_call(type)) {
		handle_interprocedural_call(call_site, call_target, type);
		return; 
	} 

	if (edge_type_is_indirect_call(type)) {
		handle_interprocedural_call(call_site, call_target, type);
		return; 
	}	

	if (edge_type_is_inter_direct_jmp(type)) {
		assert(0);
		//handle_interprocedural_jmp(call_site, call_target, type);
		return; 
	}

	if (edge_type_is_inter_indirect_jmp(type)) {
		assert(0);
		//handle_interprocedural_jmp(call_site, call_target, type);
		return; 
	}
}

void 
CFG::handle_interprocedural(ArmsFunction *caller, 
	address_t call_site, address_t call_target, arms_edge_type_t type)
{
#if 0 // XXX DROP
	if (edge_type_is_direct_call(type)) {
		handle_interprocedural_call(caller, call_site, call_target);
		return; 
	} 

	if (edge_type_is_indirect_call(type)) {
		handle_interprocedural_call(caller, call_site, call_target);
		return; 
	}	

	if (edge_type_is_inter_direct_jmp(type)) {
		handle_interprocedural_jmp(caller, call_site, call_target, type);
		return; 
	}

	if (edge_type_is_inter_indirect_jmp(type)) {
		handle_interprocedural_jmp(caller, call_site, call_target, type);
		return; 
	}
#endif 
}

void 
CFG::store_caller_and_callee(ArmsFunction *fun_caller, ArmsFunction **fun_callee_out, address_t call_target)
{
	ArmsFunction *fun_callee = find_function(call_target); 
	if (!fun_callee) {
		adebug_fprintf(stderr, "[XXX] handle_direct_interprocedural_edge: target fun at %p doesn't exist\n", (void*) call_target);
		fun_callee = create_dummy_function(call_target); 
	}
	fun_caller->add_callee(fun_callee); 
	fun_callee->add_caller(fun_caller); 

	*fun_callee_out = fun_callee; 
} 

	
void 
CFG::create_call_edge(ArmsFunction *fun_caller, ArmsFunction *fun_callee, 
	address_t call_site, address_t call_target, ArmsBasicBlock **bb_call_site_out, arms_edge_type_t type)
{
	ArmsBasicBlock *bb_call_site = find_bb_by_last_insn_address(call_site); 
	ArmsBasicBlock *bb_call_target = find_bb(call_target);
	
	*bb_call_site_out = bb_call_site; 

	if ((!bb_call_site) || (bb_call_site->get_function() != fun_caller)) {
		adebug_fprintf(stderr, "[XXX] create_call_edge: A problem with a bb ending@%p\n", (void*)call_site);
		return; 
	}
	if ((!bb_call_target) || (bb_call_target->get_function() != fun_callee)) {
		adebug_fprintf(stderr, "[XXX] create_call_edge: A problem with a bb starting@%p. bb_call_target: %p\n", (void*)call_target, (void*)bb_call_target);
		return; 
	}

	ArmsEdge *edge_call;
	edge_call = new ArmsEdge(bb_call_site, bb_call_target, type, this); 
	bb_call_site->add_outgoing_edge(edge_call); 
	if (edge_type_is_call(type)) { bb_call_site->drop_call_ft_edge(); }
	bb_call_target->add_incoming_edge(edge_call); 
}
	

void 
CFG::create_ret_edges(ArmsFunction *fun_caller, ArmsFunction *fun_callee, 
	address_t call_site, address_t call_target, ArmsBasicBlock *bb_call_site)
{
	std::set<ArmsBasicBlock*>* callee_exit_points = fun_callee->get_exit_points();
	std::set<ArmsBasicBlock*>::iterator callee_exit_points_iter; 

	address_t ret_target = bb_call_site->get_end_address();  
	ArmsBasicBlock *bb_ret_target = find_bb(ret_target); 
	if ((!bb_ret_target) || (bb_ret_target->get_function() != fun_caller)) {
		adebug_fprintf(stderr, "[XXX] create_ret_edge: A problem with a bb starting@%p, bb:%p\n", (void*)ret_target, (void*)bb_ret_target);
		return; 
	}

	adebug_assert(callee_exit_points->size() > 0);
	for (callee_exit_points_iter = callee_exit_points->begin(); 	
		callee_exit_points_iter != callee_exit_points->end(); callee_exit_points_iter++) {
		ArmsBasicBlock *bb_ret_site = *callee_exit_points_iter; 
		ArmsEdge *edge_ret = new ArmsEdge(bb_ret_site, bb_ret_target, arms_ret, this);
		bb_ret_site->add_outgoing_edge(edge_ret);
		bb_ret_target->add_incoming_edge(edge_ret); 
	}
}


void 
CFG::handle_interprocedural_jmp(ArmsFunction *fun_caller, 
	address_t call_site, address_t call_target, arms_edge_type_t type)
{
	/* Store caller and callee */
	ArmsFunction *fun_callee = NULL;
	store_caller_and_callee(fun_caller, &fun_callee, call_target);
	assert(fun_callee);

	/* Create call edge */
	ArmsBasicBlock *bb_call_site; 
	create_call_edge(fun_caller, fun_callee, call_site, call_target, &bb_call_site, type);
	if (fun_callee->is_plt()) {
		fun_caller->add_external_call(bb_call_site); 	
	}
}


void 
CFG::handle_interprocedural_call(ArmsFunction *fun_caller, address_t call_site, address_t call_target)
{
	/* Store caller and callee */
	ArmsFunction *fun_callee = NULL;
	store_caller_and_callee(fun_caller, &fun_callee, call_target);
	assert(fun_callee);

	/* Create call edge */
	ArmsBasicBlock *bb_call_site; 
	create_call_edge(fun_caller, fun_callee, call_site, call_target, &bb_call_site, arms_direct_call);
	if (fun_callee->is_plt()) {
		fun_caller->add_external_call(bb_call_site); 	
	}
	assert(bb_call_site); 
	
	/* Create ret edges */	
	if (! bb_call_site->is_exit_block()) {
		create_ret_edges(fun_caller, fun_callee, call_site, call_target, bb_call_site);
	}
}

void 
CFG::create_call_edge(ArmsBasicBlock *bb_call_site, address_t call_target, arms_edge_type_t type)
{
	ArmsBasicBlock *bb_call_target = find_bb(call_target);
	
	if (!bb_call_target) {
		adebug_fprintf(stderr, "[XXX] create_call_edge: A problem with a bb starting@%p. bb_call_target: %p\n", (void*)call_target, (void*)bb_call_target);
		return; 
	}

	ArmsEdge *edge_call = new ArmsEdge(bb_call_site, bb_call_target, type, this); 
	bb_call_site->add_outgoing_edge(edge_call); 
	bb_call_target->add_incoming_edge(edge_call); 
}

static void 
callback_create_ret_edges(ArmsFunction *fun_callee, ArmsBasicBlock *bb_ret_target) 
{
	std::set<ArmsBasicBlock*>* callee_exit_points = fun_callee->get_exit_points();
	std::set<ArmsBasicBlock*>::iterator callee_exit_points_iter = callee_exit_points->begin(); 

	for (; callee_exit_points_iter != callee_exit_points->end(); callee_exit_points_iter++) {
		ArmsBasicBlock *bb_ret_site = *callee_exit_points_iter; 
		ArmsEdge *edge_ret = new ArmsEdge(bb_ret_site, bb_ret_target, arms_ret, bb_ret_target->get_cfg());
		bb_ret_site->add_outgoing_edge(edge_ret);
		bb_ret_target->add_incoming_edge(edge_ret); 
	}
}
	
void 
CFG::create_ret_edges(ArmsBasicBlock *bb_call_site, address_t target) 
{
	address_t ret_target = bb_call_site->get_end_address();  
	ArmsBasicBlock *bb_ret_target = find_bb(ret_target); 
	if (!bb_ret_target) {
		adebug_fprintf(stderr, "[XXX] create_ret_edge: A problem with a bb starting@%p, bb:%p\n", (void*)ret_target, (void*)bb_ret_target);
		return; 
	}

	ArmsBasicBlock *bb_call_target = find_bb(target); 
	if (!bb_call_target) {
		adebug_fprintf(stderr, "[XXX] create_ret_edge: A problem with a bb starting@%p, bb:%p\n", (void*)target, (void*)bb_call_target);
		return; 
	}

	bb_call_target->foreach_function(callback_create_ret_edges, bb_ret_target);
}

static void 
callback_add_external_call(ArmsFunction *fun, ArmsBasicBlock *call_site) 
{
	fun->add_external_call(call_site); 
}

// XXX FILL CALLERS AND CALLES 
void 
CFG::handle_interprocedural_call(ArmsBasicBlock *call_site, address_t target, arms_edge_type_t type)
{
	/* Create call edge */
	create_call_edge(call_site, target, type);
	ArmsFunction *fun_callee = find_function(target); 
	if ((fun_callee) && (fun_callee->is_plt())) {
		call_site->foreach_function(callback_add_external_call, call_site);
	}

	/* Create ret edges for indirect calls. For direct ones they will be added by dyninst */	
	if ((edge_type_is_indirect(type)) && (!call_site->is_exit_block())) {
		create_ret_edges(call_site, target);
	}
}

void 
CFG::debug_check_if_cs_remains_unresolved(address_t insn_addr)
{
	ArmsBasicBlock *bb = find_bb_by_last_insn_address(insn_addr);
	if (!bb) {
		adebug_fprintf(stderr, "[XXX] debug_check_if_ct_remains_unresolved: cannot find a bb with %p\n", (void*)insn_addr);
		return; 
	} 

	if (bb->has_no_call_ft_outgoing_edge()) 
		return;

	adebug_fprintf(stderr, "[XXX] debug_check_if_ct_remains_unresolved: a call site at %p remains unresolved\n", (void*)insn_addr);
} 

ArmsEdge*
CFG::create_and_add_edge(address_t source, address_t target)
{
	ArmsBasicBlock *source_bb = find_bb(source);
	if (!source_bb) { 
		source_bb = new ArmsBasicBlock(source, source+1, source, this);
		store_bb(source_bb); 
	}

	ArmsBasicBlock *target_bb = find_bb(target);
	if (!target_bb) { 
		target_bb = new ArmsBasicBlock(target, target+1, target, this);
		store_bb(target_bb); 
	}

	ArmsEdge *edge = new ArmsEdge(source_bb, target_bb, this);
	source_bb->add_outgoing_edge(edge);
	target_bb->add_incoming_edge(edge);

	return edge;
}

ArmsEdge*
CFG::create_and_add_edge(ArmsBasicBlock *source, ArmsBasicBlock *target)
{
	if(!source || !target) {
		return NULL;
	}

	if(!find_bb(source->get_start_address())) {
		store_bb(source);
	}
	assert(find_bb(source->get_start_address())->equals_bb(source));

	if(!find_bb(target->get_start_address())) {
		store_bb(target);
	}
	assert(find_bb(target->get_start_address())->equals_bb(target));

	ArmsEdge *edge = new ArmsEdge(source, target, this);
	source->add_outgoing_edge(edge);
	target->add_incoming_edge(edge);

	return edge;
}

void 
CFG::compare_edges(CFG *other_cfg)
{
	adebug_fprintf(stderr, "CFG::compare_edges: %d <-> %d bbs\n", num_bb, other_cfg->num_bb); 

	std::set<address_t> bbs_union;
	std::set<address_t>::iterator set_it;
	address_t bb_addr;
	ArmsBasicBlock *this_bb, *other_bb;

	std::map<address_t, ArmsBasicBlock *>::iterator map_it;
	for (map_it = start2bb.begin(); map_it != start2bb.end(); map_it++) { 
		bbs_union.insert(map_it->first); 
	} 
	for (map_it = other_cfg->start2bb.begin(); map_it != other_cfg->start2bb.end(); map_it++) { 
		bbs_union.insert(map_it->first); 
	} 


	for (set_it = bbs_union.begin(); set_it != bbs_union.end(); set_it++) {
		bb_addr = *set_it;

		this_bb = find_bb(bb_addr);
		other_bb = other_cfg->find_bb(bb_addr);
		
		/* See if basic blocks match */
		if ((this_bb == NULL) && (other_bb != NULL)) {
			adebug_fprintf(stderr, "difference in BB: %p <-> %p\n", (void*)this_bb, 
				(other_bb) ? (void*)other_bb->get_start_address() : (void*)other_bb);  
			continue;
		} 
		if ((this_bb != NULL) && (other_bb == NULL)) {
			ArmsBasicBlock *preceding_bb = 0;
			if (this_bb->is_ft()) {
				preceding_bb = this_bb->get_preceding_bb(); 
				other_bb = other_cfg->find_bb(preceding_bb->get_start_address());
			}
			if (other_bb == NULL) {
				adebug_fprintf(stderr, "difference in BB: %p <-> %p\n", 
					(this_bb) ? (void*)this_bb->get_start_address() : (void*)this_bb, (void*)other_bb);  
			} 
			continue;
		}
		assert(this_bb);
		assert(other_bb); 

		/* See if edges match */ 
		this_bb->compare_edges(other_bb);	
	}	
	
}

size_t
CFG::count_edges()
{
	std::map<address_t, ArmsBasicBlock*>::iterator iter;
	ArmsBasicBlock *bb;
	size_t n;

	n = 0;
	for(iter = start2bb.begin(); iter != start2bb.end(); iter++) {
		bb = iter->second;
		n += bb->outgoing_edge_count();
	}

	return n;
}

size_t
CFG::count_edges_coarse_grained()
{
	std::map<address_t, ArmsBasicBlock*>::iterator iter;
	ArmsBasicBlock *bb;
	ArmsEdge *e;
	size_t i, n, m;

	n = 0;
	for(iter = start2bb.begin(); iter != start2bb.end(); iter++) {
		bb = iter->second;
		for(i = 0; i < bb->outgoing_edge_count(); i++) {
			e = bb->get_outgoing_edge(i);
			if(!edge_type_is_return(e->type())) {
				n++;
			}
		}
	}

	m = 0;
	for(iter = start2bb.begin(); iter != start2bb.end(); iter++) {
		bb = iter->second;
		for(i = 0; i < bb->outgoing_edge_count(); i++) {
			e = bb->get_outgoing_edge(i);
			if(edge_type_is_return(e->type())) {
				m++;
			}
		}
	}

	return n + (n*m);
}

void
CFG::count_ats(size_t *icall_sites, size_t *icall_targets, size_t *icall_edges)
{
	size_t i, j;
	std::map<address_t, ArmsFunction*>::iterator iter;
	std::set<uint64_t> src_ids, dst_ids;
	ArmsBasicBlock *bb;
	ArmsEdge *e;
	ArmsFunction *f;

	(*icall_sites) = 0;
	(*icall_targets) = 0;
	(*icall_edges) = 0;
	for(iter = functions.begin(); iter != functions.end(); iter++) {
		f = iter->second;
		if(f->is_lib_dummy()) {
			/* Don't count control transfers from PLT to library functions. */
			continue;
		}
		for(i = 0; i < f->nentry_points(); i++) {
			bb = f->get_entry_point(i);
			for(j = 0; j < bb->incoming_edge_count(); j++) {
				e = bb->get_incoming_edge(j);
				if(!e->is_indirect()) {
					continue;
				}
				(*icall_edges)++;
				src_ids.insert(e->source()->id());
				dst_ids.insert(e->target()->id());
			}
		}
	}

	(*icall_sites) = src_ids.size();
	(*icall_targets) = dst_ids.size();
}


CFG* 
load_cfg_from_file(const char* filename)
{
	CFG *cfg = new CFG(filename);

	FILE* stream = fopen(filename, "r" );
	if (!stream) return cfg;
	
	char line[256];  
	unsigned long source, target; 

	while(!feof(stream)) {
		if (!fgets(line, 256, stream)) continue;
		sscanf(line, "%p %p\n", (void**)(&source), (void**)(&target));
		cfg->create_and_add_edge(source, target);
	}

	fclose(stream); 

	return cfg; 
}
