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
#include <limits.h>

#include "BPatch.h"
#include "BPatch_addressSpace.h" 
#include "BPatch_process.h" 
#include "BPatch_object.h"
#include "BPatch_binaryEdit.h" 
#include "BPatch_function.h"
#include "BPatch_point.h"
#include "BPatch_flowGraph.h" 
#include "BPatch_memoryAccessAdapter.h"

#include "PatchCommon.h"
#include "PatchMgr.h"
#include "PatchModifier.h"

#include "Instruction.h"
#include "Operand.h"
#include "Expression.h"
#include "Visitor.h"
#include "Register.h"
#include "BinaryFunction.h"
#include "Immediate.h"
#include "Dereference.h"
#include "Parsing.h" 
#include "Edge.h"
#include "Symtab.h" 

#include <string>
#include <set>
#include <vector>  

using namespace std;
using namespace Dyninst;
using namespace Dyninst::PatchAPI;
using namespace Dyninst::ParseAPI;
using namespace Dyninst::SymtabAPI;
using namespace Dyninst::InstructionAPI;

#include "function.h"
#include "instPoint.h"

#include "env.h"
#include "defs.h"
#include "arms_utils.h"
#include "arms_instruction.h"
#include "arms_source_block.h" 
#include "arms_bb.h"
#include "arms_edge.h"
#include "arms_function.h"
#include "arms_cfg.h"
#include "arms_icall_resolver.h"

#include "arms_dyninst_cfg.h"

void 
DICFG::insert_functions_and_bbs(const CodeObject::funclist& funcs)
{
	CodeObject::funclist::iterator 	funcs_iter;
	PARSE_API_RET_BLOCKLIST::iterator blocks_iter;
	ParseAPI::Function *fun; 
	ParseAPI::Block *block; 
	ArmsFunction *arms_fun, *cf;
	ArmsBasicBlock *arms_block; 
	
	/* Create objects representing individual functions */  
	for(funcs_iter = funcs.begin(); funcs_iter != funcs.end(); funcs_iter++) {
		fun = *funcs_iter;
		if (find_function((address_t)fun->addr())) continue; 
		arms_fun = new ArmsFunction((address_t)fun->addr(), fun->name(), this);

//      fprintf(stderr,"- %s\n",fun->name().c_str());

        std::vector<BPatch_function *> bfuncs;
        image->findFunction( (address_t)fun->addr(), bfuncs );
        if (bfuncs.size() == 1) {
            arms_fun->setMangledName(bfuncs[0]->getMangledName());
        } else {
            arms_fun->setMangledName(fun->name());
        }
		store_function(arms_fun); 
	} 

	/* Insert their basic blocks; mark their start and end address, plus set 
     * all containing functions. */
	for(funcs_iter = funcs.begin(); funcs_iter != funcs.end(); funcs_iter++) {
		fun = *funcs_iter;
		arms_fun = find_function((address_t)fun->addr());

		//adebug_fprintf(stderr, "Adding %s\n", arms_fun->to_string().c_str());
		ParseAPI::Function::blocklist blocks = fun->blocks();
		for(blocks_iter = blocks.begin(); blocks_iter != blocks.end(); blocks_iter++) {
			block = *blocks_iter; 

			/* don't handle shared blocks multiple times */
			if (find_bb((address_t) block->start())) continue; 

			arms_block = new ArmsBasicBlock((address_t) block->start(), (address_t) block->end(),
				(address_t) block->last(), this);
            arms_block->set_parse_block(block);
			store_bb(arms_block); 

			/* add the containing functions */
			std::vector<ParseAPI::Function *> containing_funcs; 
			block->getFuncs(containing_funcs); 
			std::vector<ParseAPI::Function *>::iterator cf_iter = containing_funcs.begin();
			for ( ; cf_iter != containing_funcs.end(); cf_iter++) {
				cf = find_function((address_t)((*cf_iter)->addr()));
				arms_block->add_containing_function(cf);
				cf->add_bb(arms_block);
			} 
		} 
	} 

	/* Mark entry bbs and exit bbs */  
	for(funcs_iter = funcs.begin(); funcs_iter != funcs.end(); funcs_iter++) {
		fun = *funcs_iter;
		arms_fun = find_function((address_t)fun->addr());
		
		Block *entry_block = fun->entry(); 
		assert(entry_block); 
		ArmsBasicBlock *arms_entry_block = find_bb((address_t)entry_block->start());
		arms_entry_block->set_is_entry_block(); 
		arms_fun->add_entry_block(arms_entry_block);

		PARSE_API_RET_BLOCKLIST return_blocks = fun->returnBlocks();
		for(blocks_iter = return_blocks.begin(); blocks_iter != return_blocks.end(); blocks_iter++) {
			ArmsBasicBlock *arms_exit_block = find_bb((address_t)(*blocks_iter)->start());
			arms_exit_block->set_is_exit_block(); 
			arms_fun->add_exit_block(arms_exit_block);
		}   
	}
}


void 
DICFG::insert_edges(const CodeObject::funclist& funcs)
{
	CodeObject::funclist::iterator 	funcs_iter;
	ParseAPI::Function::blocklist::iterator	blocks_iter;
	ParseAPI::Block::edgelist::const_iterator	edges_iter;
	ParseAPI::Function *fun; 
	ParseAPI::Block *source_block, *target_block; 
	ParseAPI::Edge *edge; 
	ArmsFunction *arms_fun;  
	ArmsBasicBlock *arms_source_block, *arms_target_block; 
	ArmsEdge *arms_edge; 

	std::set<Address> seen; 

	for(funcs_iter = funcs.begin(); funcs_iter != funcs.end(); funcs_iter++) {
		fun = *funcs_iter;
		arms_fun = find_function((address_t)fun->addr());
		ParseAPI::Function::blocklist blocks = fun->blocks();
		
		cfg_building_fprintf(stderr, "Adding edges of %s\n", arms_fun->to_string().c_str());
		for(blocks_iter = blocks.begin(); blocks_iter != blocks.end(); blocks_iter++) {
			source_block = *blocks_iter; 
			arms_source_block = find_bb((address_t)(source_block->start()));

			/* don't handle shared blocks multiple times */
			if (seen.find(source_block->start()) != seen.end()) continue; 
			seen.insert(source_block->start());

			const ParseAPI::Block::edgelist& edges = source_block->targets(); 	
			//adebug_fprintf(stderr, "bb at %p has %d edges\n", source_block->start(), edges.size());  
			for(edges_iter = edges.begin(); edges_iter != edges.end(); edges_iter++) {
				edge = *edges_iter;
				if (edge->type() == CALL_FT) continue; 

				target_block = edge->trg(); 
		
				/* If it's an indirect call, we'll add the return edge separately */
				if ((edge->type() == RET) && (target_block->start() == (Address) -1)) continue; 

				arms_target_block = (target_block->start() == (Address) -1) ? 
					0 : find_bb((address_t)target_block->start());  

				//adebug_fprintf(stderr, "\ttarget: %p, %s\n", (void*)target_block->start(), ParseAPI::format(edge->type()).c_str());  

				/* an indirect call - see if we have data from LLVM to help */
				if ((! arms_target_block) && (edge->type() == CALL)) {
					std::vector<void*> targets;
					int ret = arms_icall_resolver((void*)(source_block->last()), targets);
					adebug_fprintf(stderr, "indirect cf transfer at %p. targets: %lu\n", (void*)source_block->last(),
						(unsigned long) targets.size());
					for (unsigned i = 0; i < targets.size(); i++) {
						handle_interprocedural(arms_source_block, (address_t)targets[i], arms_indirect_call);
					}
					if (targets.size() > 0) {
						continue; 
					}
				}

				if (!arms_target_block) { 
					arms_target_block = ArmsBasicBlock::create_dummy_basic_block(arms_fun, this);
					if (!arms_fun->is_plt()) 
						adebug_fprintf(stderr, "[XXX] indirect unresolved transfer at %p\n", (void*)source_block->last()); 
				}

				// XXX if it's an interprocedural edge, call handle_interprocedural 
				// XXX call add_edge or so 
				arms_edge = new ArmsEdge(arms_source_block, arms_target_block, this); 
				copy_edge_type(arms_edge, edge, (target_block->start() == (Address) -1)); 
				arms_source_block->add_outgoing_edge(arms_edge);
				arms_target_block->add_incoming_edge(arms_edge);

				cfg_building_fprintf(stderr, "\t%s\n", arms_edge->to_string().c_str());
			}
		} 
	}
}

void
DICFG::copy_edge_type(ArmsEdge *arms_edge, ParseAPI::Edge *edge, bool indirect)
{
	arms_edge_type_t type; 

	switch(edge->type()) {
		case CALL:
			type = (indirect) ? arms_indirect_call : arms_direct_call;   
			arms_edge->set_type(type);  
			break; 
		
		case COND_TAKEN:
			arms_edge->set_type(arms_cond_taken); 
			break; 

		case COND_NOT_TAKEN:
			arms_edge->set_type(arms_cond_not_taken); 
			break; 

		case INDIRECT:
			type = (edge->interproc()) ?  arms_inter_indirect_jmp : arms_indirect_jmp;   
			arms_edge->set_type(type); 
			break; 

		case DIRECT:
			type = (edge->interproc()) ?  arms_inter_direct_jmp : arms_direct_jmp;   
			arms_edge->set_type(type); 
			break; 

		case FALLTHROUGH:
			arms_edge->set_type(arms_fallthrough); 
			break; 

		case CATCH:
			arms_edge->set_type(arms_catch); 
			break; 

		case CALL_FT:
			arms_edge->set_type(arms_call_ft); 
			break; 

		case RET: 
			arms_edge->set_type(arms_ret); 
			break; 

		default:
			assert(0);
	} 
}

Expression::Ptr DICFG::the_pc = Expression::Ptr(new RegisterAST(MachRegister::getPC(Arch_x86_64)));

void
DICFG::insert_functions(std::vector<BPatch_function *> *funcs)
{
	std::vector<BPatch_function *>::iterator funcs_iter; 

	/* Create ArmsFunction objects of individual functions */
	BPatch_function *bp_fun;
	ArmsFunction *arms_fun;  
	//vector<ArmsFunctionWithAddress *> ordered_funcs; 
	for(funcs_iter = funcs->begin(); funcs_iter != funcs->end(); funcs_iter++) {
		bp_fun = *funcs_iter; 
		if (find_function((address_t)(bp_fun->getBaseAddr()))) continue;  
		arms_fun = new ArmsFunction((address_t)(bp_fun->getBaseAddr()), bp_fun->getName(), this); 
        arms_fun->setMangledName(bp_fun->getMangledName());
		store_function(arms_fun); 
		//ordered_funcs.push_back(arms_fun);
	}
#if 0
	std::sort(ordered_funcs.begin(), ordered_funcs.end(), ArmsFunctionWithAddress::arms_function_with_address_compare);
	ArmsFunctionWithAddress *prev_fun; 
	for(unsigned int i = 1; i < ordered_funcs.size(); i++) {
		prev_fun = ordered_funcs[i-1]; 
		prev_fun->set_end_address(ordered_funcs[i]->get_start_address());
		prev_fun->assert_range(); 
	} 	
#endif 


	/* Insert CFGs of individual functions. */
	for(funcs_iter = funcs->begin(); funcs_iter != funcs->end(); funcs_iter++) {
		insert_intraprocedural_function_flow_graph(*funcs_iter); 	
		set_entry_and_exit_points_of_function(*funcs_iter); 
	}
}

/* Insert a new function object, and create its flow graph. 
 * At this stage, we don't connect it to other functions/modules yet. */
void 
DICFG::insert_intraprocedural_function_flow_graph(BPatch_function *bp_fun) 
{
	PatchFunction 		*pfun = PatchAPI::convert(bp_fun);
	BPatch_flowGraph 	*bp_fg;

	std::set<BPatch_basicBlock*> bp_bbs; 
	std::set<BPatch_basicBlock*>::iterator bp_bbs_iter; 
	BPatch_basicBlock *bp_block; 

	ArmsFunction	*arms_fun; 
	ArmsBasicBlock	*arms_block, *arms_block_source, *arms_block_target; 
	ArmsEdge		*arms_edge; 

	adebug_fprintf(stderr, "\nFun %s has %ld bbs\n", bp_fun->getName().c_str(), (long) pfun->blocks().size());
	
	arms_fun = find_function((address_t)bp_fun->getBaseAddr());
 	
	if (!(bp_fg = bp_fun->getCFG())) return;  
	bp_fg->getAllBasicBlocks(bp_bbs);

	/* Debug */
#if 0
	if ((bp_fun->getBaseAddr() == (void*)0x4057b0) || 
		(bp_fun->getBaseAddr() == (void*)0x405700)) 
	{

	for (bp_bbs_iter = bp_bbs.begin(); bp_bbs_iter != bp_bbs.end(); bp_bbs_iter++) {
		bp_block = *bp_bbs_iter; 	
		adebug_fprintf(stderr, "BB[%p, %p): ", (void*)bp_block->getStartAddress(), (void*)bp_block->getEndAddress());

		std::vector<BPatch_edge*> bp_edges; 
		std::vector<BPatch_edge*>::iterator bp_edges_iter; 
		BPatch_edge *bp_edge; 

		bp_block->getOutgoingEdges(bp_edges);

		for(bp_edges_iter = bp_edges.begin(); bp_edges_iter != bp_edges.end(); bp_edges_iter++) {
			bp_edge = *bp_edges_iter; 	
			adebug_fprintf(stderr, "-> %p, ", (void*)bp_edge->getTarget()->getStartAddress());
		} 
		adebug_fprintf(stderr, "\n");
	}

	}
#endif 

	/* 1. Insert all basic blocks. Mark all entry and exits ones. */
	for (bp_bbs_iter = bp_bbs.begin(); bp_bbs_iter != bp_bbs.end(); bp_bbs_iter++) {
		bp_block = *bp_bbs_iter; 
		if (find_bb((address_t) bp_block->getStartAddress())) continue; 
#if 0
		if (! arms_fun->basic_block_in_range((address_t) bp_block->getStartAddress(), 
			(address_t) bp_block->getEndAddress())) {
			adebug_fprintf(stderr, "bb at %p doesn't belong to fun at %p\n", 
				(address_t)bp_block->getStartAddress(), (address_t)arms_fun->get_start_address());
			continue;  
		}
#endif 

		arms_block = new ArmsBasicBlock(
			(address_t) bp_block->getStartAddress(), (address_t) bp_block->getEndAddress(),
			(address_t) bp_block->getLastInsnAddress(), arms_fun, this); 
        arms_block->set_bpatch_block(bp_block);
		arms_block->set_if_entry_block(bp_block->isEntryBlock());
		arms_block->set_if_exit_block(bp_block->isExitBlock());
		store_bb(arms_block); 
	}


	/* 2. Connect basic blocks within this function. */
	for (bp_bbs_iter = bp_bbs.begin(); bp_bbs_iter != bp_bbs.end(); bp_bbs_iter++) {
		bp_block = *bp_bbs_iter; 	
#if 0
		if (! arms_fun->basic_block_in_range((address_t) bp_block->getStartAddress(), 
			(address_t) bp_block->getEndAddress()))
			continue;  
#endif 

		arms_block_source = find_bb((address_t)(bp_block->getStartAddress())); 	
		
		std::vector<BPatch_edge*> bp_edges; 
		std::vector<BPatch_edge*>::iterator bp_edges_iter; 
		BPatch_edge *bp_edge; 

		bp_block->getOutgoingEdges(bp_edges);
		//adebug_fprintf(stderr, "Adding %d outgoing edges of %s\n", (int)bp_edges.size(), arms_block_source->to_string().c_str());

		for(bp_edges_iter = bp_edges.begin(); bp_edges_iter != bp_edges.end(); bp_edges_iter++) {
			bp_edge = *bp_edges_iter; 	
			arms_block_target = find_bb((address_t)(bp_edge->getTarget()->getStartAddress())); 	

#if 0
			address_t target_block_start_addr = (address_t)(bp_edge->getTarget()->getStartAddress());
			address_t target_block_end_addr = (address_t)(bp_edge->getTarget()->getEndAddress());
			bool intra = (arms_block_source->get_function())->basic_block_in_range(
				target_block_start_addr, target_block_end_addr);
#endif 

			if (!arms_block_source || !arms_block_target) {
				adebug_fprintf(stderr, "[XXX] Source or target of an edge is missing!\n");
				continue; 
			} 
			if (arms_block_source->forward_connected_with(arms_block_target)) 
				continue;

			bool intra = (arms_block_source->get_function() == arms_block_target->get_function());

			arms_edge = new ArmsEdge(arms_block_source, arms_block_target, this); 
			copy_edge_type(arms_edge, bp_edge, intra); 
			
			arms_block_source->add_outgoing_edge(arms_edge);
			arms_block_target->add_incoming_edge(arms_edge);
		}
	}

}

void 
DICFG::copy_edge_type(ArmsEdge *arms_edge, BPatch_edge *bp_edge, bool intraprocedural) 
{
	Dyninst::ParseAPI::Edge* edge;
	edge = ParseAPI::convert(bp_edge);

	switch (edge->type()) {
		case ParseAPI::CALL:
			arms_edge->set_type(arms_direct_call); // XXX direct or indirect?  
			adebug_assert(0); 	
			break; 
		case ParseAPI::COND_TAKEN:
			arms_edge->set_type(arms_cond_taken); 
			if (!intraprocedural) adebug_assert(0);  
			break; 
		case ParseAPI::COND_NOT_TAKEN:
			arms_edge->set_type(arms_cond_not_taken); 
			if (!intraprocedural) adebug_assert(0);  
			break; 
		case ParseAPI::INDIRECT:
			arms_edge->set_type(arms_indirect_jmp); 
			if (!intraprocedural) adebug_assert(0);  
			break; 
		case ParseAPI::DIRECT:
			arms_edge->set_type((intraprocedural) ? arms_direct_jmp : arms_inter_direct_jmp); 
			break; 
		case ParseAPI::FALLTHROUGH:
			arms_edge->set_type(arms_fallthrough); 
			if (!intraprocedural) adebug_assert(0);  
			break; 
		case ParseAPI::CATCH:
			arms_edge->set_type(arms_catch); 
			if (!intraprocedural) adebug_assert(0);  
			break; 
		case ParseAPI::CALL_FT:        // fallthrough after call instruction
			arms_edge->set_type(arms_call_ft); 
			if (!intraprocedural) adebug_assert(0);  
			break; 
		case ParseAPI::RET:
			arms_edge->set_type(arms_ret); 
			adebug_assert(0); 	
			break; 
		case ParseAPI::NOEDGE:
			arms_edge->set_type(arms_no_edge); 
			break; 
		case ParseAPI::_edgetype_end_:
			arms_edge->set_type(arms_unknown); 
			break; 
		default: 
			arms_edge->set_type(arms_unknown); 
			break; 
	}
} 


void 
DICFG::set_entry_and_exit_points_of_function(BPatch_function *bp_fun)
{
	ArmsFunction *arms_fun = find_function((address_t)bp_fun->getBaseAddr()); 
	assert(arms_fun); 

	/* Entry points */
	BPatch_Vector<BPatch_point *> entry_points;
	BPatch_Vector<BPatch_point *>::iterator entry_points_iter;
	address_t entry_address;

	bp_fun->getEntryPoints(entry_points);
	for(entry_points_iter = entry_points.begin(); entry_points_iter != entry_points.end(); entry_points_iter++) {
		entry_address = (address_t)(*entry_points_iter)->getAddress(); 
		arms_fun->debug_confirm_entry_block(entry_address);
		arms_fun->add_entry_block(entry_address); 
	}

	/* Exit points */
	BPatch_Vector<BPatch_point *> exit_points;
	BPatch_Vector<BPatch_point *>::iterator exit_points_iter;
	address_t exit_address;

	bp_fun->getExitPoints(exit_points);
	for(exit_points_iter = exit_points.begin(); exit_points_iter != exit_points.end(); exit_points_iter++) {
		exit_address = (address_t)(*exit_points_iter)->getAddress(); 
		arms_fun->debug_confirm_exit_block(exit_address);
		arms_fun->add_exit_block(exit_address); 
	}
} 


void 
DICFG::insert_plt_entries(Symtab *symtab)
{
	vector<SymtabAPI::relocationEntry> fbt;
	vector<SymtabAPI::relocationEntry>::iterator fbt_iter;

	bool result = symtab->getFuncBindingTable(fbt);
	if (!result)
		return;	

	for (fbt_iter = fbt.begin(); fbt_iter != fbt.end(); fbt_iter++) {
		adebug_fprintf(stderr, "insert_plt_entries: %p -> %s\n", (void*)((*fbt_iter).target_addr()), (*fbt_iter).name().c_str());
		create_plt_function((*fbt_iter).name(), (address_t)((*fbt_iter).target_addr()));
	}

}

void 
DICFG::insert_interprocedural_edges(std::vector<BPatch_function *> *funcs)
{
	std::vector<BPatch_function *>::iterator funcs_iter; 

	for(funcs_iter = funcs->begin(); funcs_iter != funcs->end(); funcs_iter++) {
		BPatch_function *bp_fun = *funcs_iter; 
		ArmsFunction *arms_fun = find_function((address_t)bp_fun->getBaseAddr()); 
		assert(arms_fun); 

		BPatch_Vector<BPatch_point *> call_points;
		BPatch_Vector<BPatch_point *>::iterator call_points_iter;
		bp_fun->getCallPoints(call_points);	
		for(call_points_iter = call_points.begin(); call_points_iter != call_points.end(); call_points_iter++) {
			insert_interprocedural_edge(arms_fun, *call_points_iter);
		}
	}
}

void
DICFG::insert_interprocedural_edge(ArmsFunction *arms_fun, BPatch_point *call_point)
{
	/* Check if it's a call or a jmp */
	BPatch_basicBlock* call_bb = call_point->getBlock();
	if (!call_bb) {
		adebug_fprintf(stderr, "\t[XXX] DICFG::insert_interprocedural_edge: call_bb = NULL\n");  
		return; 
	}

	std::vector<std::pair<Instruction::Ptr, Dyninst::Address> > insns;
	std::vector<std::pair<Instruction::Ptr, Dyninst::Address> >::reverse_iterator insns_iter;
	Instruction::Ptr call_insn;
	call_bb->getInstructions(insns);
	for(insns_iter = insns.rbegin(); insns_iter != insns.rend(); insns_iter++) {
		if (insns_iter->second == ((Address)call_point->getAddress())) {
			call_insn = insns_iter->first; 
			break; 
		}
	}
	if (!call_insn) {
		adebug_fprintf(stderr, "\t[XXX] DICFG::insert_interprocedural_edge: call_insn = NULL\n");  
		return; 
	}
	bool call = (call_insn->getCategory() == c_CallInsn);
	
	/* direct */
	BPatch_function *bp_called_fun = call_point->getCalledFunction(); 
	if (bp_called_fun) {
		adebug_fprintf(stderr, "\ninsert_interprocedural_edge(%p@%p) -> %p <- direct\n", 
			(void*)arms_fun->get_base_addr(), (void*)call_point->getAddress(), (void*)(bp_called_fun->getBaseAddr())); 
		arms_edge_type_t type = (call) ? arms_direct_call : arms_inter_direct_jmp; 
		handle_interprocedural(arms_fun, (address_t)call_point->getAddress(), 
			(address_t)(bp_called_fun->getBaseAddr()), type); 
		return;
	} 

	/* indirect or rip-relative */
	Expression::Ptr target_expr; 
	address_t target; 
       	std::vector<void*> targets;
       	int ret;

	target_expr = call_insn->getControlFlowTarget(); 
	target_expr->bind(the_pc.get(), Result(u64, (Address)call_point->getAddress())); 
	Result res = target_expr->eval(); 
	if (!res.defined) {
		adebug_fprintf(stderr, "\ninsert_interprocedural_edge(%p@%p) -> %s (undefined) <- indirect\n", 
			(void*)arms_fun->get_base_addr(), (void*)call_point->getAddress(), target_expr->format().c_str());
		arms_edge_type_t type = (call) ? arms_indirect_call : arms_inter_indirect_jmp; 
		ret = arms_icall_resolver((void*)call_point->getAddress(), targets);
		if (ret < 0) {
			adebug_fprintf(stderr, "\nWarning: error retrieving icall data, resorting to default target!\n");
			targets.push_back((void*)arms_fun->get_base_addr());
		}
		for (unsigned i=0;i<targets.size();i++) {
			target = (address_t) targets[i];
                       	handle_interprocedural(arms_fun, (address_t)call_point->getAddress(), target, type);
               	}
	} else {
		target = (address_t)(res.convert<Address>());
		adebug_fprintf(stderr, "\ninsert_interprocedural_edge(%p@%p) -> %p (%s) <- direct, RIP relative\n", 
			(void*)arms_fun->get_base_addr(), (void*)call_point->getAddress(), 
			(void*)target, target_expr->format().c_str()); 
		arms_edge_type_t type = (call) ? arms_direct_call : arms_inter_direct_jmp; 
		handle_interprocedural(arms_fun, (address_t)call_point->getAddress(), target, type); 
	}

}


void 
DICFG::analyze_unresolved_control_transfers(std::vector<BPatch_function *> *funcs) 
{
	std::vector<BPatch_function *>::iterator funcs_iter; 

	/* Look at the unresolved control transfers */
	for(funcs_iter = funcs->begin(); funcs_iter != funcs->end(); funcs_iter++) {
		BPatch_function *bp_fun = *funcs_iter; 

		BPatch_Vector<BPatch_point *> unresolvedCFs;
		BPatch_Vector<BPatch_point *>::iterator unresolved_iter; 
		BPatch_point *unresolved_point;
		
		address_t unresolved_instr_addr;

		bp_fun->getUnresolvedControlTransfers(unresolvedCFs);
		for (unresolved_iter = unresolvedCFs.begin(); unresolved_iter != unresolvedCFs.end(); unresolved_iter++) {
			unresolved_point = *unresolved_iter;
			unresolved_instr_addr = (address_t) (unresolved_point->getAddress());

			debug_check_if_cs_remains_unresolved(unresolved_instr_addr); 
		}

#if 0
		Instruction::Ptr unresolved_insn; 
		InsnCategory unresolved_category;


		for (unresolved_iter = unresolvedCFs.begin(); unresolved_iter != unresolvedCFs.end(); unresolved_iter++) {
			unresolved_point = *unresolved_iter;
			unresolved_insn = unresolved_point->getInsnAtPoint(); 	
			if (!unresolved_insn) {
				adebug_fprintf(stderr,  "[XXX] getUnresolvedControlTransfers: an insn at point %p is missing\n", (void*)(unresolved_point->getAddress()));			
				continue;
			}

			unresolved_category = unresolved_insn->getCategory(); 
			if ((unresolved_category == c_CallInsn) || (unresolved_category == c_ReturnInsn) || 
				(unresolved_category == c_SysEnterInsn)) {
				adebug_fprintf(stderr, "[XXX] getUnresolvedControlTransfers: HANDLE ME!\n");
			}
		}
#endif 
	}
}


static DICFG* 
try_ParseAPI(BPatch_addressSpace *handle, int index)
{
	SymtabCodeSource *sts;
	CodeObject *co;

	std::vector<BPatch_object*> objs;
	handle->getImage()->getObjects(objs);
	assert(objs.size() > 0);
            
    string bin = objs[index]->pathName();

	DICFG *parse_cfg = new DICFG(bin.c_str()); 
    
    parse_cfg->handle = handle;
	parse_cfg->image  = handle->getImage();

	// Create a new binary object 
	sts 	= new SymtabCodeSource((char*)bin.c_str());
	co 		= new CodeObject(sts);


	// Parse the binary 
	co->parse(); 

	/* Parse the functions found by the BPatch API */
	BPatch_image *image = handle->getImage();
	std::vector<BPatch_module *> *mods = image->getModules();
	std::vector<BPatch_module *>::iterator mods_iter; 
	for (mods_iter = mods->begin(); mods_iter != mods->end(); mods_iter++) {
		address_t mod_start = (address_t)(*mods_iter)->getBaseAddr();
		address_t mod_end   = (address_t)(*mods_iter)->getBaseAddr() + (*mods_iter)->getSize();
		if((parse_cfg->get_start_addr() == 0) || (mod_start < parse_cfg->get_start_addr())) {
			parse_cfg->set_start_addr(mod_start);
		}
		if((parse_cfg->get_end_addr() == 0) || (mod_end > parse_cfg->get_end_addr())) {
			parse_cfg->set_end_addr(mod_end);
		}

		std::vector<BPatch_function *> *funcs = (*mods_iter)->getProcedures(false); 
		std::vector<BPatch_function *>::iterator funcs_iter = funcs->begin();
		for(; funcs_iter != funcs->end(); funcs_iter++) {
			co->parse((Address)(*funcs_iter)->getBaseAddr(), true);
		} 
	}

	/* Parse PLT entries */
	Symtab *symtab	= Symtab::findOpenSymtab(string(bin.c_str()));
	vector<SymtabAPI::relocationEntry> fbt;
	vector<SymtabAPI::relocationEntry>::iterator fbt_iter;
	symtab->getFuncBindingTable(fbt);

	for (fbt_iter = fbt.begin(); fbt_iter != fbt.end(); fbt_iter++) {
		co->parse((Address)((*fbt_iter).target_addr()), true);
	}

	const CodeObject::funclist& funcs = co->funcs();
	
	parse_cfg->insert_functions_and_bbs(funcs);		
	for (fbt_iter = fbt.begin(); fbt_iter != fbt.end(); fbt_iter++) {
		address_t plt_fun_addr = (address_t)(*fbt_iter).target_addr();

		if((parse_cfg->get_start_addr() == 0) || (plt_fun_addr < parse_cfg->get_start_addr())) {
			parse_cfg->set_start_addr(plt_fun_addr);
		}
		if((parse_cfg->get_end_addr() == 0) || (plt_fun_addr > parse_cfg->get_end_addr())) {
			parse_cfg->set_end_addr(plt_fun_addr);
		}

		parse_cfg->mark_function_as_plt(plt_fun_addr);
	}

	parse_cfg->insert_edges(funcs);


	return parse_cfg; 
}


static DICFG*
try_ParseAPI_deprecated(const char *bin, const char **argv)
{
	BPatch bpatch;
	BPatch_addressSpace *handle = NULL;
	if (! getenv("RT_EDIT")) {
		handle = bpatch.openBinary(bin);
	} else {
		handle = bpatch.processCreate(bin, argv);
	}

	return try_ParseAPI(handle, 0);
}


void
dyninst_analyze_address_taken(BPatch_addressSpace *handle, DICFG *cfg)
{
	/* XXX: this is currently a /very/ simple address-taken analysis.
         * It looks for instruction operands that correspond to known function addresses,
         * and then marks these functions as having their address taken. In particular, we
         * do /not/ look for function pointers stored in (static) memory, or for function
         * pointers that are computed at runtime. 
	 * !!!!!!! This analysis is good enough for testing, but /not/ for production! !!!!!!! */

	SymtabCodeSource *sts;
	CodeObject *co;

	std::vector<BPatch_object*> objs;
	handle->getImage()->getObjects(objs);
	assert(objs.size() > 0);
	const char *bin = objs[0]->pathName().c_str();

	// Create a new binary object 
	sts 	= new SymtabCodeSource((char*)bin);
	co 	= new CodeObject(sts);

	// Parse the binary 
	co->parse(); 

	BPatch_image *image = handle->getImage();
	std::vector<BPatch_module *> *mods = image->getModules();
	std::vector<BPatch_module *>::iterator mods_iter; 
	for (mods_iter = mods->begin(); mods_iter != mods->end(); mods_iter++) {
		std::vector<BPatch_function *> *funcs = (*mods_iter)->getProcedures(false); 
		std::vector<BPatch_function *>::iterator funcs_iter = funcs->begin();
		for(; funcs_iter != funcs->end(); funcs_iter++) {
			co->parse((Address)(*funcs_iter)->getBaseAddr(), true);
			BPatch_flowGraph *fg = (*funcs_iter)->getCFG();
			std::set<BPatch_basicBlock*> blocks;
			fg->getAllBasicBlocks(blocks);
			std::set<BPatch_basicBlock*>::iterator block_iter;
			for (block_iter = blocks.begin(); block_iter != blocks.end(); ++block_iter) {
				BPatch_basicBlock *block = (*block_iter);
				std::vector<Instruction::Ptr> insns;
				block->getInstructions(insns);
				std::vector<Instruction::Ptr>::iterator insn_iter;
				for (insn_iter = insns.begin(); insn_iter != insns.end(); ++insn_iter) {
					Instruction::Ptr ins = *insn_iter;
					std::vector<Operand> ops;
					ins->getOperands(ops);
					std::vector<Operand>::iterator op_iter;
					for (op_iter = ops.begin(); op_iter != ops.end(); ++op_iter) {
						Expression::Ptr expr = (*op_iter).getValue();

						struct OperandAnalyzer : public Dyninst::InstructionAPI::Visitor {
							virtual void visit(BinaryFunction* op) {};
							virtual void visit(Dereference* op) {}
							virtual void visit(Immediate* op) {
								address_t addr;
								ArmsFunction *func;
								switch(op->eval().type) {
								case s32:
									addr = op->eval().val.s32val;
									break;
								case u32:
									addr = op->eval().val.u32val;
									break;
								case s64:
									addr = op->eval().val.s64val;
									break;
								case u64:
									addr = op->eval().val.u64val;
									break;
								default:
									return;
								}
								func = cfg_->find_function(addr);
								if(func) {
									printf("Instruction [%s] references function 0x%jx\n", ins_->format().c_str(), addr);
									func->set_addr_taken();
								}
							}
							virtual void visit(RegisterAST* op) {}
							OperandAnalyzer(DICFG *cfg, Instruction::Ptr ins) {
								cfg_ = cfg;
								ins_ = ins;
							};
							DICFG *cfg_;
							Instruction::Ptr ins_;
						};

						OperandAnalyzer oa(cfg, ins);
						expr->apply(&oa);
					}
				}
			}
		} 
	}
}


void
dyninst_analyze_address_taken_deprecated(const char*bin, const char **argv, DICFG *cfg)
{
	BPatch bpatch;
	BPatch_addressSpace *handle = NULL;
	if (! getenv("RT_EDIT")) {
		handle = bpatch.openBinary(bin);
	} else {
		handle = bpatch.processCreate(bin, argv);
	}

	return dyninst_analyze_address_taken(handle, cfg);
}


DICFG*
dyninst_build_cfg(BPatch_addressSpace *handle, int index)
{
	DICFG *cfg = try_ParseAPI(handle, index);
	return cfg;
}


DICFG* 
dyninst_build_cfg_deprecated(const char *bin, const char **argv)
{

	//CFG* ida_cfg = load_cfg_from_file("/home/asia/vu/armors/code/patharmor/cfg/nginx-edges.txt");

	DICFG *cfg =  try_ParseAPI_deprecated(bin, argv); 
	//cfg->compare_edges(ida_cfg); 

	return cfg;  		

}

