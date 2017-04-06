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

#include "PatchCommon.h"
#include "PatchMgr.h"
#include "PatchModifier.h"

#include "Visitor.h"

using namespace std;
using namespace Dyninst;
using namespace Dyninst::PatchAPI;
using namespace Dyninst::ParseAPI;
using namespace Dyninst::InstructionAPI;
using namespace Dyninst::SymtabAPI;

#include "defs.h" 
#include "arms_bb.h"
#include "arms_edge.h" 
#include "arms_function.h" 
#include "arms_liveness.h"

#include <liveness.h>

#define DEBUG
//#define DDEBUG

/* Possible strategy types */
#define STRATEGY_CONSERVATIVE      1
#define STRATEGY_RECURSIVE         2
#define STRATEGY_CONCLUSIVE        3

#define ALLOW_UNINITIALIZED_READ

// TODO this is really TOO conservative...
//#define CONSERVATIVE_CALLSITE

/* Possible options for conservative strategy */
#define STRATEGY_CON_OPT_EXPECT_2ND_RETVAL  0x01
#define STRATEGY_CON_OPT_2                  0x02

/* Possible options for recursive strategy */
#define STRATEGY_REC_OPT_1            0x01
#define STRATEGY_REC_OPT_2            0x02
#define STRATEGY_REC_OPT_3            0x04


/* Strategy type and option */
//#define STRATEGY_TYPE       STRATEGY_RECURSIVE
#define STRATEGY_TYPE       STRATEGY_CONCLUSIVE
#define STRATEGY_OPTIONS    STRATEGY_CON_OPT_EXPECT_2ND_RETVAL



#ifdef DEBUG
#define  dprintf(...) fprintf(stderr, __VA_ARGS__)
#else
#define dprintf(...) void()
#endif

#ifdef DDEBUG
#define ddprintf(...) fprintf(stderr, __VA_ARGS__)
#else
#define ddprintf(...) void()
#endif

struct OperandType : public InstructionAPI::Visitor {
    virtual void visit(InstructionAPI::BinaryFunction *) { binaryFunction = true; }
    virtual void visit(InstructionAPI::Dereference *)    { dereference    = true; } 
    virtual void visit(InstructionAPI::Immediate *)      { immediate      = true; }
    virtual void visit(InstructionAPI::RegisterAST* )    { registerAST    = true; }
    OperandType(): binaryFunction(false), 
                      dereference(false), 
                        immediate(false),
                      registerAST(false) {};
    bool binaryFunction,
         dereference,
         immediate,
         registerAST;
};


/*********************************** ARMS REGISTER ***********************************/

string ArmsRegister::getStateName(StateType state) {
    switch(state) {
        case IA64_READ:  return "read ";
        case IA64_WRITE: return "write";
        case IA64_RW:    return "r/w  ";
        case IA64_CLEAR: return "clear";
        default: {
                     dprintf("WTF: %d\n", state);
                     return "unkown";
                 };
    }
}

void ArmsRegister::setDeref(ArmsBasicBlock *block, unsigned long offset) {
    deref_block_list[block][offset] = true;
}

void ArmsRegister::setState(ArmsBasicBlock *block, unsigned long offset, StateType state) {
//  dprintf("setState(%p, %p, %d) (this: %p)\n", block, (void *) offset, state, this);

    /* An instruction can read and write to the same register. */ 
    if ((block_list[block][offset] == IA64_READ  && state == IA64_WRITE) || 
        (block_list[block][offset] == IA64_WRITE && state == IA64_READ)) {
        block_list[block][offset] = IA64_RW;
    } else {
        block_list[block][offset] = state;
    }


}
void ArmsRegister::setRead(ArmsBasicBlock *block, unsigned long offset) {
    setState(block, offset, IA64_READ);
}
void ArmsRegister::setWrite(ArmsBasicBlock *block, unsigned long offset) {
    setState(block, offset, IA64_WRITE);
}

bool ArmsRegister::writtenInBlock(ArmsBasicBlock *block) {
    StateType reg_state;

    for (state_it_type it  = block_list[block].begin();
                       it != block_list[block].end();
                       it++) {
        unsigned long insn_offset = it->first;
        reg_state = it->second;

        if (reg_state == IA64_WRITE || reg_state == IA64_RW) return true;
    }

    return false;
}

bool ArmsRegister::writtenInBlocks(std::set<ArmsBasicBlock *> blocks) {

    for (std::set<ArmsBasicBlock *>::iterator it  = blocks.begin();
                                              it != blocks.end();
                                              it++) {
        ArmsBasicBlock *block = *it;
        if (writtenInBlock(block)) return true;
    }

    return false;
}

bool ArmsRegister::writtenLastInBlock(ArmsBasicBlock *block) {
    StateType reg_state;

    for (state_rit_type rit  = block_list[block].rbegin();
                        rit != block_list[block].rend();
                        rit++) {
        unsigned long insn_offset = rit->first;
        reg_state = rit->second;

        if (reg_state == IA64_WRITE) return true;
        if (reg_state == IA64_RW)    return true;
        if (reg_state == IA64_CLEAR) continue;
        return false;
    }

    return false;
}

StateType ArmsRegister::getLastState(ArmsBasicBlock *block) {
    StateType reg_state = IA64_CLEAR;

    for (state_rit_type rit  = block_list[block].rbegin();
                        rit != block_list[block].rend();
                        rit++) {
        unsigned long insn_offset = rit->first;
        reg_state = rit->second;

        if (reg_state != IA64_CLEAR) break;
    }

    return reg_state;
}

/* Returns the RW state for this register in a specific block. This assumes
 * that the instructions for this block were parsed in consecutive order. */
StateType ArmsRegister::getState(ArmsBasicBlock *block) {
    StateType reg_state = IA64_CLEAR; /* register is untouched by default */

    if (block_list.count(block) != 1) return reg_state;

    /* loop over all recorded states for this block */
    for (state_it_type it  = block_list[block].begin(); 
                       it != block_list[block].end(); 
                       it++) {
        unsigned long insn_offset = it->first;  /* instruction offset */
        reg_state = it->second;

        /* stop once the first state change was observed */
        if (reg_state != IA64_CLEAR) break;
    }

    return reg_state;
}

bool ArmsRegister::getDeref(ArmsBasicBlock *block) {
    bool deref = false;

    if (deref_block_list.count(block) != 1) return deref;

    for (deref_it_type it = deref_block_list[block].begin();
                       it != deref_block_list[block].end();
                       it++) {
        unsigned long insn_offset = it->first;
        deref = it->second;

        if (deref) break;
    }

    return deref;
}


StateType ArmsRegister::getState(ArmsBasicBlock *block, unsigned long offset) {
    if (block_list.count(block) != 1) return IA64_CLEAR;
    if (block_list[block].count(offset) != 1) return IA64_CLEAR;
    return block_list[block][offset];
}

/* Returns the RW state for this register in a number of blocks */
StateType ArmsRegister::getState(std::vector<ArmsBasicBlock *> blocks) {
    StateType reg_state = IA64_CLEAR; /* register is untouched by default */

    /* call getState() for each block until the register is no longer clear */
    for (std::vector<ArmsBasicBlock *>::iterator it  = blocks.begin();
                                                 it != blocks.end();
                                                 it++) {
        reg_state = getState(*it);

        /* stop once the first state change was observed */
        if (reg_state != IA64_CLEAR) break;
    }
    return reg_state;
}


ArmsBasicBlock * ArmsRegister::getBB(std::vector<ArmsBasicBlock *> blocks, StateType state) {
    for (std::vector<ArmsBasicBlock *>::iterator it  = blocks.begin();
                                                 it != blocks.end();
                                                 it++) {
        if (getState(*it) == state) return *it;
    }
    return NULL;
}

unsigned long ArmsRegister::getOffset(ArmsBasicBlock *block, StateType state) {
    for (state_it_type it  = block_list[block].begin(); 
                       it != block_list[block].end(); 
                       it++) {
        unsigned long insn_offset = it->first;
        int reg_state = it->second;

        if (reg_state == state) return insn_offset;
    }
    return 0;
}









/*********************************** ARMS LIVENESS ***********************************/

// static
string ArmsLiveness::get_register_name(int reg) {
    switch(reg) {
        case IA64_RDI: return "RDI";
        case IA64_RSI: return "RSI";
        case IA64_RDX: return "RDX";
        case IA64_RCX: return "RCX";
        case IA64_R8:  return "R8 ";
        case IA64_R9:  return "R9 ";
        case IA64_RSP: return "RSP";
        case IA64_RBP: return "RBP";
        case IA64_RAX: return "RAX";
        default: return "unknown";
    }
}

// static
int ArmsLiveness::parse_functions(ArmsFunction *f, void *arg) {
    ArmsLiveness *alive = (ArmsLiveness *) arg;
    return alive->parse_function(f);
}

int ArmsLiveness::getFirstReadArgRegister(ArmsBasicBlock *bb, unsigned long offset) {

    for (int i = 0; i < IA64_ARGS; i++) {
        if (rw_registers[i].getState(bb, offset) == IA64_READ)
            return i;
    }

    return IA64_ARGS;
}

bool ArmsLiveness::is_analyzed(ArmsBasicBlock *bb) {
    return analyzed_blocks.find(bb) != analyzed_blocks.end();
}

int get_reg_index(RegisterAST::Ptr reg) {
    int reg_value = reg->getID().val();
    int reg_class = reg->getID().regClass();
    
    if (reg_class != x86::GPR) {
        /* not a GPR (could be a flag or RIP or ...) */
        return -1;
    }
    switch(reg_value & 0x000000ff ) {
        case 0: // RAX
            return IA64_RAX;
            break;
        case 1: // RCX
            return IA64_RCX;
            break;
        case 2: // RDX
            return IA64_RDX;
            break;
        case 3: // RBX
            break;
        case 4: // RSP
            return IA64_RSP;
            break;
        case 5: // RBP
            return IA64_RBP;
            break;
        case 6: // RSI
            return IA64_RSI;
            break;
        case 7: // RDI
            return IA64_RDI;
            break;
        case 8: // R8
            return IA64_R8;
            break;
        case 9: // R9
            return IA64_R9;
            break;
        case 10: // R10
            break;
        case 11: // R11
            break;
        case 12: // R12
            break;
        case 13: // R13
            break;
        case 14: // R14
            break;
        case 15: // R15
            break;
        default: // anything else
            break;
    }
    return -1;
}


void ArmsLiveness::parse_register(RegisterAST::Ptr reg, 
                                  ArmsBasicBlock *bb, unsigned long offset, StateType state) {
    int reg_index = get_reg_index(reg);
    if (reg_index < 0) return;
    
    dprintf("              : (%d): %s -> %s\n", reg_index, 
                         get_register_name(reg_index).c_str(), 
                    ArmsRegister::getStateName(state).c_str());
    rw_registers[reg_index].setState(bb, offset, state);
    
}

void ArmsLiveness::parse_register_set(std::set<RegisterAST::Ptr> register_set, 
                        ArmsBasicBlock *bb, unsigned long offset, StateType state) {
 
    for (std::set<RegisterAST::Ptr>::iterator it  = register_set.begin(); 
                                              it != register_set.end(); 
                                              it++) {
        RegisterAST::Ptr reg = *it;
        int  reg_value = reg->getID().val();
        parse_register(reg, bb, offset, state);
    }
}

bool isNop(Instruction::Ptr iptr) {
    if (iptr->getOperation().getID() == e_nop) return true;
    return false;
}

bool isNop(ArmsBasicBlock *bb) {
    ParseAPI::Block *pblock = (ParseAPI::Block *) bb->get_parse_block();
    ParseAPI::Block::Insns insns;
    pblock->getInsns(insns);
    for (ParseAPI::Block::Insns::iterator it  = insns.begin(); 
                                          it != insns.end(); 
                                          it++) {
        /* it->first:  offset
         * it->second: instruction */
        if (!isNop(it->second)) return false;
    }

    return true;
}

void ArmsLiveness::parse_instruction(Instruction::Ptr iptr,
                                     ArmsBasicBlock *bb, unsigned long offset) {

    if (!iptr->isLegalInsn()) {
        dprintf("      %p: [ILLEGAL INSTRUCTION]\n", (void *) offset);
        bb->set_disas_err((void*) offset);
        return;
    }
    dprintf("      %p: %s\n", (void *) offset, iptr->format(0).c_str());

    
    RegisterAST::Ptr reg = is_dereference(iptr);
    if (reg != NULL) {
        int reg_index = get_reg_index(reg);
        if (reg_index >= 0) {
            dprintf("setting deref\n");
            rw_registers[reg_index].setDeref(bb, offset);
        }
    }

    ins_length[offset] = iptr->size();

    if (iptr->size() == 2 && iptr->rawByte(0) == 0xF3 && iptr->rawByte(1) == 0x90) {
        dprintf("                PAUSE\n");
        return;
    }
    if (iptr->size() == 2 && iptr->rawByte(0) == 0x0F && iptr->rawByte(1) == 0xA2) {
        dprintf("                CPUID\n");
        RegisterAST::Ptr eax(new RegisterAST(x86::eax)); // TODO
        RegisterAST::Ptr ebx(new RegisterAST(x86::ebx));
        RegisterAST::Ptr ecx(new RegisterAST(x86::ecx));
        RegisterAST::Ptr edx(new RegisterAST(x86::edx));
        parse_register(eax, bb, offset, IA64_WRITE);
        parse_register(ebx, bb, offset, IA64_WRITE);
        parse_register(ecx, bb, offset, IA64_WRITE);
        parse_register(edx, bb, offset, IA64_WRITE);
        return;
    }
    /* TODO: for us, syscalls are not indirect calls. we should modify the arms
     * interface so that it does not add those edges in the first place */
    if (iptr->size() == 2 && iptr->rawByte(0) == 0x0F && iptr->rawByte(1) == 0x05) {
        dprintf("                SYSCALL\n");
        bb->set_syscall();
    }
/* TODO:
    if (iptr->size() == 2 && iptr->rawByte(0) == 0x0f && iptr->rawByte(1) == 0x0b) {
        dprintf("                UD2\n");
    }
 */

    std::set<RegisterAST::Ptr> register_set;

    if (!isNop(iptr)) iptr->getReadSet(register_set);
    parse_register_set(register_set, bb, offset, IA64_READ);
    register_set.clear();

    if (!isNop(iptr)) iptr->getWriteSet(register_set);
    parse_register_set(register_set, bb, offset, IA64_WRITE);
    register_set.clear();



}


void ArmsLiveness::parse_block(ArmsFunction *f, ArmsBasicBlock *bb) {
    /* Analyze blocks only once */
    if (is_analyzed(bb)) {
        dprintf("O NO\n");
        return;
    }

    dprintf("  - Analyzing block %p - %p\n", (void *)bb->get_start_address(),
                                           (void *)bb->get_last_insn_address());

    /* The ArmsBasicBlock stores a pointer to either a ParseAPI::Block or a
     * BPatchBasicBlock. We currently only support the first. */
    ParseAPI::Block *pblock = (ParseAPI::Block *) bb->get_parse_block();
    if (!pblock) return; // TODO

    /* Parse the instructions of this basic block */
    ParseAPI::Block::Insns insns;
    pblock->getInsns(insns);
    for (ParseAPI::Block::Insns::iterator it  = insns.begin(); 
                                          it != insns.end(); 
                                          it++) {
        /* it->first:  offset
         * it->second: instruction */
        parse_instruction(it->second, bb, it->first);
    }

    dprintf("    Block summary:\n");
    for (int i = 0; i < IA64_REGS; i++) {
        dprintf("      %s: %s\n",            get_register_name(i).c_str(), 
                               ArmsRegister::getStateName(rw_registers[i].getState(bb)).c_str() );
    }

    analyzed_blocks.insert(bb);
    function_blocks[f].push_back(bb);

    /* Recursively analyze adjacent blocks by looping over the outgoing edges of
     * this block. */

    /* TODO The order of analyzing blocks is dictated by how we traverse the
     * CFG. This could have an impact on the read before write states, consider
     * code like:
     * 
     *      cmp rax, 0
     *      je foo
     *      mov rcx, 2
     * foo: mov r15, rcx
     *
     * In above example, depending on the order we traverse the blocks, we may
     * conclude that rcx is write before read (in case we do not follow the
     * conditional jump to label foo), or read before write (when we analyze the
     * code at label foo first).
     *
     * Analysis will have to tell whether this is a problem.
     */
    dprintf("    > edges: %lu\n",bb->outgoing_edge_count());
    for(size_t i = 0; i < bb->outgoing_edge_count(); i++) {
        ArmsEdge *edge = bb->get_outgoing_edge(i);
        ArmsBasicBlock *next_bb;
  
        /* We do not want to leave the current function */
        if (edge->is_return()) {
            dprintf("    > Not following return edge\n");
            continue;
        } else if (edge->is_direct_call()) {
            dprintf("    > Not following direct call edge, looking at fallthrough bb instead\n");
            /* TODO: test whether a direct call is made to a function that exits
             * Maybe it easier to try to use the ARMS interface to get a hold on
             * all the basicblocks for a specific function, instead of doing all
             * the work again here... --> ARMS nor ParseAPI won't solve this :( */
            if (edge->target() != NULL &&
                edge->target()->get_function() != NULL &&
                (edge->target()->get_function()->get_name() == "_EXIT" ||
                 edge->target()->get_function()->get_name() == "_exit")) {
                dprintf("    > Call to _EXIT, not even looking at fallthrough bb\n");
                continue;
            }
            next_bb = bb->get_fallthrough_bb();
        } else if(edge->is_indirect_call()) {
            dprintf("    > Not following indirect call edge, looking at fallthrough bb instead\n");
            next_bb = bb->get_fallthrough_bb();

            /* This looks like a great place to perform the live analysis for
             * indirect callsites. However, if we need to implement our own
             * analysis algoritm here, we need to remember that not all basic
             * blocks of this function may be parsed yet. For this reason, we
             * do the icall analysis AFTER the entire function was analyzed.
             * 
             * To speed fix up a bit, we store this basicblock so we do not have
             * to go over all the blocks again.
             */
            icall_blocks[f].insert(bb);

        } else {
            dprintf("    > Getting target of edge\n");
            next_bb = edge->target();
        }

        if (next_bb == NULL) {
            dprintf("    > next bb does not exist\n");
            continue;
        }

        if (edge->is_direct_call() && isNop(next_bb)) {
            dprintf("    > fallthrough is nop while last edge was a direct call. Assuming non-returning\n");
            continue;
        }

        if (edge->is_direct_call() && next_bb->is_entry_block()) {
            dprintf("    > fallthrough is entry block while last edge was a direct call. Assuming non-returning\n");
            continue;
        }

        if (is_analyzed(next_bb)) {
            dprintf("    > next bb is already analyzed\n");
            continue;
        }

        std::vector<ArmsFunction*> funcs = next_bb->get_functions();
        if (funcs.size() == 0) {
            dprintf("    > next bb is not from any function\n");
            continue;
        }
        for (std::vector<ArmsFunction *>::iterator it  = funcs.begin();
                                                   it != funcs.end();
                                                   it++) {
            if (*it == f) {
                goto function_found;
            }

        }
        dprintf("    > next bb is from a different function:\n");
        for (std::vector<ArmsFunction *>::iterator it  = funcs.begin();
                                                   it != funcs.end();
                                                   it++) {
            ArmsFunction *fun = *it;
            dprintf("      > %s\n", fun->get_name().c_str());
        }

        continue;

function_found:
        this->parse_block(f, next_bb);
    }
}

int ArmsLiveness::parse_function(ArmsFunction *f) {
    
    if(f->is_plt() || f->is_lib_dummy()) {
        dprintf("* Skipping analysis of function %s\n", f->get_name().c_str());
        return 0;
    } 
    dprintf("* Analyzing function %s\n", f->get_name().c_str());


    std::set<ArmsBasicBlock*> *bbs = f->get_basic_blocks();
    for (std::set<ArmsBasicBlock *>::iterator it  = bbs->begin();
                                              it != bbs->end();
                                              it++) {
        ArmsBasicBlock *b = *it;
        dprintf("- basicblock %p - %p\n", (void *)b->get_start_address(),
                                          (void *)b->get_last_insn_address());
    }

    std::vector<ArmsBasicBlock*> entry_blocks;
    entry_blocks.assign(f->get_entry_points()->begin(), f->get_entry_points()->end());

    function_blocks[f].clear();
    icall_blocks[f].clear();

    /* Recursively analyze each block of the function starting from the entry blocks */
    while(entry_blocks.size() > 0) {
        ArmsBasicBlock *bb = entry_blocks.back();
        entry_blocks.pop_back();

        parse_block(f, bb);
    }

    dprintf("    Function summary:\n");
    for (int i = 0; i < IA64_REGS; i++) {
        dprintf("      %s: %s\n", get_register_name(i).c_str(), 
            ArmsRegister::getStateName(rw_registers[i].getState(function_blocks[f])).c_str() );
    }


    return 0;
}


string ArmsLiveness::get_regstate_name(int i, ArmsFunction *f) {
    return ArmsRegister::getStateName(rw_registers[i].getState(function_blocks[f]));
}





/**** DETECTING VARIADIC FUNCTIONS ****/

bool ArmsLiveness::also_read(int k, ArmsBasicBlock *bb, int reg_index) {
    for (int i = k; i < IA64_ARGS; i++) {
        unsigned long offset = rw_registers[i].getReadOffset(bb);
        ddprintf("  [varargs.C4] State for %s at offset %lx (1st read of %s): %s\n", 
                get_register_name(reg_index).c_str(), offset, get_register_name(i).c_str(), 
                ArmsRegister::getStateName( rw_registers[reg_index].getState(bb,offset) ).c_str());
                
        if (rw_registers[reg_index].getState(bb,offset) != IA64_READ) {
            return false;
        }
    }
    return true;
}

/* This function can safely return 0 to indicate the function is not-variadic:
 * variadic functions always expect at least one argument. */
int ArmsLiveness::is_variadic(ArmsFunction *f) {
    int i;

    /* Variadic functions do not necessarily read all argument registers: a
     * function may overwrite a non-varargs parameter without reading it first,
     * for example. However, it seems to be the case that for any optimization
     * level, the compiler always generates code that stores the registers that
     * hold varargs (the ...) onto the stack. In addition, this always seems to
     * happen in the same order (vaarg 1 before vaarg 2 before vaarg 3 ...) and
     * also always within the same basic block.
     * We identify four conditions:
     *  1. The last N argument registers are read before write for this function
     *  2. This happens in the same basic block.
     *  3. This happens in a specific order.
     *  4. They are written to the stack.
     * and a possible 5th condition:
     *  5. 1-4 happens before the first call instruction of a function. 
     * (6. Must happen within the first 3 basic blocks)
     * If all these conditions are met, we conclude that the function is
     * variadic and expects at least 6 - N arguments.
     */
    
    
    /* CONDITION 5:
     * Make sure that there are no call instructions before the affected basic
     * block. Since a called function may overwrite some of the parameter
     * registers, the varargs must have been stored before the call is made.
     * We enforce this by minimzing the number of basic blocks that can be analyzed.
     */
    std::vector<ArmsBasicBlock *> blocks;
    for (std::vector<ArmsBasicBlock *>::iterator it  = function_blocks[f].begin();
                                                 it != function_blocks[f].end();
                                                 it++) {
        ArmsBasicBlock *bb = *it;
        blocks.push_back(bb);
        if (bb->outgoing_contains_inter()) break;
    }


    /* CONDITION 1:
     * Get the number of arugment registers that were read before write */
    int n = 0;
    ddprintf("  [varargs.C1] Searching for last n arguments that are read before write... %s\n",f->get_name().c_str());
    for (i = IA64_LAST_ARG; i >= n; i--) {
        ddprintf("  [varargs.C1] %d: %s - %s\n", i, get_register_name(i   ).c_str(), 
                                                    get_regstate_name(i, f).c_str());
        if (!rw_registers[i].isRead(blocks)) {
            n = i + 1;
            break;
        }
    }
    /* If zero argument registers were found (i.e., R9 was not read before
     * write), we conclude that this function is not variadic. It could still be
     * variadic of course, if it has more than 6 constant arguments. */
    if (i == IA64_LAST_ARG) return 0;
    
    /* At this moment, we know that argument registers n, n+1, ..., 6 are
     * all read before write. */
    
    /* CONDITION 2:
     * Get the number of read before write arguments that had their first read
     * instruction in the same basic block. */
    int k = n;
    ArmsBasicBlock *last_bb = rw_registers[IA64_LAST_ARG].getReadBB(blocks);
    ddprintf("  [varargs.C2] Matching basic blocks against %p...\n", (void *)last_bb);
    for (i = IA64_LAST_ARG; i >= k; i--) {
        ArmsBasicBlock *bb = rw_registers[i].getReadBB(blocks);
        ddprintf("  [varargs.C2] %d: %s - %p\n", i, get_register_name(i).c_str(), (void *)bb);

        if (last_bb != bb) {
            k = i + 1;
            break;
        }
    }

    /* At this moment, we know that argument registers k, k+1, ..., 6 are all
     * read before write within the same basic block. */


    /* TODO. condition 3 must be strong: it must even be the next instruction.
     * */

    /* CONDITION 3:
     * Get the number of read before write arguments for which their read
     * instructions (that rely in the same basic block) occurred in consecutive
     * order. This could either be Rx, Ry, ..., R8, R9 for gcc or R9, R8, ...
     * Ry, Rx for clang. */
    int m = k;
    unsigned long last_seen_offset = rw_registers[IA64_LAST_ARG].getReadOffset(last_bb);
    ddprintf("  [varargs.C3] Comparing offsets...\n");
    for (i = IA64_LAST_ARG-1; i >= m; i--) {
        unsigned long offset = rw_registers[i].getReadOffset(last_bb);
#if 0
        ddprintf("  [varargs.C3] %d: %lx (read of %s) < %lx (read of %s)?\n", 
                i,           offset, get_register_name(i).c_str(), 
                   last_seen_offset, get_register_name(i+1).c_str());

        if (offset >= last_seen_offset) {
#else
        ddprintf("  [varargs.C3] %d: %lx (read of %s) > %lx (read of %s)?\n", 
                i,           offset, get_register_name(i).c_str(), 
                   last_seen_offset, get_register_name(i+1).c_str());

        if (offset != last_seen_offset + ins_length[offset]) {
#endif
            m = i + 1;
            break;
        }

        last_seen_offset = offset;
    }

    /* At this moment, we know that the argument registers m, m+1, ... 6 are
     * all read before write within the same basic block and in a consecutive
     * order. */
    
    /* CONDITION 4:
     * Ensure that the last m arguments that were (i) read before write, (ii)
     * read within the same block, and (iii) read in consecutive order, are all
     * written to the stack.
     * We do this by testing if for each read instruction, the stack pointer
     * (RSP) was read by the same instruction (this indicates that the read
     * before write instruction is likely to move the argument value to the
     * stack). TODO: if necessary, we make this check harder by keeping track of
     * memory writes.
     *
     * Unoptimized binaries may use the base pointer (RBP) instead of RSP which
     * is why we perform the test twice. 
     *
     * TODO? We thus currently enforce that the last non-vararg argument is no
     * longer in this set. I am not sure if this is always the case. */
    ddprintf("  [varargs.C4] Testing whether RSP/RBP was read...\n");
    if (!also_read(m, last_bb, IA64_RSP) && 
        !also_read(m, last_bb, IA64_RBP)) {
        /* Not all possible variadic arguments were stored on the stack.
         * Assuming not variadic. */
        return 0;
    }

    /* we mark this <last_bb> as vararg-related so that we can use it later */
    last_bb->mark_vararg();

    return m;


    /* Now, when optimization is enabled, we wrongly detect:
     *
     * int test_va_working_func(int p0, int p1, ...) {
     *  va_list vl;
     *  va_start(vl, p1);
     *  va_end(vl);
     * }
     *
     * as a variadic function that expects 3 arguments. This is caused by the
     * compiler optimizing the use of p1 away. While this is valid code, of
     * course, I argue that this is a programming error.
     *
     * It happens for
     * - proftpd: src/scoreboard.c: pr_scoreboard_entry_update(pid_t pid, ...)
     * - openssh: openbsd-compat/setproctitle.c: setproctitle(const char *fmt, ...)
     */
}


/* Store read/write/clear state for 6 argument registers. We need two bits per
 * argument: 12 bits in total */
//uint16_t reg_bitmap;

/* As defined in arms_liveness.h:
 *   IA64_CLEAR     0x00    00b
 *   IA64_READ      0x01    01b
 *   IA64_WRITE     0x02    10b
 *   IA64_RW        0x03    11b
 */

/* set register <reg_index> to <state> */
void set_reg_bitmap(uint16_t *reg_bitmap, int reg_index, uint16_t state) {
    *reg_bitmap &= ~(0x03 << (reg_index * 2)); // clear first
    *reg_bitmap |= state << (reg_index * 2);
}

/* returns true if register <reg_index> is set to <state> */
bool is_reg_bitmap(int reg_bitmap, int reg_index, uint16_t state) {
    return (reg_bitmap >> (reg_index * 2) & 0x03) == state;
}

/* returns the state of register <reg_index> */
int get_reg_bitmap(int reg_bitmap, int reg_index) {
    return (reg_bitmap >> (reg_index * 2) & 0x03);
}

int bitmap_argset(int reg_bitmap, uint16_t state) {
    int argcount = 0;

    while (get_reg_bitmap(reg_bitmap, argcount) == state) {
        argcount++;
    }

    return argcount;
}

bool is_complete(int reg_bitmap, uint16_t state) {
    for (int i = 0; i < 6; i++) {
        if (is_reg_bitmap(reg_bitmap, i, state)) return false;
    }
    return true;
}


std::string ArmsLiveness::bm_tostring(int reg_bitmap) {
    string result = "";
    for (int i = 0; i < 6; i++) {
        if (is_reg_bitmap(reg_bitmap, i, IA64_CLEAR)) result += "C ";
        if (is_reg_bitmap(reg_bitmap, i, IA64_READ)) result += "R ";
        if (is_reg_bitmap(reg_bitmap, i, IA64_WRITE)) result += "W ";
        if (is_reg_bitmap(reg_bitmap, i, IA64_RW)) result += "X ";
    }
    return result;

}



bool ArmsLiveness::getRAXreads(ArmsFunction *f,
                                   ArmsBasicBlock *bb,
                                   std::vector<ArmsBasicBlock *> retuse_fts,
                                   std::vector<ArmsBasicBlock *> retuse_analyzed_blocks) {   

    int edges_followed = 0;

    std::vector<bool> bitmaps;
    std::string blanks(retuse_analyzed_blocks.size(), ' ');

    StateType state;
    state = rw_registers[IA64_RAX].getState(bb);
    if (state == IA64_READ)   {
        return true;
    }
    if (state == IA64_WRITE ||
        state == IA64_RW) {
        return false;
    }


    /* state == IA64_CLEAR (rax was not touched) */
    
    if (bb->outgoing_edge_count() == 0) {
        /* If this block has no outgoing edges, we must stop. */
        return false;
    }

    
    retuse_analyzed_blocks.insert(retuse_analyzed_blocks.begin(), bb);


    for (size_t i = 0; i < bb->outgoing_edge_count(); i++) {
        bitmaps.push_back(false);

        ArmsEdge *edge = bb->get_outgoing_edge(i);
        ArmsBasicBlock *next_bb = NULL;
        ArmsBasicBlock *fallthrough_bb = NULL;

        ddprintf("[ret-ft]%s Edge %lu/%lu ",blanks.c_str(),i+1,bb->outgoing_edge_count());

        if (edge->is_return()) {
            /* do we have a fallthrough to follow? */
            if (!retuse_fts.empty()) {
                ddprintf("is return, continuing at fallthrough\n");
                next_bb = retuse_fts.back();
                retuse_fts.pop_back();
                assert(false);
            } else {
                ddprintf("is return, but not fallthrough found. End of function?\n");
                return false;
            }
        } else if (edge->is_direct_call()) {
            // FIXME we must return here
            return false;
              
            /* TODO maybe we can omit this if we're assuming standard calling convention. the 
             * compiler may optimize this. if the callee needs the return value as an argument, it
             * does not necessarily have to be moved into an argument register. */
            ddprintf("is direct call, storing fallthrough\n");

            next_bb = edge->target();
            fallthrough_bb = bb->get_fallthrough_bb();
       
            assert(next_bb != NULL);

            /* some direct calls never return, in which case we do not look at
             * the fallthrough. */
            if (fallthrough_bb == NULL) {
                ddprintf("[ret-ft]%s fallthrough is null. assuming non-returning\n", blanks.c_str());
            } else if (isNop(fallthrough_bb)) {
                ddprintf("[ret-ft]%s fallthrough is nop. assuming non-returning\n", blanks.c_str());
                fallthrough_bb = NULL;
            } else if (fallthrough_bb->is_entry_block()) {
                ddprintf("[ret-ft]%s fallthrough is entry block. assuming non-returning\n", blanks.c_str());
                fallthrough_bb = NULL;
            } else {
                ddprintf("[ret-ft]%s fallthr: %p\n", blanks.c_str(), (void *)fallthrough_bb->get_start_address());
                
                if (next_bb->get_function() != NULL &&
                    next_bb->get_function()->is_plt()) {
                
                    if (next_bb->get_function()->get_name() == "exit") {
                        ddprintf("[ret-ft]%s direct call to exit@plt, non returning\n", blanks.c_str());
                        fallthrough_bb = NULL;
                    } else {
                        ddprintf("[ret-ft]%s direct call to PLT stub, continuing straight at fallthrough\n", blanks.c_str());
                        next_bb = fallthrough_bb;
                    }
                } else {
                    retuse_fts.push_back(fallthrough_bb);
                }
            }
        } else if (edge->is_indirect_call()) {
            ddprintf("is indirect call, we must assume the target does not reads rax\n");
//          assert(bb->outgoing_edge_count() == 1);
            return false;
        } else {
            ddprintf("is regular\n");
            next_bb = edge->target();
        }

        assert(next_bb != NULL);

        if (next_bb->get_function() == NULL) {
            /* FIXME this bb is part of multiple functions, we must stop */
            return false;
        }
        if (next_bb->get_function() != f) {
            /* FIXME */
            return false;
        }

        ddprintf("[ret-ft]%s Next block: %p\n", blanks.c_str(), (void *) next_bb->get_start_address());

        if (std::find(retuse_analyzed_blocks.begin(),
                      retuse_analyzed_blocks.end(),
                      next_bb) != retuse_analyzed_blocks.end()) {
            ddprintf("[ret-ft]%s Next block is already analyzed (loop detection)\n", blanks.c_str());
            bitmaps[i] = true; /* assuming worst-case */
            continue;
        }

        ddprintf("[ret-ft]%s Entering recursing\n",blanks.c_str());
        bitmaps[i] = this->getRAXreads(f, next_bb, retuse_fts, retuse_analyzed_blocks);
        
        edges_followed++;
    }
        
    ddprintf("[ret-ft]%s followed %d edges\n", blanks.c_str(), edges_followed);

    if (edges_followed == 0) {
        ddprintf("[ret-ft]%s No edges followed\n", blanks.c_str());
        return false;
    }

    ddprintf("[ret-ft]%s Computing best bitmap\n", blanks.c_str());
    for (auto it  = bitmaps.begin(); 
              it != bitmaps.end();
              it++) {
        bool bitmap = *it;

        /* all paths must read before write rax */
        if (bitmap == false) return false;
    }
    return true;
}



uint16_t ArmsLiveness::getBackwardLiveness(ArmsFunction *f,
                                       ArmsBasicBlock *bb,
            std::vector<ArmsBasicBlock *> callsite_analyzed_blocks) {

    int edges_followed = 0;
    uint16_t *bitmaps;

    std::string blanks(callsite_analyzed_blocks.size(), ' ');

    ddprintf("[bt]%s Block status for %p: ",blanks.c_str(), (void *)bb->get_start_address());


    uint16_t reg_bitmap = 0;
    for (int i = 0; i < IA64_ARGS; i++) {
        set_reg_bitmap(&reg_bitmap, i, IA64_READ);
    }

    /* update the callsite_registers with information from the current block */
    /* defaults to read. if a register get trashed, we mark it as clear; else written */
    bool done = true;
    for (int i = 0; i < IA64_ARGS; i++) {
        if (is_reg_bitmap(reg_bitmap, i, IA64_READ)) {
            if (rw_registers[i].writtenInBlock(bb)) {
                set_reg_bitmap(&reg_bitmap, i, IA64_WRITE);
            } else {
                done = false;
            }
        }
        ddprintf("%d ",get_reg_bitmap(reg_bitmap, i));
    }
    ddprintf("(%x)\n",reg_bitmap);
    
    dprintf("[bt]%s %p -> ", blanks.c_str(), (void*)bb->get_start_address());
    for (auto it  = callsite_analyzed_blocks.begin(); 
              it != callsite_analyzed_blocks.end();
              it++) {
        ArmsBasicBlock* analyzed_block = *it;
        dprintf("%p -> ", (void *) analyzed_block->get_start_address());
    }
    dprintf("? (block has %x)\n",reg_bitmap);

    if (done) {
        ddprintf("[bt]%s All arguments set, returning\n", blanks.c_str());
        goto debug_return;
        return reg_bitmap;
    }

    callsite_analyzed_blocks.insert(callsite_analyzed_blocks.begin(), bb);

    bitmaps = (uint16_t *) malloc(bb->incoming_edge_count() * sizeof(uint16_t)); 


    if (bb->is_entry_block() && bb->incoming_edge_count() == 0) {
        if (bb->get_function() == 0) {
            ddprintf("[bt] wtf %s\n",f->get_name().c_str());
        } else {
            ddprintf("could use a direct edge: %s\n", f->get_name().c_str());
        }
        f->add_dependency(bb->get_function());
        for (int i = 0; i < IA64_ARGS; i++) {
            if (is_reg_bitmap(reg_bitmap, i, IA64_READ)) {
                set_reg_bitmap(&reg_bitmap, i, IA64_WRITE);
            }
        }
    }

    /* Loop recursively over the incoming edges for this basic block */
    for (size_t i = 0; i < bb->incoming_edge_count(); i++) {

        bitmaps[i] = reg_bitmap;


        ArmsEdge *edge = bb->get_incoming_edge(i);
        ArmsBasicBlock *prev_bb;

        ddprintf("[bt]%s Edge %lu/%lu\n",blanks.c_str(),i+1,bb->incoming_edge_count());

        if (edge->is_return()) {
            ddprintf("[bt]%s Edge is return, flushing\n", blanks.c_str());
            ddprintf("[bt]%s Updated block status: ", blanks.c_str());
            for (int j = 0; j < IA64_ARGS; j++) {
                if (is_reg_bitmap(bitmaps[i],j,IA64_READ)) {
                    set_reg_bitmap(&bitmaps[i], j, IA64_CLEAR);
                }
                ddprintf("%d ",get_reg_bitmap(bitmaps[i],j));
            }
            ddprintf("(%x)\n",bitmaps[i]);
            reg_bitmap = bitmaps[i];
            free(bitmaps);
            /* there may be more edges, but it won't get better than this.
             * return here */

            goto debug_return;
            return reg_bitmap;


        } else if (edge->is_direct_call() || edge->is_indirect_call()) {
            ddprintf("[bt]%s Edge is direct call\n",blanks.c_str());
            /* Simply continue the backward search. This is a function that called us */
            prev_bb = edge->source();
        } else {
            ddprintf("[bt]%s Edge is regular\n",blanks.c_str());
            prev_bb = edge->source();
              
        }

        assert(prev_bb != NULL);

        ddprintf("[bt]%s Previous block: %p\n", blanks.c_str(), (void *) prev_bb->get_start_address());

        if (std::find(callsite_analyzed_blocks.begin(),
                      callsite_analyzed_blocks.end(),
                      prev_bb) != callsite_analyzed_blocks.end()) {
            ddprintf("[bt]%s Previous block is already analyzed\n", blanks.c_str());
            bitmaps[i] = 0xaaa; /* assume all WRITE TODO shouldn't this be all CLEAR? (0x000) */
            edges_followed++;
            continue;
        }

        if (backward_cache.count(prev_bb)) {
            ddprintf("[bt]%s Cache lookup\n",blanks.c_str());
            bitmaps[edges_followed] = backward_cache[prev_bb];
        } else {
            ddprintf("[bt]%s Entering recursing\n",blanks.c_str());
            bitmaps[edges_followed] = this->getBackwardLiveness(f, prev_bb, callsite_analyzed_blocks);
            backward_cache[prev_bb] = bitmaps[edges_followed];
        }

        ddprintf("[bt]%s Got bitmap %x\n", blanks.c_str(), bitmaps[edges_followed]);
        assert(is_complete(bitmaps[edges_followed], IA64_READ));
        
        edges_followed++;
    }


    /* we now have our own bitmap <reg_bitmap> and a set of complete bitmaps.
     * get the best complete bitmap and combine it with ours */
    
    if (edges_followed == 0) {
//      ddprintf("[bt]%s best_bitmap = %x | reg_bitmap = %x\n", blanks.c_str(), best_bitmap, reg_bitmap);

        /* this means that no edges were found. we'll flush */
        ddprintf("[bt]%s No edges found, flushing\n", blanks.c_str());
        ddprintf("[bt]%s Updated block status: ", blanks.c_str());
        for (int j = 0; j < IA64_ARGS; j++) {
            if (is_reg_bitmap(reg_bitmap,j,IA64_READ)) {
                set_reg_bitmap(&reg_bitmap, j, IA64_CLEAR);
            }
            ddprintf("%d ",get_reg_bitmap(reg_bitmap,j));
        }
        ddprintf("(%x)\n",reg_bitmap);
    } else {
    
        uint16_t best_bitmap = 0xaaa;

        for (size_t i = 0; i < edges_followed; i++) {
            assert(is_complete(bitmaps[i], IA64_READ));
           
#ifdef CONSERVATIVE_CALLSITE
            if (bitmap_argset(bitmaps[i], IA64_WRITE) >= bitmap_argset(best_bitmap, IA64_WRITE)) {
                best_bitmap = bitmaps[i];
            }
#else
            if (bitmap_argset(bitmaps[i], IA64_WRITE) <= bitmap_argset(best_bitmap, IA64_WRITE)) {
                best_bitmap = bitmaps[i];
            }   
#endif
        }

    
        /* combine */
        ddprintf("[bt]%s Combining with %x\n", blanks.c_str(), best_bitmap);
        ddprintf("[bt]%s Updated block status: ", blanks.c_str());
        for (int i = 0; i < IA64_ARGS; i++) {
            if (is_reg_bitmap(reg_bitmap, i, IA64_READ)) {
                set_reg_bitmap(&reg_bitmap, i, get_reg_bitmap(best_bitmap,i));
            }
            ddprintf("%d ", get_reg_bitmap(reg_bitmap, i));
        }
        ddprintf("(%x)\n",reg_bitmap);
    }

    free(bitmaps);
    ddprintf("[bt]%s Processed all edges, returning our best bitmap (%x)\n", blanks.c_str(), reg_bitmap);
    goto debug_return;
    return reg_bitmap;


debug_return:
    dprintf("[bt]%s ", blanks.c_str());
    for (auto it  = callsite_analyzed_blocks.begin(); 
              it != callsite_analyzed_blocks.end();
              it++) {
        ArmsBasicBlock* analyzed_block = *it;
        dprintf("%p -> ", (void *) analyzed_block->get_start_address());
    }
    dprintf("(%x)\n", reg_bitmap);
    return reg_bitmap;



}


/* based on getBackwardLiveness. we start at the exit point and move back to search for writes on rax */
bool ArmsLiveness::getRAXwrites(ArmsFunction *f,
                                    ArmsBasicBlock *bb,
            std::vector<ArmsBasicBlock *> callee_retuse_analyzed_blocks) {

    int edges_followed = 0;
    bool *bitmaps;

    std::string blanks(callee_retuse_analyzed_blocks.size(), ' ');

    if (rw_registers[IA64_RAX].writtenInBlock(bb)) {
        dprintf("[ret-bt]%s RAX is written in block\n", blanks.c_str());
        return true;
    }    

    callee_retuse_analyzed_blocks.insert(callee_retuse_analyzed_blocks.begin(), bb);

    bitmaps = (bool *) malloc(bb->incoming_edge_count() * sizeof(bool)); 

    if (bb->is_entry_block() && bb->incoming_edge_count() == 0) {
        /* no incoming edges - it could be an AT function that must be called. we can 
         * return false here (rax is not written) because we do not have to take possible 
         * callers into account (these are the callsites that expect rax to be written) */
        return false;
    }

    /* Loop recursively over the incoming edges for this basic block */
    for (size_t i = 0; i < bb->incoming_edge_count(); i++) {

        bitmaps[i] = false;

        ArmsEdge *edge = bb->get_incoming_edge(i);
        ArmsBasicBlock *prev_bb;

        ddprintf("[ret-bt]%s Edge %lu/%lu\n",blanks.c_str(),i+1,bb->incoming_edge_count());

        if (edge->is_return()) {
            ddprintf("[ret-bt]%s Edge is return, we must look at the called function\n", blanks.c_str());
            /* TODO assuming a write for now */
            return true;
        } else if (edge->is_direct_call() || edge->is_indirect_call()) {
            ddprintf("[ret-bt]%s Edge is direct call\n",blanks.c_str());
            /* Here we can stop, unless we implement previous mentioned TODO */
            return false;
        } else {
            ddprintf("[ret-bt]%s Edge is regular\n",blanks.c_str());
            prev_bb = edge->source();
        }

        assert(prev_bb != NULL);

        ddprintf("[ret-bt]%s Previous block: %p\n", blanks.c_str(), (void *) prev_bb->get_start_address());

        if (std::find(callee_retuse_analyzed_blocks.begin(),
                      callee_retuse_analyzed_blocks.end(),
                      prev_bb) != callee_retuse_analyzed_blocks.end()) {
            ddprintf("[ret-bt]%s Previous block is already analyzed\n", blanks.c_str());
            bitmaps[i] = true; /* assume all WRITE - worst case scenario */
            edges_followed++;
            continue;
        }

        ddprintf("[ret-bt]%s Entering recursing\n",blanks.c_str());
        //bitmaps[edges_followed] = this->getRAXwrites(f, prev_bb, callee_retuse_analyzed_blocks);
// patch Enes
        if(this->getRAXwrites(f, prev_bb, callee_retuse_analyzed_blocks)){
          free(bitmaps);
          return true;
        }else{
          bitmaps[edges_followed] = false;
        }
// patch Enes done

        ddprintf("[ret-bt]%s Got bitmap %x\n", blanks.c_str(), bitmaps[edges_followed]);
        
        edges_followed++;
    }


    /* we now have our own bitmap (false) and a set of complete bitmaps.
     * get the best complete bitmap and combine it with ours */
    
    if (edges_followed == 0) {
//      ddprintf("[bt]%s best_bitmap = %x | reg_bitmap = %x\n", blanks.c_str(), best_bitmap, reg_bitmap);
        
        
        /* the previous bb could have ended with an (indirect) call */
        if (!bb->is_entry_block()) {
            ArmsBasicBlock *up = bb->get_fallup_bb();
            if (up != NULL) {
                dprintf("[ret-bt] fount fallup\n");
                if (up->outgoing_edge_count() == 1) {
                    if (up->get_outgoing_edge(0)->is_indirect_call()) {
                        dprintf("[ret-bt] outgoing edge of up is indirect call");
                        return true;
                    }
                    if (up->get_outgoing_edge(0)->is_direct_call()) {
                        dprintf("[ret-bt] outgoing edge of up is direct call");
                        return true;
                        // TODO we can continue analysis instead of returning immediately
                    }
                }
            }
        }

        /* this means that no edges were found. we'll flush */
        ddprintf("[ret-bt]%s No edges found, flushing\n", blanks.c_str());
        return false;
    } 
    
    uint16_t all_true = true;

    /* rax must be written on all paths */
    for (size_t i = 0; i < edges_followed; i++) {
        if (bitmaps[i] == false) {
            all_true = false;
            break;
        }
    }

    free(bitmaps);
    ddprintf("[bt]%s Processed all edges, returning our best bitmap (%x)\n", blanks.c_str(), all_true);
    return all_true;

}




uint16_t ArmsLiveness::getForwardLiveness2(ArmsFunction *f,
                                       ArmsBasicBlock *bb,
                                       std::vector<ArmsBasicBlock *> fts,
                                       std::vector<ArmsBasicBlock *> argcount_analyzed_blocks) {   

    int edges_followed = 0;

    std::vector<uint16_t> bitmaps;
    std::string blanks(argcount_analyzed_blocks.size(), ' ');

    uint16_t reg_bitmap = 0;
    for (int i = 0; i < IA64_ARGS; i++) {
        set_reg_bitmap(&reg_bitmap, i, IA64_CLEAR);
    }

    /* Update the function_registers with information from the current block. */
    bool done = true;
    for (int i = 0; i < IA64_ARGS; i++) {
        if (is_reg_bitmap(reg_bitmap, i, IA64_CLEAR)) {

            StateType state;
            if (bb->is_vararg_mark()) {
                /* Stop if this block is vararg-related and responsible for
                 * writing the variadiac arguments to the stack.  
                 * The problem is that if we're in function F1, and we call
                 * variadic function F2 with 2 variaric arguments, then F2 will
                 * still write a the other arguments to the stack (and thus
                 * reads those arguments). This will result in false conclusions
                 * on the read-state of these registers.
                 */
                state = IA64_WRITE;
            } else {
                state = rw_registers[i].getState(bb);

                if (state == IA64_READ) {
                    if (rw_registers[i].getDeref(bb)) {
                        ddprintf("[ft] deref found\n");
                    }
                }
            }
                
            set_reg_bitmap(&reg_bitmap, i, state);

            if (state == IA64_CLEAR) {
                done = false;
            }

        }
    }
    
    ddprintf("[ft]%s blck_bitmap = %s (block %p)\n",blanks.c_str(), bm_tostring(reg_bitmap).c_str(), (void *)bb->get_start_address());
    
    
                
    if (bb->outgoing_edge_count() == 0) {
        /* If this block has no outgoing edges, we must stop. */
        done = true;
    }

    /* print process */
    dprintf("[ft]%s ", blanks.c_str());
    for (auto rit  = argcount_analyzed_blocks.rbegin(); 
              rit != argcount_analyzed_blocks.rend();
              rit++) {
        ArmsBasicBlock* analyzed_block = *rit;
        dprintf("%p <- ", (void *) analyzed_block->get_start_address());
    }
    dprintf("%p ", (void*)bb->get_start_address());
    dprintf("? (block has %x)\n",reg_bitmap);
    
    argcount_analyzed_blocks.insert(argcount_analyzed_blocks.begin(), bb);

    if (done) {
        ddprintf("[ft]%s All arguments processed, returning\n", blanks.c_str());
        goto ft_debug_return;
        return reg_bitmap;
    }






    for (size_t i = 0; i < bb->outgoing_edge_count(); i++) {
    
        bitmaps.push_back(reg_bitmap);

        ArmsEdge *edge = bb->get_outgoing_edge(i);
        ArmsBasicBlock *next_bb = NULL;
        ArmsBasicBlock *fallthrough_bb = NULL;

        ddprintf("[ft]%s Edge %lu/%lu ",blanks.c_str(),i+1,bb->outgoing_edge_count());

    
        if (edge->is_return()) {
            /* do we have a fallthrough to follow? */
            if (!fts.empty()) {
                ddprintf("is return, continuing at fallthrough\n");
                next_bb = fts.back();
                fts.pop_back();
            } else {
                ddprintf("is return, but not fallthrough found. End of function?\n");
                reg_bitmap = bitmaps[i];
                goto ft_debug_return;
                return reg_bitmap;
            }
        } else if (edge->is_direct_call()) {
            ddprintf("is direct call, storing fallthrough\n");

            next_bb = edge->target();
            fallthrough_bb = bb->get_fallthrough_bb();
       
            assert(next_bb != NULL);

            /* some direct calls never return, in which case we do not look at
             * the fallthrough. */
            if (fallthrough_bb == NULL) {
                ddprintf("[ft]%s fallthrough is null. assuming non-returning\n", blanks.c_str());
            } else if (isNop(fallthrough_bb)) {
                ddprintf("[ft]%s fallthrough is nop. assuming non-returning\n", blanks.c_str());
                fallthrough_bb = NULL;
            } else if (fallthrough_bb->is_entry_block()) {
                ddprintf("[ft]%s fallthrough is entry block. assuming non-returning\n", blanks.c_str());
                fallthrough_bb = NULL;
            } else {
                ddprintf("[ft]%s fallthr: %p\n", blanks.c_str(), (void *)fallthrough_bb->get_start_address());
                
                if (next_bb->get_function() != NULL &&
                    next_bb->get_function()->is_plt()) {
                
                    if (next_bb->get_function()->get_name() == "exit") {
                        ddprintf("[ft]%s direct call to exit@plt, non returning\n", blanks.c_str());
                        fallthrough_bb = NULL;
                    } else {
                        ddprintf("[ft]%s direct call to PLT stub, continuing straight at fallthrough\n", blanks.c_str());
                        next_bb = fallthrough_bb;
                    }
                } else {
                    fts.push_back(fallthrough_bb);
                }
            }
        } else if (edge->is_indirect_call()) {
            // TODO: with profiling, the story becomes a bit different. I don't think it matters for now
            ddprintf("is indirect call, continuing at fallthrough\n");
//          assert(bb->outgoing_edge_count() == 1);

            fallthrough_bb = bb->get_fallthrough_bb();

            /* maybe there is icall tail optimization? - not supported*/
//          assert(fallthrough_bb != NULL);
            if (fallthrough_bb == NULL) {
                continue;
            }

//          assert(!fallthrough_bb->is_entry_block());
            if (fallthrough_bb->is_entry_block()) {
                /* let's assume this is not part of the same function */
                continue;
            }
//          assert(!isNop(fallthrough_bb));

            next_bb = fallthrough_bb;
        } else {
            ddprintf("is regular\n");
            next_bb = edge->target();
        }

        assert(next_bb != NULL);

        ddprintf("[ft]%s Next block: %p\n", blanks.c_str(), (void *) next_bb->get_start_address());

        if (std::find(argcount_analyzed_blocks.begin(),
                      argcount_analyzed_blocks.end(),
                      next_bb) != argcount_analyzed_blocks.end()) {
            ddprintf("[ft]%s Next block is already analyzed (loop detection)\n", blanks.c_str());
            bitmaps[i] = (0x0);
            continue;
        }

        if (forward_cache.count(next_bb)) {
            ddprintf("[ft]%s Cache lookup\n",blanks.c_str());
        } else {
            ddprintf("[ft]%s Entering recursing\n",blanks.c_str());
            forward_cache[next_bb] = this->getForwardLiveness2(f, next_bb, fts, argcount_analyzed_blocks);
        }
        bitmaps[i] = forward_cache[next_bb];
        
        ddprintf("[ft]%s Got bitmap %x\n", blanks.c_str(), forward_cache[next_bb]);
        
        edges_followed++;
    }
        
    ddprintf("[ft]%s followed %d edges\n", blanks.c_str(), edges_followed);

    if (edges_followed == 0) {
        ddprintf("[ft]%s No edges followed\n", blanks.c_str());
    } else {
        uint16_t best_bitmap = 0xfff; /* start with worst-case, all clear */

        ddprintf("[ft]%s Computing best bitmap\n", blanks.c_str());
        dprintf("[ft]%s blck_bitmap = %s (block %p)\n",blanks.c_str(), bm_tostring(reg_bitmap).c_str(), (void *)bb->get_start_address());
        for (auto it  = bitmaps.begin(); 
                  it != bitmaps.end();
                  it++) {
            uint16_t bitmap = *it;

            dprintf("[ft]%s      bitmap = %s\n", blanks.c_str(), bm_tostring(bitmap).c_str());
            for (int i = 0; i < IA64_ARGS; i++) {

#ifdef ALLOW_UNINITIALIZED_READ
                if (is_reg_bitmap(best_bitmap, i, 0x3)) {
                    /* if no state found yet, use the child's state */
                    set_reg_bitmap(&best_bitmap, i, get_reg_bitmap(bitmap, i));
                } else if (is_reg_bitmap(best_bitmap, i, IA64_READ)) {
                    /* if our current state is READ, then ALL children must be READ also. Or CLEAR.
                     */
                    if (is_reg_bitmap(bitmap, i, IA64_READ)) {
                        /* ... */
                    } else if (is_reg_bitmap(bitmap, i, IA64_WRITE)) {
                        set_reg_bitmap(&best_bitmap, i, IA64_WRITE);
                    } else if (is_reg_bitmap(bitmap, i, IA64_RW)) {
                        set_reg_bitmap(&best_bitmap, i, IA64_RW);
                    } else if (is_reg_bitmap(bitmap, i, IA64_CLEAR)) {
                        set_reg_bitmap(&best_bitmap, i, IA64_CLEAR);
                    }
                } else if (is_reg_bitmap(best_bitmap, i, IA64_CLEAR)) {
                    /* if our current state CLEAR, we can become WRITE */
                    if (is_reg_bitmap(bitmap, i, IA64_WRITE)) {
                        set_reg_bitmap(&best_bitmap, i, IA64_WRITE);
                    } else if (is_reg_bitmap(bitmap, i, IA64_RW)) {
                        set_reg_bitmap(&best_bitmap, i, IA64_RW);
                    }
                }
#else 
                if (is_reg_bitmap(best_bitmap, i, 0x3)) {
                    set_reg_bitmap(&best_bitmap, i, get_reg_bitmap(bitmap, i));
                } else if (is_reg_bitmap(best_bitmap, i, IA64_WRITE) ||
                           is_reg_bitmap(best_bitmap, i, IA64_RW) ||
                           is_reg_bitmap(best_bitmap, i, IA64_CLEAR)) {

                    if (is_reg_bitmap(bitmap, i, IA64_READ)) {
                        set_reg_bitmap(&best_bitmap, i, IA64_READ);
                    } else if(is_reg_bitmap(bitmap, i, IA64_WRITE)) {
                        /* ... */
                    } else if (is_reg_bitmap(bitmap, i, IA64_RW)) {
                        /* ... */
                    } else if (is_reg_bitmap(bitmap, i, IA64_CLEAR)) {
                        /* ... */
                    }
                }
#endif 




            }
        }
        dprintf("[ft]%s comb_bitmap = %s\n", blanks.c_str(), bm_tostring(best_bitmap).c_str());

    
        /* combine */
        for (int i = 0; i < IA64_ARGS; i++) {
            if (is_reg_bitmap(reg_bitmap, i, IA64_CLEAR)) {
                set_reg_bitmap(&reg_bitmap, i, get_reg_bitmap(best_bitmap,i));
            }
        }
        dprintf("[ft]%s updt_bitmap = %s\n", blanks.c_str(), bm_tostring(reg_bitmap).c_str());
    }

    ddprintf("[ft]%s Processed all edges, returning our best bitmap (%x)\n", blanks.c_str(), reg_bitmap);
    goto ft_debug_return;
    return reg_bitmap;

ft_debug_return:
    dprintf("[ft]%s ", blanks.c_str());
    for (auto rit  = argcount_analyzed_blocks.rbegin(); 
              rit != argcount_analyzed_blocks.rend();
              rit++) {
        ArmsBasicBlock* analyzed_block = *rit;
        dprintf("%p <- ", (void *) analyzed_block->get_start_address());
    }
    dprintf("(%x)\n",reg_bitmap);

    return reg_bitmap;
}


bool ArmsLiveness::getForwardLiveness(ArmsFunction *f,
                                     ArmsBasicBlock *bb) {   

    dprintf("[rec] Looking at block %p\n", (void *)bb->get_start_address());
    dprintf("[rec]   Register status: ");

    bool done = true;
    /* update the argc_registers with information from the current block */
    /* except if this block is vararg-related and responsible for writing
     * the variadiac arguments to the stack, we stop here. 
     * The problem is that if we're in function F1, and we call variadic
     * function F2 with 2 variaric arguments, then F2 will still write a the
     * other arguments to the stack (and thus reads those arguments). This
     * will result in false conclusions on the read-state of these registers.
     */
    if (bb->is_vararg_mark()) {
        /* just stop here */
        for (int i = 0; i < IA64_ARGS; i++) {
            if (argc_registers[i] == IA64_CLEAR) {
                argc_registers[i] = IA64_WRITE;
            }
            dprintf("%d ", argc_registers[i]);
        }
        dprintf(" (vararg-mark)\n");
    } else {

        for (int i = 0; i < IA64_ARGS; i++) {
            if (argc_registers[i] == IA64_CLEAR) {
                argc_registers[i] = rw_registers[i].getState(bb);
                if (argc_registers[i] == IA64_CLEAR) done = false;
            }
            dprintf("%d ",argc_registers[i]);
        }
        dprintf("\n");
    }

    argc_analyzed_blocks.insert(bb);


    /* we can stop once we reach the point that we have a state for all registers. */
    if (done) return true;
    /* this of course should be improved by keeping track of all possible subpaths and then select
     * the path for which we get the most read before writes */


    ArmsBasicBlock *fallthrough_bb = NULL;

    /* we need to continue discovering this branch, if possible */
    /* TODO. This code is very similar to the one where we parse blocks to get
     * the information in the first place. Maybe we can easily merge this.
     * That could infect our varargs detection though.
     */
    for(size_t i = 0; i < bb->outgoing_edge_count(); i++) {
        ArmsEdge *edge = bb->get_outgoing_edge(i);
        ArmsBasicBlock *next_bb;
        
        dprintf("[rec] edge: %lu/%lu\n",i+1,bb->outgoing_edge_count());
  
        if (edge->is_return()) {
            /* We won't follow return edges. Instead, when we discover a direct
             * call, we mark it's fallthrough basic block as additional edge target. That way, 
             * if we run into a direct call, we always fall back to its return.
             * Additionally, this ensures that we won't follow return edges for the
             * actual function that we are analyzing.
             */
            dprintf("[rec]  > Not following return edge\n");
            continue;
        } else if (edge->is_direct_call()) {
            dprintf("[rec]  > Following direct call, adding fallthrough bb as additional block that we should analyze\n");
           
            /* some direct calls never return, in which case we do not look at
             * the fallthrough */
            if (edge->target() != NULL &&
                edge->target()->get_function() != NULL &&
                (edge->target()->get_function()->get_name() == "_EXIT" ||
                 edge->target()->get_function()->get_name() == "_exit")) {
                dprintf("[rec]  > Call to _EXIT, not looking at fallthrough bb\n");
                continue;
            } else {
                next_bb = edge->target();
                fallthrough_bb = bb->get_fallthrough_bb();
            }
            if (next_bb != NULL)        dprintf("[rec] next_bb: %p\n", (void *) next_bb->get_start_address());
            if (fallthrough_bb != NULL) dprintf("[rec] fallthr: %p\n", (void *)fallthrough_bb->get_start_address());
        } else if(edge->is_indirect_call()) {
            /* We cannot follow indirect calls. We can not increase our
             * knowledge any further at this point: the target may read argument
             * registers that are passed to us without them being read before
             * this point.
             * */
            dprintf("[rec]  > Not following indirect call edge, we are done\n");
            /* TODO can't we just return here directly? */
            continue;
        } else {
            dprintf("[rec]  > Getting target of edge\n");
            next_bb = edge->target();
        }

        if (next_bb == NULL) {
            dprintf("[rec]  > next bb does not exist\n");
            continue;
        }

        if (fallthrough_bb != NULL) {
            if (edge->is_direct_call() && isNop(fallthrough_bb)) {
                dprintf("[rec]  > fallthrough is nop while last edge was a direct call. Assuming non-returning\n");
                fallthrough_bb = NULL;
            } else if (edge->is_direct_call() && fallthrough_bb->is_entry_block()) {
                dprintf("[rec]  > fallthrough is entry block while last edge was a direct call. Assuming non-returning\n");
                fallthrough_bb = NULL;
            }
        }

        if (argc_analyzed_blocks.find(next_bb) != argc_analyzed_blocks.end()) {
            dprintf("[rec]  > next bb is already analyzed\n");
            continue;

            /* TODO. This is not completely ok. We should actualy continue
             * analysis if the path found is a 'better' one. Depending on our
             * results, we may have to implement this....
             */
        }
        
        /* this is also import for varargs... */
        dprintf("next bb is entry block? %d\n", next_bb->is_entry_block());
        if (edge->is_interprocedural() && next_bb->is_entry_block()) {
            /* we are making a function call. Maybe we already completed
             * analysis for this function. */
            ArmsFunction *callee = next_bb->get_function();
            dprintf("callee is exactly one? %p\n", callee);
            /* even if it is one, we should search all callees. then pick the callee for which it's
             * starting basic block equals this basic block and match the argcount.
             */

            if (callee && callee->get_argcount() != -1) {
                /* yes, we analyzed this one */

                if (callee->get_argcount() == 0) {
                    // nothing to do
                } else {
                    if (argc_registers[callee->get_argcount()-1] == IA64_CLEAR)
                        argc_registers[callee->get_argcount()-1] = IA64_READ;
                }

                continue;
            }
        } 
        if (this->getForwardLiveness(f, next_bb)) return true;
        
        
        /* do we still have a fallback to analyze perhaps? */
        if (fallthrough_bb == NULL) {
            dprintf("[rec]  > no fallthrough\n");
            continue;
        } 
        if (argc_analyzed_blocks.find(fallthrough_bb) != argc_analyzed_blocks.end()) {
            dprintf("[rec]  > fallthrough already analyzed\n");
            continue;
        }

        if (this->getForwardLiveness(f, fallthrough_bb)) return true;

    }

    return false;
}


/* only perform the variadic detection. We need to have exclusive results on this before we run 
 * func-arg detection */
int ArmsLiveness::get_vararg_count(ArmsFunction *f) {
    /* Only if this function was analyzed */
    if (function_blocks.count(f) == 0) {
        return -1;
    }
    
    int argcount = is_variadic(f);
    if (argcount) {
        f->set_variadic();
        f->set_argcount(argcount);
        ddprintf("Detected variadic function with %d fixed arguments: %s\n", 
                argcount, f->get_name().c_str());
        return argcount;
    }

    return -1;
}

int ArmsLiveness::get_arg_count(ArmsFunction *f) {
    /* Only if this function was analyzed */
    if (function_blocks.count(f) == 0) {
        return -1;
    }


    /* before doing anything else, search for writes on RAX to get the status for return value use */
    dprintf("\n=== Starting retuse analysis for function %s ===\n", f->get_name().c_str());

    /* Start with the exit blocks of this function. */
    std::vector<ArmsBasicBlock*> exit_blocks;
    exit_blocks.assign(f->get_exit_points()->begin(), f->get_exit_points()->end());

    /* Recursively analyze each block of the function starting from the entry blocks */
    /* This is a depth first search */

    std::vector<ArmsBasicBlock *> callee_retuse_analyzed_blocks;
   
    f->set_write_rax(true);
    dprintf("-> number of exit blocks: %lu\n", exit_blocks.size());
    while(exit_blocks.size() > 0) {
        callee_retuse_analyzed_blocks.clear();

        ArmsBasicBlock *bb = exit_blocks.back();
        exit_blocks.pop_back();

        /* all exit points of the callee must be the result of a path that writes rax */
        if (!getRAXwrites(f, bb, callee_retuse_analyzed_blocks)) {
            f->set_write_rax(false);
            break;
        }
    }

    dprintf("=== Finished retuse analysis for function %s: %d ===\n\n", f->get_name().c_str(), f->get_write_rax());




    if (f->get_argcount() != -1) {
        /* this is a variadic function. not proceeding */
        return -1;
    }


    /* ASSUMING THAT This is *NOT* a variadic function */

    /* Conservative strategy:
     * - do not analyze nested function calls
     * - assume *all* parameter registers are used at some point in the function
     */

#if STRATEGY_TYPE == STRATEGY_CONSERVATIVE
    for (argcount = 0; argcount < IA64_ARGS; argcount++) {
        ddprintf("  [args] %d: %s - %s\n", argcount, get_register_name(argcount   ).c_str(), 
                                                     get_regstate_name(argcount, f).c_str());
        if (!rw_registers[argcount].isRead(function_blocks[f])) {

#if STRATEGY_OPTIONS & STRATEGY_CON_OPT_EXPECT_2ND_RETVAL
            /* RDX may be used to store a second return value. We currenly only see
             * this in vsftpd... */
            if (argcount-1 == IA64_RDX) {
   
                /* We do not have to decrease the argcount if RDX was read
                 * before a call instruction */
                std::vector<ArmsBasicBlock *> blocks;
                for (std::vector<ArmsBasicBlock *>::iterator it  = function_blocks[f].begin();
                                                             it != function_blocks[f].end();
                                                             it++) {
                    ArmsBasicBlock *bb = *it;
                    blocks.push_back(bb);
                    if (bb->outgoing_contains_inter()) break;
                }

                ArmsBasicBlock *rdx_read_block = rw_registers[IA64_RDX].getReadBB(function_blocks[f]);

                if (find(blocks.begin(), blocks.end(), rdx_read_block) != blocks.end()) {
                    /* The first READ RDX instruction occurs before a call instruction. */
                } else {
                    /* The first READ RDX is after a call instruction. Without
                     * performing recursion, we must assume it was set by a child
                     * function as a second return value and thus decrement the
                     * argcount.
                     */
                    argcount--;
                }
                
            }
#endif // STRATEGY_CON_OPT_EXPECT_2ND_RETVAL
            break;
        }
    }
#elif STRATEGY_TYPE == STRATEGY_RECURSIVE
    ddprintf("\n=== Starting recursive analysis for function %s ===\n", f->get_name().c_str());
       
    /* Start with the entry blocks of this function. */
    std::vector<ArmsBasicBlock*> entry_blocks;
    entry_blocks.assign(f->get_entry_points()->begin(), f->get_entry_points()->end());

    /* Recursively analyze each block of the function starting from the entry blocks */
    /* This is a depth first search */

    for (int i = 0; i < IA64_ARGS; i++) {
        argc_registers[i] = IA64_CLEAR;
    }
    argc_analyzed_blocks.clear();

    while(entry_blocks.size() > 0) {
        ArmsBasicBlock *bb = entry_blocks.back();
        entry_blocks.pop_back();


        if (argc_analyzed_blocks.find(bb) == argc_analyzed_blocks.end()) 
            getForwardLiveness(f, bb);
    }

    int argcount = 0;
    for (int i = IA64_ARGS; i >=0; i--) {
        if (argc_registers[i] == IA64_READ) {
            argcount = i+1;
            break;
        }
    }

    ddprintf("=== Finished recursive analysis ===\n\n");

#elif STRATEGY_TYPE == STRATEGY_CONCLUSIVE
    dprintf("\n=== Starting conclusive analysis for function %s ===\n", f->get_name().c_str());

    /* Start with the entry blocks of this function. */
    std::vector<ArmsBasicBlock*> entry_blocks;
    entry_blocks.assign(f->get_entry_points()->begin(), f->get_entry_points()->end());

    /* Recursively analyze each block of the function starting from the entry blocks */
    /* This is a depth first search */

    uint16_t reg_bitmap = 0;
    for (int i = 0; i < IA64_ARGS; i++) {
        set_reg_bitmap(&reg_bitmap, i, IA64_CLEAR);
    }
    std::vector<ArmsBasicBlock *> argcount_analyzed_blocks;
    std::vector<ArmsBasicBlock *> fts;
    argcount_analyzed_blocks.clear();

    assert(entry_blocks.size() == 1);

    reg_bitmap = getForwardLiveness2(f, entry_blocks[0], fts, argcount_analyzed_blocks);

    int argcount = 0;
    for (int i = IA64_ARGS; i >=0; i--) {
        if (get_reg_bitmap(reg_bitmap, i) == IA64_READ) {
            argcount = i+1;
            break;
        }
    }

    dprintf("=== Finished recursive analysis for function %s: %d ===\n\n", f->get_name().c_str(), argcount);
#endif


    ddprintf("Detected normal function with %d arguments: %s\n", argcount, f->get_name().c_str());
    f->set_argcount(argcount);


    return argcount;
}

/* If the provided set of preceding_blocks contain entry_blocks for function f,
 * recursively continue searching for preceding blocks in callers of f.
 *
 * returns true if the preceding blocks contain entry blocks.
 */

#define MAX_DEPTH 10

bool follow_entry_blocks(std::set<ArmsBasicBlock *> *preceding_blocks, ArmsFunction *f, 
                         std::set<ArmsFunction   *> *processed_callers, 
                         int depth) {

    /* It could happen that we end up with an entry block that has zero callers.
     * In exim with -O1, for example, there is a function dbmdb_find() that is
     * called by dbmnz_find() which is called from nowhere. We must then
     * conclude that dbmnz_find() could be the target of an indirect call itself
     * (it should have its address taken) and, as we cannot continue the live
     * analysis recursively, must conclude that we cannot determine the argcount
     * for the indirect callsite.
     *
     * We will use entry_block_left as a boolean that is true if the set of
     * preceding blocks contain an entry block with zero callers. Moreover, this
     * is only true if there is no other entry block higher up the CFG that has
     * a caller.
     */
    bool entry_block_left = true;

    std::set<ArmsBasicBlock*>* entry_blocks = f->get_entry_points(); 
    for (std::set<ArmsBasicBlock *>::iterator it  = entry_blocks->begin();
                                              it != entry_blocks->end();
                                              it++) {
        ArmsBasicBlock *entry_block = *it;
        if (preceding_blocks->count(entry_block)) {


            /* Set of preceding blocks contains an entry block, look at callers */
            std::set<ArmsFunction *> callers = f->get_callers();
            

            for (std::set<ArmsFunction*>::iterator it  = callers.begin();
                                                   it != callers.end();
                                                   it++) {
                ArmsFunction *caller = *it;

                if (processed_callers->count(caller))
                    /* Already processed */
                    continue;

                dprintf("Looking at caller %s\n", caller->get_name().c_str());
                processed_callers->insert(caller);
                entry_block->get_preceding_bbs(preceding_blocks, caller->get_basic_blocks());

                /* Recursion */
                if (depth < MAX_DEPTH) {
                    bool res = follow_entry_blocks(preceding_blocks, caller, processed_callers, depth++);
                    if (entry_block_left) entry_block_left = res;
                } else {
                    dprintf("Reached maxdepth\n");
                    entry_block_left = false;
                }
            }
        } else {
            entry_block_left = false;
        }
    }

    return entry_block_left;
}

RegisterAST::Ptr ArmsLiveness::is_dereference(Instruction::Ptr iptr) {
    std::vector<Operand> operands;
    iptr->getOperands(operands);
    for (std::vector<Operand>::iterator it  = operands.begin();
                                        it != operands.end();
                                        it++) {
        Operand operand = *it;
        Expression::Ptr expr = operand.getValue();

        /* we are only interested in operands that are read */
        if (!operand.isRead()) continue;

        /* if more than two registers are used, either one may contain a
         * pointer. so we can only support operands that read one register.
         * let's assume that if we see a computation with a constant, the
         * constant is never an address. */
        std::set<RegisterAST::Ptr> register_set;
        register_set.clear();
        operand.getReadSet(register_set);
        if (register_set.size() != 1) continue; 
            
        RegisterAST::Ptr reg;
        for (std::set<RegisterAST::Ptr>::iterator it  = register_set.begin(); 
                                                  it != register_set.end(); 
                                                  it++) {
            reg = *it;
        }

        OperandType operandType;
        operand.getValue()->apply(&operandType);
        if (operandType.dereference)  {
            dprintf("      [dereference read-operand]: %s\n", operand.format(Arch_x86_64).c_str());
            return reg;
        }
    }
    return NULL;
}

/* returns true if the provided instruction contains a computation */
bool ArmsLiveness::computation_used(Instruction::Ptr iptr) {
    std::vector<Operand> operands;
    iptr->getOperands(operands);
    for (std::vector<Operand>::iterator it  = operands.begin();
                                        it != operands.end();
                                        it++) {
        Operand operand = *it;
        Expression::Ptr expr = operand.getValue();

        OperandType operandType;
        operand.getValue()->apply(&operandType);
        if (operandType.binaryFunction) 
            return true;
    }
    return false;
}

#define ICALL_OPTIMIZATION_MIN_ARG_USE_ICALLS 10        // X below
#define ICALL_OPTIMIZATION_MIN_ARG_USE_PERCENTAGE 40    // Y below
/* Without any optimization, we found that many indirect call instructions use
 * one of the argument registers as target address, e.g., call *%rcx. In these
 * cases the used argument register limits the upper bound of the number of prepared
 * parameters for the called function (in the case of call *%rcx, a maximum of 3
 * parameters shall be provided: %rdi, %rsi and %rdx). This is a perfect means
 * to fixate the maximum number of arguments prepared at an indirect callsite.
 *
 * We also observed that without optimization, not many indirect call
 * instructions that use one of the arguments registers consist of a
 * computation. In other words, we won't see many instructions like call
 * *0x50(%rcx). However, with optimization enabled (starting from -O1 already),
 * these computations become much more common, while at the same time the number
 * of call *%<arg_register> instructions (without the use of a computation)
 * drops drastically.
 *
 * As such, we implemented a mechanism that detects whether indirect call
 * instructions are optimized or not. By default, we assume the binary is
 * optimized. However, if we see more than X occurences of indirect call
 * instructions that use an argument register, say N, we take a closer look. If,
 * for those N instructions, the percentage of instructions that contain a
 * computation is less than Y, we conclude that the binary (or at least the
 * indirect call instructions) is unoptimized and we can thus rely on above
 * information (limiting the upper bound of prepared arguments by looking at the
 * target register).
 */

/* Returns true if indirect calls are optimized */
bool ArmsLiveness::icalls_optimized(void) {

    if (opt_detector_completed) return is_optimized;

    unsigned int icalls = 0;
    unsigned int icalls_with_arg_use = 0;
    unsigned int icalls_with_arg_use_and_computation = 0;

    for (std::map<ArmsFunction *, std::set<ArmsBasicBlock *> > ::iterator ix  = icall_blocks.begin();
                                                                          ix != icall_blocks.end();
                                                                          ix++) {
        ArmsFunction *f = ix->first;
        dprintf("Looking at f: %s\n", f->get_name().c_str());

        for (std::set<ArmsBasicBlock *>::iterator it  = icall_blocks[f].begin();
                                                  it != icall_blocks[f].end();
                                                  it++, icalls++) {
            ArmsBasicBlock *block = *it;

            /* Get the indirect call instruction */
            unsigned long icall_addr = block->get_last_insn_address();
            dprintf("- indirect call at %p\n", (void *) icall_addr);

            ParseAPI::Block *pblock = (ParseAPI::Block *) block->get_parse_block();
            Instruction::Ptr iptr = pblock->getInsn( icall_addr );

            /* Get the first argument register that is used by this instruction (if any) */
            int arg_register = getFirstReadArgRegister(block, icall_addr);


            /* If any... */
            if (arg_register != IA64_ARGS) {
                /* ... determine whether a computation was used. If more than
                 * ICALL_OPTIMIZATION percent of these instructions contain a
                 * computation, we conclude that the indirect call instructions are
                 * optimzed.
                 */
                if (computation_used(iptr))
                    icalls_with_arg_use_and_computation++;

                icalls_with_arg_use++;
            }
        }
    }

    opt_detector_completed = true;

    dprintf("[icall-optimization-detection] #icalls:                       %3u\n", icalls);
    dprintf("[icall-optimization-detection] #icalls arg use:               %3u\n", icalls_with_arg_use);
    dprintf("[icall-optimization-detection] #icalls arg use + computation: %3u\n", icalls_with_arg_use_and_computation);
    if (icalls_with_arg_use > ICALL_OPTIMIZATION_MIN_ARG_USE_ICALLS) {
        float percentage = (float) icalls_with_arg_use_and_computation / (float) icalls_with_arg_use * 100.0;
        dprintf("[icall-optimization-detection] percentage:                    %5.2f\n", percentage);
        if (percentage < ICALL_OPTIMIZATION_MIN_ARG_USE_PERCENTAGE)
            is_optimized = false;
    }

    dprintf("[icall-optimization-detection] icalls optimized? %d\n", is_optimized);

    return is_optimized;
}



int ArmsLiveness::get_icallsites(ArmsFunction *f) {
    /* Assumes that get_arg_count() was called for all functions.
     *
     * TODO We should build one main function that accepts the CFG and then
     * performs all the analysis for us.
     */

    
    int i = 0;
    for (std::set<ArmsBasicBlock *>::iterator it  = icall_blocks[f].begin();
                                              it != icall_blocks[f].end();
                                              it++, i++) {
        ArmsBasicBlock *block = *it;
        unsigned long icall_addr = block->get_last_insn_address();
        dprintf("\n%s() got icall in basic block: %p\n", f->get_name().c_str(), (void*)block->get_start_address());


        std::vector<ArmsBasicBlock *> retuse_analyzed_blocks;
        std::vector<ArmsBasicBlock *> retuse_fts;

        /* search for reads on rax first */
        if (block->get_fallthrough_bb() == NULL) {
            // tail icall optimization? assume whatever */
            block->set_read_rax(false);
        } else if (getRAXreads(f, block->get_fallthrough_bb(), retuse_fts, retuse_analyzed_blocks)) {
            block->set_read_rax(true);
            dprintf("!! icallsite %s.%d (%p) reads RAX !!\n", f->get_name().c_str(), i, (void *)block->get_last_insn_address());
        } else {
            block->set_read_rax(false);
        }



    
        uint16_t reg_bitmap = 0;
        for (int i = 0; i < IA64_ARGS; i++) {
            set_reg_bitmap(&reg_bitmap, i, IA64_READ);
        }
        std::vector<ArmsBasicBlock *> callsite_analyzed_blocks;
        callsite_analyzed_blocks.clear();

        reg_bitmap = getBackwardLiveness(f, block, callsite_analyzed_blocks);

        int argcount = 6;
        for (int i = 0; i < IA64_ARGS; i++) {
            if (get_reg_bitmap(reg_bitmap, i) != IA64_WRITE) {
                argcount = i;
                break;
            }
        }
                

        int max_arguments = argcount;
        int min_arguments = argcount;


#if 0 

        /* Get the indirect call instruction */
        ParseAPI::Block *pblock = (ParseAPI::Block *) block->get_parse_block();
        Instruction::Ptr iptr = pblock->getInsn( icall_addr );
        
        dprintf("                indirect call instruction at: %p - %s\n", (void *)icall_addr, iptr->format(0).c_str());
  

        int min_arguments = 0;
        int max_arguments = IA64_ARGS;

        /* Without optimization, we can assume that if one of the argument
         * registers holds the target of the indirect call instruction, then the
         * previous argument must, at best, be the last argument that the callee
         * accepts. In other words, if we see a call *rdx, we assume that the
         * target accepts at most 3 arguments (passed in rsi, rdi and rcx).
         *
         * Of course, this does not always have to be the case. Applying
         * optimization may result in special indirect call instructions where
         * even more arguments are used. For example, if the callee
         * expects a 'this' pointer:
         *
         *         ret = srv->network_backend_write(srv, con, con->fd, cq);
         *  40d885:   48 8b 75 e8             mov    -0x18(%rbp),%rsi
         *  40d889:   8b 56 50                mov    0x50(%rsi),%edx
         *  40d88c:   48 8b 4d e0             mov    -0x20(%rbp),%rcx
         *  40d890:   48 8b 7d f0             mov    -0x10(%rbp),%rdi
         *  40d894:   ff 97 f0 02 00 00       callq  *0x2f0(%rdi)
         *  40d89a:   89 45 dc                mov    %eax,-0x24(%rbp)
         *
         *  If the first field of a datastructure holds a function pointer, we
         *  could also see:
         *
         *         u->read_event_handler(r, u);
         *  43f0be:   ff 16                   callq  *(%rsi)
         *
         *  We only see this behavior when the indirect call instructions are
         *  optimized though.
         */
        if (!icalls_optimized()) max_arguments = getFirstReadArgRegister(block, icall_addr);

        /* Perform 'backward live analysis': starting from the last possible
         * argument register, test if these registers are written by any basic
         * block of this function that precedes the icall instruction.
         */
        
        /* First, get all the preceding basic blocks.
         * XXX The current implementation of get_preceding_bbs does not follow
         * fallthrough edges. This means that the fetching preceding blocks
         * stops at (direct) call instructions. This may actually be a good
         * thing: if we see high argument registers being written here (r8, r9),
         * we know for sure that these are not used for a direct call
         * instruction that happens to expect 5-6 arguments. On the other hand,
         * an optimization may set these registers before such call instruction
         * in which case we will underestimate.
         */
        std::set<ArmsBasicBlock *> preceding_blocks;
        block->get_preceding_bbs(&preceding_blocks, f->get_basic_blocks());
        preceding_blocks.insert(block);

        std::set<ArmsBasicBlock *>::iterator iter;
        for(iter = preceding_blocks.begin(); iter != preceding_blocks.end(); iter++) {
            ArmsBasicBlock *bb = *iter;
            dprintf("preceding block: %p - %p\n", (void *) bb->get_start_address(), (void *) bb->get_last_insn_address()); 
        } 
        
        /* if any(f->entry_blocks) in preceding_blocks:
         *      it could be that a function argument is redirect to the icall
         *      invocation directly. we must assume that the last argument may
         *      could be used with an explicit write.
         *          - we can try to rely on our function-argcount detection,
         *          however, that is an underestimation at best, so it won't be
         *          100% fool proof.  ---> found one in vsftpd :(  hash_get_bucket
         *                                      exim  - dbmdb_find
         *          - instead, we could simply maximize argcount for these icalls which is
         *          probably bad.
         *          - we will perform a recursive lookup!
         */


        std::set<ArmsFunction *> processed_callers;
        bool maybe_address_taken = follow_entry_blocks(&preceding_blocks, f, &processed_callers, 0);

        if (maybe_address_taken) dprintf("ADDRESS COULD BE TAKEN!\n");

        
        for(iter = preceding_blocks.begin(); iter != preceding_blocks.end(); iter++) {
            ArmsBasicBlock *bb = *iter;
            dprintf("(after following entries) preceding block: %p - %p\n", (void *) bb->get_start_address(), (void *) bb->get_last_insn_address()); 
        } 

        /* Assume that all argument registers are written - no gaps */
                /* we need to look at the paths, and then look at the minimum.
                 * and we need to follow through direct call (get thrash registered)
                 * and we can ignore indirect calls (reuse) */
        int j;
        for (j = 0; j < max_arguments; j++) {
            ddprintf("  %s written in preceding blocks: %d\n", 
                            get_register_name(j).c_str(),
                            rw_registers[j].writtenInBlocks(preceding_blocks));
            if (!rw_registers[j].writtenInBlocks(preceding_blocks)) {
                break;
            }
        }
        max_arguments = j;



   

        if (maybe_address_taken) 
            /* TODO confirm that one of the addresses actually taken... */
            max_arguments = IA64_ARGS;
        dprintf("max-arguments: %d\n", max_arguments);
#endif

        // going bold
        block->set_icall_args(max_arguments);


        if (min_arguments == max_arguments) {
            dprintf("!! icallsite %s.%d sets exactly %d arguments !!\n", f->get_name().c_str(), i, max_arguments);
        } else {
            dprintf(" !! icallsite %s.%d sets %d to %d arguments !!\n", f->get_name().c_str(), i, min_arguments, max_arguments);
        }
        
        std::set<ArmsFunction*> dependencies = f->get_dependencies();
            for (auto it  = dependencies.begin();
                      it != dependencies.end();
                      it++) {
                ArmsFunction *dep = *it;
                dprintf("[bt] icall %s.%d (%p) may benefit from profiling (now: %d args): lone (possible AT) function: %s (%p)\n", f->get_name().c_str(), i, (void*)block->get_last_insn_address(), max_arguments, dep->get_name().c_str(), (void *)dep->get_base_addr());
                block->add_dependency(dep);
            }
            f->clear_dependencies();
        
    }
}


