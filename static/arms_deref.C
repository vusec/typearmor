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
#include "arms_deref.h"

#include <liveness.h>

#define DEBUG
#define DDEBUG

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

string ArmsDerefRegister::getStateName(D_StateType state) {
    switch(state) {
        case D_IA64_DEREF: return "deref";
        case D_IA64_WRITE: return "write";
        case D_IA64_CLEAR: return "clear";
        default: {
                     dprintf("WTF: %d\n", state);
                     return "unkown";
                 };
    }
}


void ArmsDerefRegister::setState(ArmsBasicBlock *block, unsigned long offset, D_StateType state) {
//  dprintf("setState(%p, %p, %d) (this: %p)\n", block, (void *) offset, state, this);

    block_list[block][offset] = state;
}
void ArmsDerefRegister::setDeref(ArmsBasicBlock *block, unsigned long offset) {
    setState(block, offset, D_IA64_DEREF);
}
void ArmsDerefRegister::setWrite(ArmsBasicBlock *block, unsigned long offset) {
    setState(block, offset, D_IA64_WRITE);
}

bool ArmsDerefRegister::writtenInBlock(ArmsBasicBlock *block) {
    D_StateType reg_state;

    for (state_it_type it  = block_list[block].begin();
                       it != block_list[block].end();
                       it++) {
        unsigned long insn_offset = it->first;
        reg_state = it->second;

        if (reg_state == D_IA64_WRITE) return true;
    }

    return false;
}

bool ArmsDerefRegister::writtenInBlocks(std::set<ArmsBasicBlock *> blocks) {

    for (std::set<ArmsBasicBlock *>::iterator it  = blocks.begin();
                                              it != blocks.end();
                                              it++) {
        ArmsBasicBlock *block = *it;
        if (writtenInBlock(block)) return true;
    }

    return false;
}



/* Returns the RW state for this register in a specific block. This assumes
 * that the instructions for this block were parsed in consecutive order. */
D_StateType ArmsDerefRegister::getState(ArmsBasicBlock *block) {
    D_StateType reg_state = D_IA64_CLEAR; /* register is untouched by default */

    if (block_list.count(block) != 1) return reg_state;

    /* loop over all recorded states for this block */
    for (state_it_type it  = block_list[block].begin(); 
                       it != block_list[block].end(); 
                       it++) {
        unsigned long insn_offset = it->first;  /* instruction offset */
        reg_state = it->second;

        /* stop once the first state change was observed */
        if (reg_state != D_IA64_CLEAR) break;
    }

    return reg_state;
}



D_StateType ArmsDerefRegister::getState(ArmsBasicBlock *block, unsigned long offset) {
    if (block_list.count(block) != 1) return D_IA64_CLEAR;
    if (block_list[block].count(offset) != 1) return D_IA64_CLEAR;
    return block_list[block][offset];
}

/* Returns the RW state for this register in a number of blocks */
D_StateType ArmsDerefRegister::getState(std::vector<ArmsBasicBlock *> blocks) {
    D_StateType reg_state = D_IA64_CLEAR; /* register is untouched by default */

    /* call getState() for each block until the register is no longer clear */
    for (std::vector<ArmsBasicBlock *>::iterator it  = blocks.begin();
                                                 it != blocks.end();
                                                 it++) {
        reg_state = getState(*it);

        /* stop once the first state change was observed */
        if (reg_state != D_IA64_CLEAR) break;
    }
    return reg_state;
}


ArmsBasicBlock * ArmsDerefRegister::getBB(std::vector<ArmsBasicBlock *> blocks, D_StateType state) {
    for (std::vector<ArmsBasicBlock *>::iterator it  = blocks.begin();
                                                 it != blocks.end();
                                                 it++) {
        if (getState(*it) == state) return *it;
    }
    return NULL;
}

unsigned long ArmsDerefRegister::getOffset(ArmsBasicBlock *block, D_StateType state) {
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
string ArmsDeref::get_register_name(int reg) {
    switch(reg) {
        case D_IA64_RAX: return "RAX";
        default: return "unknown";
    }
}

// static
int ArmsDeref::parse_functions(ArmsFunction *f, void *arg) {
    ArmsDeref *alive = (ArmsDeref *) arg;
    return alive->parse_function(f);
}


bool ArmsDeref::is_analyzed(ArmsBasicBlock *bb) {
    return analyzed_blocks.find(bb) != analyzed_blocks.end();
}

int d_get_reg_index(RegisterAST::Ptr reg) {
    int reg_value = reg->getID().val();
    int reg_class = reg->getID().regClass();
    
    if (reg_class != x86::GPR) {
        /* not a GPR (could be a flag or RIP or ...) */
        return -1;
    }
    switch(reg_value & 0x000000ff ) {
        case 0: // RAX
            return D_IA64_RAX;
        case 1: // RCX
            break;
        case 2: // RDX
            break;
        case 3: // RBX
            break;
        case 4: // RSP
            break;
        case 5: // RBP
            break;
        case 6: // RSI
            break;
        case 7: // RDI
            break;
        case 8: // R8
            break;
        case 9: // R9
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


void ArmsDeref::parse_register(RegisterAST::Ptr reg, 
                                  ArmsBasicBlock *bb, unsigned long offset, D_StateType state) {
    int reg_index = d_get_reg_index(reg);
    if (reg_index < 0) return;
    
    dprintf("              : (%d): %s -> %s\n", reg_index, 
                         get_register_name(reg_index).c_str(), 
                    ArmsDerefRegister::getStateName(state).c_str());
    rw_registers[reg_index].setState(bb, offset, state);
    
}

void ArmsDeref::parse_register_set(std::set<RegisterAST::Ptr> register_set, 
                        ArmsBasicBlock *bb, unsigned long offset, D_StateType state) {
 
    for (std::set<RegisterAST::Ptr>::iterator it  = register_set.begin(); 
                                              it != register_set.end(); 
                                              it++) {
        RegisterAST::Ptr reg = *it;
        int  reg_value = reg->getID().val();
        parse_register(reg, bb, offset, state);
    }
}

bool d_isNop(Instruction::Ptr iptr) {
    if (iptr->getOperation().getID() == e_nop) return true;
    return false;
}

bool d_isNop(ArmsBasicBlock *bb) {
    ParseAPI::Block *pblock = (ParseAPI::Block *) bb->get_parse_block();
    ParseAPI::Block::Insns insns;
    pblock->getInsns(insns);
    for (ParseAPI::Block::Insns::iterator it  = insns.begin(); 
                                          it != insns.end(); 
                                          it++) {
        /* it->first:  offset
         * it->second: instruction */
        if (!d_isNop(it->second)) return false;
    }

    return true;
}

void ArmsDeref::parse_instruction(Instruction::Ptr iptr,
                                     ArmsBasicBlock *bb, unsigned long offset) {

    if (!iptr->isLegalInsn()) {
        dprintf("      %p: [ILLEGAL INSTRUCTION]\n", (void *) offset);
        bb->set_disas_err((void*) offset);
        return;
    }
    dprintf("      %p: %s\n", (void *) offset, iptr->format(0).c_str());

    
    RegisterAST::Ptr reg = is_dereference(iptr);
    if (reg != NULL) {
        int reg_index = d_get_reg_index(reg);
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
        parse_register(eax, bb, offset, D_IA64_WRITE);
        parse_register(ebx, bb, offset, D_IA64_WRITE);
        parse_register(ecx, bb, offset, D_IA64_WRITE);
        parse_register(edx, bb, offset, D_IA64_WRITE);
        return;
    }
/* TODO:
    if (iptr->size() == 2 && iptr->rawByte(0) == 0x0f && iptr->rawByte(1) == 0x0b) {
        dprintf("                UD2\n");
    }
 */

    std::set<RegisterAST::Ptr> register_set;

    iptr->getWriteSet(register_set);
    parse_register_set(register_set, bb, offset, D_IA64_WRITE);
    register_set.clear();
}


void ArmsDeref::parse_block(ArmsFunction *f, ArmsBasicBlock *bb) {
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
    for (int i = 0; i < D_IA64_REGS; i++) {
        dprintf("      %s: %s\n",            get_register_name(i).c_str(), 
                               ArmsDerefRegister::getStateName(rw_registers[i].getState(bb)).c_str() );
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

        if (edge->is_direct_call() && d_isNop(next_bb)) {
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

int ArmsDeref::parse_function(ArmsFunction *f) {
    
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
    for (int i = 0; i < D_IA64_REGS; i++) {
        dprintf("      %s: %s\n", get_register_name(i).c_str(), 
            ArmsDerefRegister::getStateName(rw_registers[i].getState(function_blocks[f])).c_str() );
    }


    return 0;
}


string ArmsDeref::get_regstate_name(int i, ArmsFunction *f) {
    return ArmsDerefRegister::getStateName(rw_registers[i].getState(function_blocks[f]));
}







/* Store read/write/clear state for 6 argument registers. We need two bits per
 * argument: 12 bits in total */
//uint16_t reg_bitmap;

/* As defined in arms_deref.h:
 *   D_IA64_CLEAR     0x00    00b
 *   D_IA64_DEREF     0x01    01b
 *   D_IA64_WRITE     0x02    10b
 */

/* set register <reg_index> to <state> */
void d_set_reg_bitmap(uint16_t *reg_bitmap, int reg_index, uint16_t state) {
    *reg_bitmap &= ~(0x03 << (reg_index * 2)); // clear first
    *reg_bitmap |= state << (reg_index * 2);
}

/* returns true if register <reg_index> is set to <state> */
bool d_is_reg_bitmap(int reg_bitmap, int reg_index, uint16_t state) {
    return (reg_bitmap >> (reg_index * 2) & 0x03) == state;
}

/* returns the state of register <reg_index> */
int d_get_reg_bitmap(int reg_bitmap, int reg_index) {
    return (reg_bitmap >> (reg_index * 2) & 0x03);
}



std::string d_bm_tostring(int reg_bitmap) {
    string result = "";
    for (int i = 0; i < 6; i++) {
        if (d_is_reg_bitmap(reg_bitmap, i, D_IA64_CLEAR)) result += "C ";
        if (d_is_reg_bitmap(reg_bitmap, i, D_IA64_DEREF)) result += "D ";
        if (d_is_reg_bitmap(reg_bitmap, i, D_IA64_WRITE)) result += "W ";
    }
    return result;

}






uint16_t ArmsDeref::getForwardLiveness2(ArmsFunction *f,
                                       ArmsBasicBlock *bb,
                                       std::vector<ArmsBasicBlock *> fts,
                                       std::vector<ArmsBasicBlock *> argcount_analyzed_blocks) {   

    int edges_followed = 0;

    std::vector<uint16_t> bitmaps;
    std::string blanks(argcount_analyzed_blocks.size(), ' ');

    uint16_t reg_bitmap = 0;
    for (int i = 0; i < D_IA64_ARGS; i++) {
        d_set_reg_bitmap(&reg_bitmap, i, D_IA64_CLEAR);
    }

    /* Update the function_registers with information from the current block. */
    bool done = true;
    for (int i = 0; i < D_IA64_ARGS; i++) {
        if (d_is_reg_bitmap(reg_bitmap, i, D_IA64_CLEAR)) {

            D_StateType state;
            {
                state = rw_registers[i].getState(bb);

            }
                
            d_set_reg_bitmap(&reg_bitmap, i, state);

            if (state == D_IA64_CLEAR) {
                done = false;
            }

        }
    }
    
    ddprintf("[ft]%s blck_bitmap = %s (block %p)\n",blanks.c_str(), d_bm_tostring(reg_bitmap).c_str(), (void *)bb->get_start_address());
    
    
                
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
            } else if (d_isNop(fallthrough_bb)) {
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
            ddprintf("is indirect call, continuing at fallthrough\n");
            assert(bb->outgoing_edge_count() == 1);

            fallthrough_bb = bb->get_fallthrough_bb();

            /* maybe there is icall tail optimization? - not supported*/
            assert(fallthrough_bb != NULL);
            assert(!fallthrough_bb->is_entry_block());
//          assert(!d_isNop(fallthrough_bb));

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
        dprintf("[ft]%s blck_bitmap = %s (block %p)\n",blanks.c_str(), d_bm_tostring(reg_bitmap).c_str(), (void *)bb->get_start_address());
        for (auto it  = bitmaps.begin(); 
                  it != bitmaps.end();
                  it++) {
            uint16_t bitmap = *it;

            dprintf("[ft]%s      bitmap = %s\n", blanks.c_str(), d_bm_tostring(bitmap).c_str());
            for (int i = 0; i < D_IA64_ARGS; i++) {

#ifdef ALLOW_UNINITIALIZED_READ
                if (d_is_reg_bitmap(best_bitmap, i, 0x3)) {
                    /* if no state found yet, use the child's state */
                    d_set_reg_bitmap(&best_bitmap, i, d_get_reg_bitmap(bitmap, i));
                } else if (d_is_reg_bitmap(best_bitmap, i, D_IA64_DEREF)) {
                    /* if our current state is DEREF, then ALL children must be DEREF also. Or CLEAR.
                     */
                    if (d_is_reg_bitmap(bitmap, i, D_IA64_DEREF)) {
                        /* ... */
                    } else if (d_is_reg_bitmap(bitmap, i, D_IA64_WRITE)) {
                        d_set_reg_bitmap(&best_bitmap, i, D_IA64_WRITE);
                    } else if (d_is_reg_bitmap(bitmap, i, D_IA64_CLEAR)) {
                        d_set_reg_bitmap(&best_bitmap, i, D_IA64_CLEAR);
                    }
                } else if (d_is_reg_bitmap(best_bitmap, i, D_IA64_CLEAR)) {
                    /* if our current state CLEAR, we can become WRITE */
                    if (d_is_reg_bitmap(bitmap, i, D_IA64_WRITE)) {
                        d_set_reg_bitmap(&best_bitmap, i, D_IA64_WRITE);
                    }
                }
#else 
                if (d_is_reg_bitmap(best_bitmap, i, 0x3)) {
                    d_set_reg_bitmap(&best_bitmap, i, d_get_reg_bitmap(bitmap, i));
                } else if (d_is_reg_bitmap(best_bitmap, i, D_IA64_WRITE) ||
                           d_is_reg_bitmap(best_bitmap, i, D_IA64_CLEAR)) {

                    if (d_is_reg_bitmap(bitmap, i, D_IA64_DEREF)) {
                        d_set_reg_bitmap(&best_bitmap, i, D_IA64_DEREF);
                    } else if(d_is_reg_bitmap(bitmap, i, D_IA64_WRITE)) {
                        /* ... */
                    } else if (d_is_reg_bitmap(bitmap, i, D_IA64_CLEAR)) {
                        /* ... */
                    }
                }
#endif 




            }
        }
        dprintf("[ft]%s comb_bitmap = %s\n", blanks.c_str(), d_bm_tostring(best_bitmap).c_str());

    
        /* combine */
        for (int i = 0; i < D_IA64_ARGS; i++) {
            if (d_is_reg_bitmap(reg_bitmap, i, D_IA64_CLEAR)) {
                d_set_reg_bitmap(&reg_bitmap, i, d_get_reg_bitmap(best_bitmap,i));
            }
        }
        dprintf("[ft]%s updt_bitmap = %s\n", blanks.c_str(), d_bm_tostring(reg_bitmap).c_str());
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





int ArmsDeref::get_callee_retuse(ArmsFunction *f) {
    /* Only if this function was analyzed */
    if (function_blocks.count(f) == 0) {
        return -1;
    }

    dprintf("\n=== Starting retuse analysis for function %s ===\n", f->get_name().c_str());

    /* Start with the entry blocks of this function. */
    std::vector<ArmsBasicBlock*> entry_blocks;
    entry_blocks.assign(f->get_entry_points()->begin(), f->get_entry_points()->end());

    /* Recursively analyze each block of the function starting from the entry blocks */
    /* This is a depth first search */

    uint16_t reg_bitmap = 0;
    for (int i = 0; i < D_IA64_ARGS; i++) {
        d_set_reg_bitmap(&reg_bitmap, i, D_IA64_CLEAR);
    }
    std::vector<ArmsBasicBlock *> argcount_analyzed_blocks;
    std::vector<ArmsBasicBlock *> fts;
    argcount_analyzed_blocks.clear();

    assert(entry_blocks.size() == 1);

    reg_bitmap = getForwardLiveness2(f, entry_blocks[0], fts, argcount_analyzed_blocks);

    for (int i = D_IA64_ARGS; i >=0; i--) {
        if (d_get_reg_bitmap(reg_bitmap, i) == D_IA64_WRITE) {
            dprintf("RAX is written in %s\n", i, f->get_name().c_str());
        }
    }

    dprintf("=== Finished retuse analysis for function %s ===\n\n", f->get_name().c_str());

    return 0;
}

/* If the provided set of preceding_blocks contain entry_blocks for function f,
 * recursively continue searching for preceding blocks in callers of f.
 *
 * returns true if the preceding blocks contain entry blocks.
 */

#define MAX_DEPTH 10


RegisterAST::Ptr ArmsDeref::is_dereference(Instruction::Ptr iptr) {
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
bool ArmsDeref::computation_used(Instruction::Ptr iptr) {
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




int ArmsDeref::get_icallsites(ArmsFunction *f) {
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
    
        uint16_t reg_bitmap = 0;
        for (int i = 0; i < D_IA64_ARGS; i++) {
            d_set_reg_bitmap(&reg_bitmap, i, D_IA64_DEREF);
        }
        std::vector<ArmsBasicBlock *> callsite_analyzed_blocks;
        callsite_analyzed_blocks.clear();

        reg_bitmap = getBackwardLiveness(f, block, callsite_analyzed_blocks);

        int argcount = 99;
        for (int i = 0; i < D_IA64_ARGS; i++) {
            if (d_get_reg_bitmap(reg_bitmap, i) != D_IA64_WRITE) {
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
        int max_arguments = D_IA64_ARGS;

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
            max_arguments = D_IA64_ARGS;
        dprintf("max-arguments: %d\n", max_arguments);
#endif

        // going bold
        block->set_icall_args(max_arguments);


        if (min_arguments == max_arguments) {
            dprintf("!! icallsite %s.%d sets exactly %d arguments !!\n", f->get_name().c_str(), i, max_arguments);
        } else {
            dprintf(" !! icallsite %s.%d sets %d to %d arguments !!\n", f->get_name().c_str(), i, min_arguments, max_arguments);
        }

    }
}


