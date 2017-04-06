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

#ifndef __ARMS_LIVENESS__
#define __ARMS_LIVENESS__


#include <map>
    

class ArmsBasicBlock; 
class ArmsFunction;
class ArmsEdge;

typedef enum {
    IA64_CLEAR,     /* register was untouched */
    IA64_READ,      /* register was read only */
    IA64_WRITE,     /* register was write only */
    IA64_RW,        /* register was read and write */
} StateType;

class ArmsRegister {


public: 
    /* Constructor / Destructor */
	ArmsRegister() {}
	~ArmsRegister() {} 

    /* Iterators */
    typedef std::map <ArmsBasicBlock *, std::map <unsigned long, StateType> > :: iterator block_it_type;
    typedef                             std::map <unsigned long, StateType>   :: iterator state_it_type;
    typedef                             std::map <unsigned long, bool>        :: iterator deref_it_type;
    typedef std::map <unsigned long, StateType>::reverse_iterator state_rit_type;

    /* Returns a string representation for a specific state */
    static string getStateName(StateType state);

    /* Set the register state for a specific instruction (block/offset combination) */
    void setState(ArmsBasicBlock *block, unsigned long offset, StateType state);
    void setRead (ArmsBasicBlock *block, unsigned long offset);
    void setWrite(ArmsBasicBlock *block, unsigned long offset);

    void setDeref(ArmsBasicBlock *block, unsigned long offset);
    bool getDeref(ArmsBasicBlock *block);

    /* Returns true if this register was read before write within the provided blocks */
    bool isRead(std::vector<ArmsBasicBlock *> blocks) { return getState(blocks) == IA64_READ; }

    /* Returns the RW state for this register in a specific block. This assumes
     * that the instructions for this block were parsed in consecutive order. */
    StateType getState(ArmsBasicBlock *block);
    /* Returns the register state for at a specific offset in a block */
    StateType getState(ArmsBasicBlock *block, unsigned long offset);

    /* Returns the RW state for this register in a number of blocks */
    StateType getState(std::vector<ArmsBasicBlock *> blocks);

    StateType getLastState(ArmsBasicBlock *block);

    bool writtenInBlock(ArmsBasicBlock *block);
    bool writtenLastInBlock(ArmsBasicBlock *block);

    bool writtenInBlocks(std::set<ArmsBasicBlock *> blocks);
   
    /* Returns the first basic block in which the state for this register was <state> */
    ArmsBasicBlock* getBB(std::vector<ArmsBasicBlock *> blocks, StateType state);
    ArmsBasicBlock* getReadBB(std::vector<ArmsBasicBlock *> blocks) { return getBB(blocks, IA64_READ); }

    /* Returns the offset for the instruction that set the state for this register */
    unsigned long getOffset(ArmsBasicBlock *block, StateType state);
    unsigned long getReadOffset(ArmsBasicBlock *block) { return getOffset(block, IA64_READ); }



private:
    std::map <ArmsBasicBlock *, std::map <unsigned long, StateType> > block_list;
    std::map <ArmsBasicBlock *, std::map <unsigned long, bool> > deref_block_list; 
    
};










class ArmsLiveness {

#define IA64_RDI 0
#define IA64_RSI 1
#define IA64_RDX 2
#define IA64_RCX 3
#define IA64_R8  4
#define IA64_R9  5
#define IA64_RSP 6 /* to identify varargs */
#define IA64_RBP 7
#define IA64_RAX 8

#define IA64_LAST_ARG IA64_R9
#define IA64_REGS 9 /* Number of registers that we keep track of */
#define IA64_ARGS 6 /* Number of registers used for arguments. Additional
                       registers (like RSP) must be placed after the register
                       arguments. */


public:
    ArmsLiveness() {}

    ~ArmsLiveness() {}

    /* returns a string representation of for a specific regiser index */
    static string get_register_name(int reg);
    /* callback for foreach_function(). arg should be a pointer to an
     * ArmsLiveness instance */
    static int parse_functions(ArmsFunction *f, void *arg);

    void set_bpatch_image(BPatch_image *image) { image = image; };
   
    /* Get the argument count for a given arms function */
    int get_arg_count(ArmsFunction *f); 
    int get_vararg_count(ArmsFunction *f); 

    int get_icallsites(ArmsFunction *f);

private:
    ArmsRegister rw_registers[IA64_REGS];

    /* blocks that have been analyzed */
    std::set<ArmsBasicBlock *>  analyzed_blocks; 

    /* blocks per function, stored in a vector so we control the ordering */
    std::map<ArmsFunction *, std::vector<ArmsBasicBlock *> > function_blocks;

    /* blocks per function that end with an indirect call instruction */
    std::map<ArmsFunction *, std::set<ArmsBasicBlock *> > icall_blocks;

    BPatch_image *image;

    /* return the first argument register that is read at a specific offset within a
     * given basic block. */
    int getFirstReadArgRegister(ArmsBasicBlock *bb, unsigned long offset);

    bool is_analyzed(ArmsBasicBlock *bb);
    
    std::string bm_tostring(int reg_bitmap);
    void parse_register(RegisterAST::Ptr reg, 
                        ArmsBasicBlock *bb, unsigned long offset, StateType state);
    void parse_register_set(std::set<RegisterAST::Ptr> register_set, 
                            ArmsBasicBlock *bb, unsigned long offset, StateType state);
    void parse_instruction(Instruction::Ptr iptr,
                           ArmsBasicBlock *bb, unsigned long offset);
    void parse_block(ArmsFunction *f, ArmsBasicBlock *bb);
    int parse_function(ArmsFunction *f);

    bool getForwardLiveness(ArmsFunction *f,
                                     ArmsBasicBlock *bb);
    uint16_t getForwardLiveness2(ArmsFunction *f,
                                     ArmsBasicBlock *bb,
            std::vector<ArmsBasicBlock *> fts,
            std::vector<ArmsBasicBlock *> argcount_analyzed_blocks);
   
    bool getRAXreads(ArmsFunction *f,
            ArmsBasicBlock *bb,
            std::vector<ArmsBasicBlock *> retuse_fts,
            std::vector<ArmsBasicBlock *> retuse_analyzed_blocks);
    bool getRAXwrites(ArmsFunction *f,
                      ArmsBasicBlock *bb,
            std::vector<ArmsBasicBlock *> callee_retuse_analyzed_blocks);

    uint16_t getBackwardLiveness(ArmsFunction *f,
                                       ArmsBasicBlock *bb,
            std::vector<ArmsBasicBlock *> callsite_analyzed_blocks);

    RegisterAST::Ptr is_dereference(Instruction::Ptr iptr);
    bool computation_used(Instruction::Ptr iptr);
    bool icalls_optimized(void);

    /* worst-case scenario, assume optimized */
    bool is_optimized = true;
    bool opt_detector_completed = false;
    
    bool also_read(int first_vararg, ArmsBasicBlock *first_bb, int reg_index);
    int is_variadic(ArmsFunction *f);
    string get_regstate_name(int i, ArmsFunction *f);

    /* instruction length per offset */
    std::map <unsigned long, unsigned long> ins_length;
    
    /* for our recursion strategy */
    StateType argc_registers[IA64_ARGS];
    std::set<ArmsBasicBlock *> argc_analyzed_blocks;

    std::map <ArmsBasicBlock *, uint16_t> backward_cache;
    std::map <ArmsBasicBlock *, uint16_t> forward_cache;

};
#endif 
