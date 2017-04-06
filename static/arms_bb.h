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

#ifndef __bb__
#define __bb__




class ArmsEdge; 
class ArmsSourceBlock;
class ArmsInstruction; 
class ArmsRegister;
class ArmsFunction; 
class CFG; 

class ArmsBasicBlock {
	
	static uint64_t global_id; 
	static uint64_t num_dummy_blocks; 
	
public:
	static ArmsBasicBlock *create_dummy_basic_block(ArmsFunction *fun, CFG *cfg);
	static ArmsBasicBlock *create_dummy_basic_block(address_t addr, ArmsFunction *fun, CFG *cfg);
	static ArmsBasicBlock *create_dummy_basic_block(address_t start, address_t end, ArmsFunction *fun, CFG *cfg);

	ArmsBasicBlock(address_t start, address_t end, address_t last, ArmsFunction *fun, CFG *cfg) : 	
		start_address(start), end_address(end), last_insn_address(last), 
		is_entry_block_(false), is_exit_block_(false), is_dummy_(false), cfg_(cfg) 
	{ 
		id_ = ++global_id; 
		if (fun) funcs.push_back(fun); 
		//adebug_fprintf(stderr, "\tCreate BB(%ld) [%p-%p)\n", id_, (void*)start_address, (void*)end_address);
	} 

	ArmsBasicBlock(address_t start, address_t end, address_t last, CFG *cfg) : 	
		start_address(start), end_address(end), last_insn_address(last), 
		is_entry_block_(false), is_exit_block_(false), is_dummy_(false), cfg_(cfg) 
	{ 
		id_ = ++global_id; 
		//adebug_fprintf(stderr, "\tCreate BB(%ld) [%p-%p)\n", id_, (void*)start_address, (void*)end_address);
	} 

	~ArmsBasicBlock() {} 

	uint64_t id() { return id_; }

	void set_is_entry_block(void);
	void set_is_exit_block(void);
	void set_if_entry_block(bool entry);
	void set_if_exit_block(bool exit);

    /* whether or not this block is part of a variadic function and is responsible for
     * writing the variadic arguments to the stack. */
    void mark_vararg(void) { vararg_writes = true; }
    bool is_vararg_mark(void) { return vararg_writes; }

    void set_parse_block(void *p) { parse_block_ = p; };
    void *get_parse_block(void) { return parse_block_; };
    void set_bpatch_block(void *p) { bpatch_block_ = p; };
    void *get_bpatch_block(void) { return bpatch_block_; };

    void set_icall_args(int args) { icall_args = args; };
    int get_icall_args(void) { return icall_args; };

    void set_read_rax(bool val) { read_rax_ = val; };
    int get_read_rax(void) { return read_rax_; }

	bool is_entry_block(void) { return is_entry_block_; }
	bool is_exit_block(void) { return is_exit_block_; }
	bool equals_bb(ArmsBasicBlock *bb) { return id_ == bb->id_; }
	bool equals_bb_by_addr(ArmsBasicBlock *bb) { return start_address == bb->start_address; }

	address_t get_start_address(void) { return start_address; }
	address_t get_end_address(void) { return end_address; }
	address_t get_last_insn_address(void) { return last_insn_address; } 

	void add_incoming_edge(ArmsEdge *edge);
	int foreach_incoming_edge(int (*callback)(ArmsEdge*,void*), void *arg);
	size_t incoming_edge_count();
	ArmsEdge *get_incoming_edge(size_t i);
	void delete_incoming_edge(size_t i);
	void delete_incoming_edge(ArmsEdge *e);

	void add_outgoing_edge(ArmsEdge *edge); 
	size_t outgoing_edge_count(void);
	ArmsEdge *get_outgoing_edge(size_t i); 
	bool has_no_call_ft_outgoing_edge(void); 
	void delete_outgoing_edge(size_t i);
	void delete_outgoing_edge(ArmsEdge *e);

	bool has_outbound_fastpath(ArmsBasicBlock *bb);

	void drop_call_ft_edge(void); 
	void drop_incoming_call_ft_edge(void); 

	void set_is_dummy(void) { is_dummy_ = true; } 
	bool is_dummy(void) { return is_dummy_; } 
    
	bool is_ft(void); 
	bool outgoing_is_ft(void); 
    bool outgoing_contains_inter(void);

    bool has_syscall(void) { return has_syscall_; }
    void set_syscall(void) { has_syscall_ = true; }

    void set_disas_err(void* offset) { is_disas_err_ = offset; }
    void *is_disas_err(void) { return is_disas_err_; }

	CFG* get_cfg(void) { return cfg_; }
    
    
    void add_dependency(ArmsFunction *f) { dependencies.insert(f); }
    std::set<ArmsFunction*> get_dependencies(void) { return dependencies; }


	std::vector<ArmsFunction*>& get_containing_functions(void) { return funcs; } 
	void add_containing_function(ArmsFunction *fun) { 
		funcs.push_back(fun); 
	} 
	/* provided there is exactly one */
	ArmsFunction* get_function(void) {
		if (funcs.size() == 1) return funcs[0];	
		return 0; 
	} 
    std::vector<ArmsFunction*> get_functions(void) { return funcs; }
	int foreach_function(void (*callback)(ArmsFunction*, ArmsBasicBlock*), ArmsBasicBlock *arg);

	string to_string(void); 

	/* provided there is exactly one */
	ArmsBasicBlock *get_preceding_bb(void); 
	ArmsBasicBlock *get_following_bb(void); 
	ArmsBasicBlock *get_fallthrough_bb(void);
    ArmsBasicBlock *get_fallup_bb(void);

    void get_preceding_bbs(std::set<ArmsBasicBlock*> *blocks, std::set<ArmsBasicBlock*> *fblocks);

	bool forward_connected_with(ArmsBasicBlock *bb); 
	void get_forward_connected_bbs(vector<ArmsBasicBlock*>& forward_connected, bool &all_indirect); 
	void get_forward_connected_bbs(vector<address_t>& forward_connected, bool &all_indirect);  
	void print_forward_connected_bbs(vector<address_t>& forward_connected);

	void compare_edges(ArmsBasicBlock *other_bb); 

	size_t count_instr() { return instructions.size(); }
	ArmsInstruction *get_instr(size_t i) { return instructions.at(i); }

private: 
	uint64_t id_; /* internal */

	std::vector<ArmsInstruction *> instructions; 

	std::set<ArmsEdge*>	incoming_edges;
	std::set<ArmsEdge*> 	outgoing_edges;


	/* [start_address, end_address) */
	address_t		start_address;			
	address_t 		end_address;			

	/* the address of the last instruction */
	address_t 		last_insn_address; 		

    bool vararg_writes = false;

    /* ParseAPI Block */
    void *parse_block_ = 0;
    /* BPatch Block */
    void *bpatch_block_ = 0;

	/* initialized to false */
	bool is_entry_block_;					
	bool is_exit_block_;					
    
    std::set<ArmsFunction*> dependencies;

	bool is_dummy_; 

    void *is_disas_err_ = 0;
    int icall_args = -1;
    bool read_rax_;
    bool has_syscall_ = false;
   
	/* The function that contains this basic block. */
	std::vector<ArmsFunction*> funcs;						
	/* The CFG that contains this basic block. */
	CFG *cfg_;  
			
};


#endif 
