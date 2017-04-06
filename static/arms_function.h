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

#ifndef __FUNCTION__
#define __FUNCTION__

class ArmsBasicBlock; 
class CFG; 

class ArmsFunction {

static string fun_dummy_name;

public:
	ArmsFunction(address_t addr, string name, CFG *cfg) : 
		base_addr(addr), has_address_taken(false), is_plt_(false), is_lib_dummy_(false), is_main_(false), funname(name), cfg(cfg) {}

	std::set<ArmsFunction*> get_callees(void) { return callees; } 
//	std::set<ArmsFunction*> get_callers(void) { return callers; } 
	std::set<ArmsFunction*> get_callers(void);

	address_t get_base_addr(void) { return base_addr; }
	void set_addr_taken(void) { has_address_taken = true; }
        bool addr_taken() { return has_address_taken; }

	bool is_plt(void) 	{ return is_plt_; }
	void set_is_plt(void)	{ is_plt_ = true; } 
	bool is_lib_dummy(void)     { return is_lib_dummy_; }
	void set_is_lib_dummy(void) { is_lib_dummy_ = true; }
	void set_is_main(void)      { is_main_ = true; }
	bool is_main(void)          { return is_main_; }

    void set_write_rax(bool val) { write_rax_ = val; }
    bool get_write_rax(void) { return write_rax_; }

    void setMangledName(string name) { mangledName = name; }
    string getMangledName(void) { return mangledName; }

	string get_name() { return funname; }

	~ArmsFunction() {} 	

	void add_bb(ArmsBasicBlock *bb);
	void add_entry_block(address_t bb_addr);
	void add_entry_block(ArmsBasicBlock *bb);
    void add_dependency(ArmsFunction *f) { dependencies.insert(f); }
    std::set<ArmsFunction*> get_dependencies(void) { return dependencies; }
    void clear_dependencies(void) { dependencies.clear(); }
	int foreach_entry_block(int (*callback)(ArmsBasicBlock*,void*), void *arg);
	int foreach_inbound_edge(int (*callback)(ArmsEdge*,void*), void *arg);
	void debug_confirm_entry_block(address_t bb_addr);
	void add_exit_block(address_t bb_addr);
	void add_exit_block(ArmsBasicBlock *bb);
	void debug_confirm_exit_block(address_t bb_addr);

    CFG *get_cfg(void) { return cfg; };

	void add_callee(ArmsFunction *callee) { callees.insert(callee); } 
	void add_caller(ArmsFunction *caller) { callers.insert(caller); } 

	size_t nentry_points() { return entry_points.size(); }
	ArmsBasicBlock *get_entry_point(size_t i);
	size_t nexit_points() { return exit_points.size(); }
	ArmsBasicBlock *get_exit_point(size_t i);

	std::set<ArmsBasicBlock*>* get_basic_blocks(void) { return &basic_blocks; }
	std::set<ArmsBasicBlock*>* get_entry_points(void) { return &entry_points; }
	std::set<ArmsBasicBlock*>* get_exit_points(void)  { return &exit_points; }

	void add_external_call(ArmsBasicBlock *bb) { external_calls.insert(bb); }

    void set_variadic(void) { variadic = true; }
    int   is_variadic(void) { return variadic; }
    void set_argcount(int argc) { argcount = argc; }
    int  get_argcount(void) { return argcount; }

    std::map <ArmsBasicBlock *, int> get_icall_args(void);

	string to_string(void); 
    
#if 0
	virtual address_t get_start_address(void)	{ assert(0); return DUMMY_ADDR; } 
	virtual address_t get_end_address(void) 	{ assert(0); return DUMMY_ADDR; }

	virtual bool basic_block_in_range(address_t bb_start, address_t bb_end) {
		assert(0); return false; }
#endif 


private:
	/* XXX THIS CAN BE USED ONLY AS AN ID!! and not an address */
	address_t base_addr; 

	/* by default, initialized to false */
	bool has_address_taken; /* XXX */ 
	bool is_plt_;
	bool is_lib_dummy_;
	bool is_main_;
    bool write_rax_;
 	string funname; 
    string mangledName;


	std::set<ArmsBasicBlock*> basic_blocks;

	std::set<ArmsBasicBlock*> entry_points; 

	/* Basic blocks that contain a ret instruction. */
	std::set<ArmsBasicBlock*> exit_points; 

	/* Basic blocks that contain a call to an external module. */
	/* XXX */
	std::set<ArmsBasicBlock*> external_calls; 

    std::set<ArmsFunction*> dependencies;

	/* XXX should we also add a set of indirect jumps? */

	/* Callees of this function, i.e., functions called by this one. 
	 * Not sure if it's needed. Perhaps it will be more useful to have 
	 * it at the bb level only. */
	std::set<ArmsFunction*> callees;

	/* Callers of this function, i.e., functions calling this one. */
	std::set<ArmsFunction*> callers;

	/* XXX some info about the function arguments. Perhaps a vector 
	 * of a FunArgument class objects. */
    bool variadic = false;
    int argcount = -1;

	CFG *cfg; 
};

#endif
