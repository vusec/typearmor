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

#ifndef __cfg__
#define __cfg__

class ArmsBasicBlock;
class ArmsEdge; 
class ArmsFunction; 

class CFG {
	
public:
	CFG(ArmsBasicBlock *root) : start_addr_(0), end_addr_(0), is_library_(false), num_bb(0) {
		entry_points.insert(root);
		single_entry_point = true; 
	}

	CFG(const char *module_name) : start_addr_(0), end_addr_(0), is_library_(false), single_entry_point(false), num_bb(0) {
		this->module_name = string(module_name); 
	} 

	~CFG() {}

	string get_module_name() { return module_name; }

	void set_start_addr(address_t addr) { start_addr_ = addr; }
	address_t get_start_addr()          { return start_addr_; }
	void set_end_addr(address_t addr)   { end_addr_ = addr;   }
	address_t get_end_addr()            { return end_addr_;   }
	bool addr_in_cfg(address_t addr);

	bool single_entry() { return single_entry_point; }
	ArmsBasicBlock *get_entry() { return *entry_points.begin(); }

	void set_is_library(bool is_library) {is_library_ = is_library;}
	bool is_library(void) {return is_library_;} 

	ArmsFunction* create_dummy_function(address_t base_address); 
	ArmsFunction* create_dummy_function(string funname, address_t base_address);
	ArmsFunction* create_plt_function(string funname, address_t base_address);
	ArmsFunction* find_function(address_t base_address);
	void mark_function_as_plt(address_t base_address);
	void mark_at_functions();
	int foreach_function(int (*callback)(ArmsFunction*, void*), void *arg);

	ArmsFunction *find_lib_dummy_by_name(std::string name);

	ArmsBasicBlock* find_bb(address_t start_address);
	ArmsBasicBlock* find_bb_by_last_insn_address(address_t last_insn_address);

	ArmsEdge *find_edge(address_t src, address_t dst);
	ArmsEdge *find_edge_mask_lib(address_t src, address_t dst);

	void handle_interprocedural(ArmsBasicBlock *call_site, address_t target, arms_edge_type_t type);
	void handle_interprocedural_call(ArmsBasicBlock *call_site, address_t target, arms_edge_type_t type);

	// obsolete: start
	void handle_interprocedural(ArmsFunction *caller, address_t call_site, address_t target, arms_edge_type_t type);
	void handle_interprocedural_call(ArmsFunction *caller, address_t call_site, address_t target);
	void handle_interprocedural_jmp(ArmsFunction *caller, address_t call_site, address_t target, arms_edge_type_t type);
	// obsolete: end 

	ArmsEdge *create_and_add_edge(address_t source, address_t target); 
	ArmsEdge *create_and_add_edge(ArmsBasicBlock *source, ArmsBasicBlock *target);

	void compare_edges(CFG *other); 

	size_t count_basic_blocks() { return start2bb.size(); }
	size_t count_functions()    { return functions.size(); }
	size_t count_edges();
	size_t count_edges_coarse_grained();
	void   count_ats(size_t *icall_sites, size_t *icall_targets, size_t *icall_edges);

protected:

	void store_function(ArmsFunction *fun);
	void store_bb(ArmsBasicBlock *bb);

	void debug_check_if_cs_remains_unresolved(address_t instr_addr); 

private: 
	string module_name;
	address_t start_addr_;
	address_t end_addr_;
	bool is_library_; 

	/* Entry points of a module, 
	 * i.e., either _start or library functions */
	std::set<ArmsBasicBlock*> entry_points; // XXX 
	/* (single_entry_point is true) iff (entry_points.size() == 1) */
	bool single_entry_point; 

	/* A collection of functions that belong to this module. */
	std::map<address_t, ArmsFunction*> functions;

	/* A collection of basic blocks that belong to this cfg. */ 
	std::map<address_t, ArmsBasicBlock *> start2bb; 
	std::map<address_t, ArmsBasicBlock *> last2bb; 
	/* Number of basic blocks.  */
	unsigned int num_bb; 

	// obsolete: start 
	void store_caller_and_callee(ArmsFunction *fun_caller, ArmsFunction **fun_callee_out, address_t call_target); 
	void create_call_edge(ArmsFunction *fun_caller, ArmsFunction *fun_callee, 
		address_t call_site, address_t call_target, ArmsBasicBlock **bb_call_site_out, arms_edge_type_t type); 
	void create_ret_edges(ArmsFunction *fun_caller, ArmsFunction *fun_callee, 
		address_t call_site, address_t call_target, ArmsBasicBlock *bb_call_site);
	// obsolete: end 

	void create_call_edge(ArmsBasicBlock *bb_call_site, address_t call_target, arms_edge_type_t type);
	void create_ret_edges(ArmsBasicBlock *bb_call_site, address_t target);  
};

CFG* load_cfg_from_file(const char* filename); 


#endif 
