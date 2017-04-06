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

#ifndef __DYNINST_CFG_CONSTRUCTION__
#define __DYNINST_CFG_CONSTRUCTION__

class ArmsFunctionWithAddress; 

class DICFG : public CFG {

static Expression::Ptr the_pc;  


public:
	DICFG(const char *module_name) : CFG(module_name) {}  

	// ParseAPI based 
	void insert_functions_and_bbs(const CodeObject::funclist& funcs);
	void insert_edges(const CodeObject::funclist& funcs);
	//

	// BPatch_API based 
	void insert_functions(std::vector<BPatch_function *> *funcs); 
	void insert_plt_entries(Symtab *symtab); 
	void insert_interprocedural_edges(std::vector<BPatch_function *> *funcs);
	void analyze_unresolved_control_transfers(std::vector<BPatch_function *> *funcs); 

    BPatch_addressSpace *handle;
    BPatch_image *image;
	// 


private:
	// ParseAPI based 
	void copy_edge_type(ArmsEdge *arms_edge, ParseAPI::Edge *edge, bool indirect); 
	// 

	// BPatch_API based 
	void insert_intraprocedural_function_flow_graph(BPatch_function *fun); 
	void copy_edge_type(ArmsEdge *arms_edge, BPatch_edge *bp_edge, bool intra); 
	void set_entry_and_exit_points_of_function(BPatch_function *fun); 
	void insert_interprocedural_edge(ArmsFunction *arms_fun, BPatch_point *call_point);
	// 
	
};

void dyninst_analyze_address_taken_deprecated(const char *bin, const char **argv, DICFG *cfg);
DICFG* dyninst_build_cfg_deprecated(const char *bin, const char **argv); 

void dyninst_analyze_address_taken(BPatch_addressSpace *handle, DICFG *cfg);
DICFG* dyninst_build_cfg(BPatch_addressSpace *handle, int index); 

#endif 
