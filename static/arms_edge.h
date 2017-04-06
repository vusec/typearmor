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

#ifndef __edge__
#define __edge__

typedef enum {
	arms_direct_call = 0,
	arms_indirect_call,
	arms_inter_direct_jmp, 
	arms_inter_indirect_jmp, 
	arms_cond_taken,
	arms_cond_not_taken,
	arms_direct_jmp,
	arms_indirect_jmp,
	arms_fallthrough, 
	arms_catch, 
	arms_call_ft, 	// fallthrough after call instruction 
	arms_ret, 
	arms_no_edge, 
	arms_fastpath,	// simplified path, not a real edge in the binary
	arms_unknown   
} arms_edge_type_t; 

bool edge_type_is_call(arms_edge_type_t type);  
bool edge_type_is_direct_call(arms_edge_type_t type);  
bool edge_type_is_indirect_call(arms_edge_type_t type);
bool edge_type_is_return(arms_edge_type_t type);
bool edge_type_is_inter_direct_jmp(arms_edge_type_t type);  
bool edge_type_is_inter_indirect_jmp(arms_edge_type_t type);  
bool edge_type_is_indirect(arms_edge_type_t type); 

class ArmsBasicBlock; 
class CFG; 

class ArmsEdge {

	static unsigned int 	id_seq_;

public: 
	ArmsEdge(ArmsBasicBlock *from, ArmsBasicBlock *to, CFG *cfg) :  
		id_(id_seq_++), hidden_(false), source_(from), target_(to), type_(arms_unknown), 
		intra_procedural(true), cfg_(cfg) {} 

	ArmsEdge(ArmsBasicBlock *from, ArmsBasicBlock *to, arms_edge_type_t type, CFG *cfg) :  
		id_(id_seq_++), hidden_(false), source_(from), target_(to), type_(type), cfg_(cfg) {
		set_type(type);	
	} 

	~ArmsEdge() {
		unlink();
	}

	ArmsBasicBlock *get_source(void) { return this->source_; }
	ArmsBasicBlock *source(void) { return get_source(); }

	ArmsBasicBlock *get_target(void) { return this->target_; }
	ArmsBasicBlock *target(void) 	{ return get_target(); }

	void unlink();

	unsigned int id(void)		{ return id_; } 

	CFG *get_cfg(void) { return this->cfg_; }
	CFG *cfg(void) { return get_cfg(); }

	void set_type(arms_edge_type_t type); 
	arms_edge_type_t get_type(void) { return type_; }
	arms_edge_type_t type(void) 	{ return get_type(); }
	bool is_no_call_ft(void) 	{ return (type_ != arms_call_ft); }  

	void set_intraprocedural(void) 	{ intra_procedural = true; }
	void set_interprocedural(void) 	{ intra_procedural = false; }
	bool is_intraprocedural(void)	{ return intra_procedural; }
	bool is_interprocedural(void)	{ return !intra_procedural; } 
	bool is_indirect(void)		{ return edge_type_is_indirect(type_); }
	bool is_return(void)		{ return (type_ == arms_ret); } 
    bool is_direct_call(void)   { return edge_type_is_direct_call(type_); }
    bool is_indirect_call(void) { return edge_type_is_indirect_call(type_); }
    bool is_indirect_jump(void) { return (type_ == arms_inter_indirect_jmp || type_ == arms_indirect_jmp); }

	void set_replaced_edges(std::vector<ArmsEdge*> *r) { replaced.assign(r->begin(), r->end()); }
	std::vector<ArmsEdge*> *get_replaced_edges() { return &replaced; }

	bool is_fastpath() { return type_ == arms_fastpath; }
	bool is_hidden() { return hidden_; }
	bool set_hidden(bool h) { hidden_ = h; }

	string to_string(void);

private:
	const unsigned int	id_; 
	bool			hidden_;

	ArmsBasicBlock 		*source_;
	ArmsBasicBlock 		*target_;
	arms_edge_type_t 	type_; 

	std::vector<ArmsEdge*>	replaced;

	/* If the edge is inter- or intraprocedural.
	 * By default, initialized to true. */
	/* Don't touch it! It's set based on type. */
	bool		intra_procedural; 

	/* The CFG that contains this edge. */
	CFG			*cfg_; 
};

#endif 

