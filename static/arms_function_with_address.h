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

#ifndef __FUNCTION_WITH_ADDRESS__
#define __FUNCTION_WITH_ADDRESS__

class ArmsBasicBlock; 
class ArmsFunction; 
class CFG; 

class ArmsFunctionWithAddress : public ArmsFunction { 
	
public:

	ArmsFunctionWithAddress(address_t start, string name, CFG *cfg) : 
		ArmsFunction(start, name, cfg) {
		start_address 	= start;
		end_address 	= ULLONG_MAX; // FIXME set it to the end address of the module  
	} 

	address_t get_start_address(void) 	{ return start_address; }
	address_t get_end_address(void) 	{ return end_address; }
	void set_end_address(address_t end) 	{ end_address = end; }

	bool basic_block_in_range(address_t bb_start, address_t bb_end) {
		return ((bb_start >= start_address) && (bb_end <= end_address));  
	}

	void assert_range(void) { assert(start_address < end_address); }

	static bool arms_function_with_address_compare(const ArmsFunctionWithAddress* first, const ArmsFunctionWithAddress *second) {
		return (first->start_address < second->start_address);
	}

private:

	address_t start_address;
	address_t end_address; 	

}; 


#endif 
