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
#include <stdlib.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <limits.h>
#include <assert.h>
#include <iostream>
#include <string>
#include <sys/time.h>
#include <sys/ioctl.h>

#include <fstream>

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <string.h>

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

#include "Register.h"

using namespace std;
using namespace Dyninst;
using namespace Dyninst::PatchAPI;
using namespace Dyninst::ParseAPI;
using namespace Dyninst::InstructionAPI;
using namespace Dyninst::SymtabAPI;

#include "function.h"
#include "instPoint.h"

#include "env.h"
#include "defs.h" 
#include "arms_utils.h" 
#include "arms_bb.h"
#include "arms_edge.h" 
#include "arms_function.h"
#include "arms_cfg.h" 
#include "arms_dyninst_cfg.h"
#include "arms_liveness.h"

#include <dynProcess.h>
#include <AddrLookup.h>
#include <liveness.h>

#include <pass.h>

PASS_ONCE();

/* meh */
#define SYMBOLS_AVAILABLE 1

#define __PASS_DEBUG 1

#define fcfiPassLog(M) (cout << "FCFIPass: " << M << "\n")
#define fcfiPassDbg(M) DEBUG(dbgs() << "FCFIPass [DEBUG]: " << M << "\n")

static cl::opt<std::string>
optAT("at",
    cl::desc("AT output"),
    cl::init("at.txt"));

static cl::opt<std::string>
optBinfo("binfo",
    cl::desc("output binfo prefix"),
    cl::init("binfo"));

static cl::opt<bool>
optUnused("unused",
    cl::desc("Search for unused functions"),
    cl::init(false));


#include <PatchModifier.h>


using namespace Dyninst::PatchAPI;
using namespace Dyninst::InstructionAPI;
using namespace Dyninst::SymtabAPI;

#include <errno.h>

/* I will stick to the easy case: if a function has
 * - ZERO incoming edges
 * - is NOT address taken
 * I will mark it as 'unused'
 *
 * I do not follow through direct calls for now. So if function X is called only
 * by Y while Y is never called, I will not mark it as unused.
 */


class Unused {

public:
	Unused(ArmsFunction *f) {
        libname = f->get_cfg()->get_module_name();
        fname =          f->get_name();
        faddr = (void *) f->get_base_addr();
        intermodulair = false;

        std::map<ArmsBasicBlock *, int> icall_args = f->get_icall_args();
        for (auto it : icall_args) {
            ArmsBasicBlock *block = it.first;
            callsites.push_back( (void *) block->get_last_insn_address() );
        }
    }

    string libname;
    string fname;
    void * faddr;
    bool intermodulair;
    std::vector<void *> callsites;
};


/* lazy enough to make this global */
std::vector<Unused> *unused_p;


static int process_vararg_function(ArmsFunction *f, void *arg) {
    ArmsLiveness *alive = (ArmsLiveness *) arg;
    alive->get_vararg_count(f);

    return 0;
}


/* Essentially what we want to do here is intermodulair dead code ellimination
 * on a function level. Or 'recursive inlining'. We don't go that far, we just
 * elliminate the easy stuff.
 */
static int process_unused_function(ArmsFunction *f, void *arg) {
    // only if this is a PLT stub
    if (!f->is_plt()) return 0;

    for (int i = 0; i < unused_p->size(); i++) {
        if (f->get_name() == (*unused_p)[i].fname) {

            /* This means that there exists a PLT stub that calls a function
             * that has the same name of a function which we previously though
             * was not used (i.e., it is not AT and it did not have any incoming
             * edges). */
            (*unused_p)[i].intermodulair = true;
            /* Without doing special tricks, we can only map on the function
             * name. We must thus continue our search: maybe there is another
             * previously thought unused function that has the same function
             * name. */
        
            assert(f->get_entry_points()->size() == 1);
        }
    }
    
    return 0;
}

static int process_function(ArmsFunction *f, void *arg) {
    ArmsLiveness *alive = (ArmsLiveness *) arg;
    alive->get_arg_count(f);

    return 0;
}

static int process_function_callsites(ArmsFunction *f, void *arg) {
    /* Cannot be combined with above as this expects all argcounts to be
     * available */
    ArmsLiveness *alive = (ArmsLiveness *) arg;
    alive->get_icallsites(f);

    return 0;
}

FILE* fp;

static int print_variadics(ArmsFunction *f, void *arg) {
    std::set<void *> *at_funcs = (std::set<void *> *) arg;

    if(f->is_plt() || f->is_lib_dummy()) return 0;
    if (!f->is_variadic()) return 0;

    fprintf(fp,"%p = %d (%s) ", (void *)f->get_base_addr(), f->get_argcount(), f->getMangledName().c_str());
    if (at_funcs->count((void *)f->get_base_addr())) {
        fprintf(fp," AT");
    }
    fprintf(fp,"\n");

    return 0;
}

static int print_regulars(ArmsFunction *f, void *arg) {
    std::set<void *> *at_funcs = (std::set<void *> *) arg;

    if(f->is_plt() || f->is_lib_dummy()) return 0;
    if (f->is_variadic()) return 0;

    fprintf(fp,"%p = %d (%s) ", (void *)f->get_base_addr(), f->get_argcount(), f->getMangledName().c_str());
    if (at_funcs->count((void *)f->get_base_addr())) {
        fprintf(fp," AT");
    }
    fprintf(fp,"\n");

    return 0;
}

static int print_disas_errs(ArmsFunction *f, void *arg) {
    std::set<ArmsBasicBlock*> *blocks = f->get_basic_blocks();
    
    for (std::set<ArmsBasicBlock *>::iterator it  = blocks->begin();
                                              it != blocks->end();
                                              it++) {
        ArmsBasicBlock *block = *it;
        if (block->is_disas_err()) {

            fprintf(fp,"%p = %s\n", (void *) block->is_disas_err(), f->getMangledName().c_str());

            return 0;
        }
    }
    return 0;
}

static int print_icalls(ArmsFunction *f, void *arg) {
    std::set<void *> *at_funcs = (std::set<void *> *) arg;
    

    
    std::vector<ArmsBasicBlock*> entry_blocks;
    entry_blocks.assign(f->get_entry_points()->begin(), f->get_entry_points()->end());
   
    bool is_unused = true;
    while(entry_blocks.size() > 0) {
        ArmsBasicBlock *bb = entry_blocks.back();
        entry_blocks.pop_back();

        if (bb->incoming_edge_count() != 0) {
            is_unused = false;
            break;
        }
        if (at_funcs->count((void *)f->get_base_addr())) {
            is_unused = false;
            break;
        }
    }

    if (is_unused) 
        unused_p->push_back( Unused(f) );


    std::map<ArmsBasicBlock *, int> icall_args = f->get_icall_args();
    int i = 0;
    for (auto it : icall_args) {
        ArmsBasicBlock *block = it.first;
        int args = it.second;

        /* do not print blocks that end with a syscall */
        if (block->has_syscall()) continue;

        fprintf(fp,"%p = %d (%s.%d)\n", (void *) block->get_last_insn_address(), args, f->getMangledName().c_str(),i);
        i++;
    }
    return 0;
}

static int print_plts(ArmsFunction *f, void *arg) {
    if (f->is_plt()) {

        fprintf(fp,"%p = %s\n", (void *)f->get_base_addr(),f->get_name().c_str());

    }
    return 0;
}

static int print_nonvoids(ArmsFunction *f, void *arg) {
    if(f->is_plt() || f->is_lib_dummy()) return 0;

    if (f->get_write_rax()) {
        fprintf(fp,"%p = %s\n", (void *)f->get_base_addr(),f->getMangledName().c_str());
    }
    return 0;
}

static int print_nonvoidicalls(ArmsFunction*f, void *arg) {
    std::map<ArmsBasicBlock *, int> icall_args = f->get_icall_args();
    int i = 0;
    for (auto it : icall_args) {
        ArmsBasicBlock *block = it.first;
        int args = it.second;

        /* skip syscalls */
        if (block->has_syscall()) continue;

        if (block->get_read_rax()) {
            fprintf(fp,"%p = %s.%d\n", (void *) block->get_last_insn_address(), f->getMangledName().c_str(),i);
        }
        i++;
    }
    return 0;
}

static int print_goals(ArmsFunction *f, void *arg) {
    std::map<ArmsBasicBlock *, int> icall_args = f->get_icall_args();
    int i = 0;
    for (auto it : icall_args) {
        ArmsBasicBlock *block = it.first;
        int args = it.second;

        /* skip syscalls */
        if (block->has_syscall()) continue;

        if (args == 0) continue;
        
        std::set<ArmsFunction*> dependencies = block->get_dependencies();
        for (auto it  = dependencies.begin();
                  it != dependencies.end();
                  it++) {
            ArmsFunction *dep = *it;
            fprintf(fp, "%p = %s.%d -> %p = %s\n",
                    (void *) block->get_last_insn_address(), f->getMangledName().c_str(), i, 
                    (void *) dep->get_base_addr(), dep->getMangledName().c_str() );
        }

        i++;
    }
    return 0;
}


void getParams(BPatch_image *image, BPatch_addressSpace *as, CFG *cfg) {

    ArmsLiveness alive;
    alive.set_bpatch_image(image);
    if (cfg->foreach_function(ArmsLiveness::parse_functions, &alive) < 0) {
        fcfiPassLog("Could not analyze functions");
        return;
    }
    if (cfg->foreach_function(process_vararg_function, &alive) < 0) {
        fcfiPassLog("Could not analyze functions");
        return;
    }
    if (cfg->foreach_function(process_function, &alive) < 0) {
        fcfiPassLog("Could not analyze functions");
        return;
    }
    if (cfg->foreach_function(process_function_callsites, &alive) < 0) {
        fcfiPassLog("Could not analyze functions");
        return;
    }

    
}


std::map<string, std::set<void *> > getATs(string filename) {
    std::map<string, std::set<void *> > result;
    string libname;
    void *offset;

    std::ifstream infile(filename);
    while (infile >> libname >> offset) {
        result[libname].insert(offset);
    }

    return result;
}


namespace {

  class FCFIPass : public ModulePass {

    public:
        static char ID;
        FCFIPass() : ModulePass(ID) {}

        virtual bool runOnModule(void *M) {
            BPatch_addressSpace *as = (BPatch_addressSpace*) M;
            bool isBinEdit = dynamic_cast<BPatch_binaryEdit*>(as) != NULL;

            if (isBinEdit) fcfiPassLog("Running (binary edit)...");
            else           fcfiPassLog("Running (runtime)...");

            fcfiPassLog("Command-line arguments given (opt*): '" << optAT.getValue() << "'\n");


            fcfiPassLog("Reading AT functions...");
            std::map<string, std::set<void*> > at_funcs = getATs(optAT.getValue());

            BPatch_image *image = as->getImage();

            std::vector<BPatch_object *> objs;
            image->getObjects(objs);


            DICFG *cfg;
                
            std::vector<Unused> unused;
            unused_p = &unused;
            
            fcfiPassLog("Performing static analysis on objects...");

            /* Loop over all modules (shared libraries) */
//          for (unsigned i = 0; i < objs.size(); i++) {
            for (unsigned i = 0; i < 1; i++) {
                string pathname = objs[i]->pathName();
                string objname  = objs[i]->name();

                if(strncmp(objname.c_str(),"libdyninstAPI_RT.so",19) == 0) { continue; }
                if(strncmp(objname.c_str(),"libm.so",7) == 0) { continue; }
                if(strncmp(objname.c_str(),"libicui18n.so",13) == 0) { continue; }
                if(strncmp(objname.c_str(),"libv8.so",8) == 0) { continue; }
                if(strncmp(objname.c_str(),"libicuuc.so",11) == 0) { continue; }

                char output[512];
                cfg = dyninst_build_cfg(as, i);
                sprintf(output,"%s.%s",optBinfo.getValue().c_str(),objname.c_str());
                fp = fopen(output,"w");
                fprintf(fp,"Object: %s\n", objname.c_str());
               
                fprintf(stderr,"object[%d] = %s > %s\n", i, pathname.c_str(), output);

                if(!cfg) {
                  fcfiPassLog("CFG generation failed");
                  return false;
                }
                
                fprintf(fp,"Functions: %lu\n", cfg->count_functions());
                
                getParams(image, as, cfg);
                fprintf(fp,"\n[varargs]\n");
                if (cfg->foreach_function(print_variadics, &at_funcs[objname]) < 0) {
                    fcfiPassLog("Could not print variadic functions");
                }
                fprintf(fp,"\n[args]\n");
                if (cfg->foreach_function(print_regulars, &at_funcs[objname]) < 0) {
                    fcfiPassLog("Could not print regular functions");
                }
                fprintf(fp,"\n[icall-args]\n");
                if (cfg->foreach_function(print_icalls, &at_funcs[objname]) < 0) {
                    fcfiPassLog("Could not print indirect call argument info");
                }
                fprintf(fp,"\n[plts]\n");
                if (cfg->foreach_function(print_plts, NULL) < 0) {
                    fcfiPassLog("Could not print PLT stubs");
                }
                fprintf(fp,"\n[disas-errors]\n");
                if (cfg->foreach_function(print_disas_errs, NULL) < 0) {
                    fcfiPassLog("Could not print disassembly errors");
                }
                fprintf(fp,"\n[non-voids]\n");
                if (cfg->foreach_function(print_nonvoids, NULL) < 0) {
                    fcfiPassLog("Could not print nonvoids");
                }
                fprintf(fp,"\n[non-void-icalls]\n");
                if (cfg->foreach_function(print_nonvoidicalls, NULL) < 0) {
                    fcfiPassLog("Could not print non void icalls");
                }
                fprintf(fp,"\n[prof-goals]\n");
                if (cfg->foreach_function(print_goals, NULL) < 0) {
                    fcfiPassLog("Could not print profiling goals");
                }

                fclose(fp);
            }

            /*
            fcfiPassLog("Functions that were never called directly:");
            for (auto u : unused) {
                fprintf(stderr,"- [%s] %p: %s\n", u.libname.c_str(),
                                                  u.faddr, 
                                                  u.fname.c_str());
            }
            */


if (optUnused.getValue()) {
            fcfiPassLog("Searching for 'intermodulair' calls to unused functions...");

            for (unsigned i = objs.size(); i-- > 0; ) {
                string pathname = objs[i]->pathName();
                string objname  = objs[i]->name();

                if(strncmp(objname.c_str(),"libdyninstAPI_RT.so",19) == 0) continue;
                
                cfg = dyninst_build_cfg(as, i);
                if(!cfg) {
                  fcfiPassLog("CFG generation failed");
                  return false;
                }

                fcfiPassLog("- " << objname);
                if (cfg->foreach_function(process_unused_function, NULL) < 0) {
                    fcfiPassLog("Could not analyze functions");
                    return false;
                }
            }
}
            
            
            for (unsigned i = 0; i < objs.size(); i++) {
                string pathname = objs[i]->pathName();
                string objname  = objs[i]->name();

                if(strncmp(objname.c_str(),"libdyninstAPI_RT.so",19) == 0) continue;

                char output[512];
                sprintf(output,"%s.%s",optBinfo.getValue().c_str(),objname.c_str());
                fp = fopen(output,"a");
               
                fprintf(fp,"\n[unused]\n");

if (optUnused.getValue()) {
                for (auto u : unused) {
                    if (u.libname == pathname) {
                        if (!u.intermodulair) {
//                          fprintf(fp,"%p = %s\n", u.faddr, u.fname.c_str());
                            for (auto it : u.callsites) {
                                fprintf(fp,"%p = %s\n", it, u.fname.c_str());
                            }

                        }
                    }
                }
}
                fprintf(fp,"\n[done]\n");
                fclose(fp);
            }
            
            
            fcfiPassLog("Done...");
            fprintf(stderr, "[+] Done...\n");
            
            return false;
        }
  };
}

char FCFIPass::ID = 0;
RegisterPass<FCFIPass> MP("fcfi_pass", "FCFI Pass");

