##
 # Copyright 2017, Victor van der Veen
 #
 # Licensed under the Apache License, Version 2.0 (the "License");
 # you may not use this file except in compliance with the License.
 # You may obtain a copy of the License at
 #
 #     http://www.apache.org/licenses/LICENSE-2.0
 #
 # Unless required by applicable law or agreed to in writing, software
 # distributed under the License is distributed on an "AS IS" BASIS,
 # WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 # See the License for the specific language governing permissions and
 # limitations under the License.
 ## 

DYNINST_INC  = -I$(DYNINST_ROOT) \
               -I$(DYNINST_ROOT)/symlite/h \
               -I$(DYNINST_ROOT)/common/h \
               -I$(DYNINST_ROOT)/dyninstAPI/h \
               -I$(DYNINST_ROOT)/instructionAPI/h \
               -I$(DYNINST_ROOT)/dataflowAPI/h \
               -I$(DYNINST_ROOT)/symtabAPI/h \
               -I$(DYNINST_ROOT)/stackwalk/h \
               -I$(DYNINST_ROOT)/dynC_API/h \
               -I$(DYNINST_ROOT)/dwarf/h \
               -I$(DYNINST_ROOT)/proccontrol/h \
               -I$(DYNINST_ROOT)/elf/h \
               -I$(DYNINST_ROOT)/parseAPI/h \
               -I$(DYNINST_ROOT)/patchAPI/h \
               -I$(DYNINST_ROOT)/dyninstAPI_RT/h \
               -I$(DYNINST_ROOT)/symlite/src \
               -I$(DYNINST_ROOT)/common/src \
               -I$(DYNINST_ROOT)/dyninstAPI/src \
               -I$(DYNINST_ROOT)/instructionAPI/src \
               -I$(DYNINST_ROOT)/dataflowAPI/src \
               -I$(DYNINST_ROOT)/symtabAPI/src \
               -I$(DYNINST_ROOT)/stackwalk/src \
               -I$(DYNINST_ROOT)/dynC_API/src \
               -I$(DYNINST_ROOT)/dwarf/src \
               -I$(DYNINST_ROOT)/proccontrol/src \
               -I$(DYNINST_ROOT)/elf/src \
               -I$(DYNINST_ROOT)/parseThat/src \
               -I$(DYNINST_ROOT)/parseAPI/src \
               -I$(DYNINST_ROOT)/patchAPI/src \
               -I$(DYNINST_ROOT)/dyninstAPI_RT/src \
               -I$(DYNINST_ROOT)/install/common/h
