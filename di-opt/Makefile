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



LDFLAGS += -ldl -lrt -rdynamic

SRCS = di-opt.cpp

all: di-opt

ECHO=echo
CXX=g++
CFLAGS += -I../include \
          -fasynchronous-unwind-tables \
          -fPIC \
          -g \
          -D__STDC_LIMIT_MACROS \
          -Wno-deprecated \
          -Dos_linux \
          -Darch_x86_64  \
          -Dx86_64_unknown_linux2_4 \
          -DARCH=x64 \
          -std=c++0x

INSTALLDIR=../bin

# Dyninst headers
include ../Makefile.inc

INCLUDES=$(DYNINST_INC) -I../include

LDFLAGS += -L$(DYNINST_LIB) -ldyninstAPI -linstructionAPI -lparseAPI -lsymtabAPI -ldl -lrt -rdynamic

INSTALL_DIR = ../bin

all: di-opt

di-opt: di-opt.o
	$(QUIET) $(ECHO) "  [LINK] $@"
	$(QUIET) $(CXX) $(CFLAGS) -o $@ $@.o $(LDFLAGS) $(LIBS)

%.o: %.cpp $(HEADERS)
	$(QUIET) $(ECHO)  "  [C++] $<"
	$(QUIET) $(CXX) $(CFLAGS) $(INCLUDES) -c -o $@ $<

install: $(INSTALL_DIR)/di-opt

$(INSTALL_DIR)/di-opt: di-opt
	install -c -D -m 744 $? $@

clean:
	rm -f *.o di-opt
