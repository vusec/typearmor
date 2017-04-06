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


INSTALL_DIR = ../bin

include ../Makefile.inc

PASSNAME := fcfi_pass
SHARED   := arms_bb.o \
            arms_edge.o \
            arms_cfg.o \
            arms_function.o \
            arms_dyninst_cfg.o \
            arms_utils.o \
            arms_liveness.o
OBJS     := fcfi_pass.o $(SHARED)
CLEANUP  := core test test.o o.test objdump4cfg

V?=0
ifneq ($V,0)
QUIET=
ECHO:=@\#
QMAKE=VERBOSE=1 make
else
QUIET= @
ECHO= echo
QMAKE=make -s
endif

CFLAGS += -Darch_x86_64 \
          -Dx86_64_unknown_linux2_4 \
          -DARCH=x64 \
          -D__STDC_LIMIT_MACROS \
          -D__STDC_CONSTANT_MACROS \
          -std=c++0x \
          -fasynchronous-unwind-tables \
          -fPIC \
          -g \
          -Wno-deprecated \
          -Dos_linux

LDFLAGS += -L$(DYNINST_LIB)

CC=g++
CXX=g++
INCLUDES=$(DYNINST_INC) -I../include

PASSLIBNAME = $(PASSNAME).di

.PHONY: all install clean distclean

all: $(PASSLIBNAME)

$(PASSLIBNAME): $(OBJS)
	$(QUIET) $(ECHO) "  [LINK] $@"
	$(QUIET) $(CXX) $(CFLAGS) -shared -o $@ $(OBJS) $(LDFLAGS)

%.o: %.C
	$(QUIET) $(ECHO)  "  [C++] $<"
	$(QUIET) $(CXX) $(CFLAGS) $(INCLUDES) -c -o $@ $<

%.o: %.c
	$(QUIET) $(ECHO)  "  [C] $<"
	$(QUIET) $(CXX) $(CFLAGS) $(INCLUDES) -c -o $@ $<

install: $(INSTALL_DIR)/$(PASSLIBNAME)

$(INSTALL_DIR)/$(PASSLIBNAME): $(PASSLIBNAME)
	$(QUIET) $(ECHO) "  [INSTALL] $< -> $@"
	$(QUIET) install -c -D -m 744 $? $@

clean:
	$(QUIET) $(ECHO) "  [RM] $(OBJS) $(PASSLIBNAME) $(CLEANUP)"
	$(QUIET) rm -f $(OBJS) $(PASSLIBNAME) $(CLEANUP)

distclean: clean
	$(QUIET) $(ECHO)  "  [RM] $(INSTALL_DIR)/$(PASSLIBNAME)"
	$(QUIET) rm -f $(INSTALL_DIR)/$(PASSLIBNAME)

# Extra dependencies
arms_dyninst_cfg.o: arms_icall_resolver.h env.h

# Special
fcfi_pass.o: fcfi_pass.C env.h
	$(QUIET) $(ECHO)  "  [C++] $<"
	$(QUIET) $(CXX) $(CFLAGS) $(INCLUDES) -c fcfi_pass.C

