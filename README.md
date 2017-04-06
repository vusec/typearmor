# TypeArmor
This software is the open-source component of our paper "A Tough call: Mitigating Advanced Code-Reuse Attacks At The Binary Level", published in IEEE Security & Privacy (S&P) 2016. It currently only includes the static analysis of our work, allowing you to retrieve argument count information for callees and callsites of compiled C/C++ applications.  

This code is released under the [Apache 2.0 license](https://github.com/vusec/typearmor/blobl/master/LICENSE-2.0.txt).

# **Disclaimer**
####**If, for some weird reason, you think running this code broke your device, you get to keep both pieces.**

# Installation
To build the static-analysis pass, we first need to compile Dyninst. The current
latest version (9.3.1) seems to work perfectly fine. The following was tested on
Ubuntu Server 16.04.2 LTS. I might share a copy of VM later.

First install some packages:

    sudo apt-get install build-essential cmake 
    sudo apt-get install libboost-all-dev libelf-dev libiberty-dev

Next, download and build Dyninst. I assume you are in $(HOME):

    wget https://github.com/dyninst/dyninst/archive/v9.3.1.tar.gz
    tar -zxvf v9.3.1.tar.gz
    cd dyninst-9.3.1
    mkdir install
    cd install
    cmake .. -DCMAKE_INSTALL_PREFIX=`pwd`
    make -j2
    make install

Next, download and build TypeArmor:

    cd 
    git clone git@github.com:vusec/typearmor.git
    cd typearmor
    # update DYNINST_ROOT in ./envsetup.sh
    . build_envsetup
    cd static
    make
    make install
    cd ..
    cd di-opt
    make
    make install
    cd ..

You can now run TypeArmor on any given binary. The repository is shipped with
the binaries used in our S&P paper:

    cd server-bins
    ../run-ta-static.sh ./nginx

This will generate new binary info file(s) in `../out/binfo.*`. Log output will
be stored in `./ta.log`

# binfo format

Each `binfo.*` file contains different sections:

* *[varargs]*
  Variadic functions. Listed in the format <address> = <minimum argccount> (<function symbol>).
* *[args]*
  Regular (non-variadic) functions. Listed in the format <address> = <minimum
  argcount> (<function symbol>).
* *[icall-args]*
  Indirect callsites. Listed in the format <address> = <max prepared argcount>
  (<function symbol>.<callsite index in function>)
* *[plts]*
  PLT entries.
* *[disas-errors]*
  Disassembly errors.
* *[non-voids]*
  Functions that seem to be of type non-void (i.e., they write RAX). Listed in
  the format <address> = <function symbol>.
* *[prof-goals]*
  Indirect calls that could benefit from a profiling sessions. Listed in the
  format <icall address> = <function symbol.index> -> <address of function from
  which we could not backtrack> = <target function symbol>.
* *[unused]*
  Function is never used.
* *[done]*
  Marker that indicates the end of the binfo.