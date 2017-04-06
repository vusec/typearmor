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

# start me from within a sub-directory

set -e

if [ $# -lt 1 ]
then	echo "Usage: $0 <executable> [args]"
	exit 1
fi

exe=$1

# Parse some additional info on the binary to be processed, and store
# it in a database for use by analysis.c
export BINFO=`pwd`/../out/binfo
echo "Using bininfo prefix $BINFO"
rm -f $BINFO

DI=$DYNINST_ROOT/install
DI_OPT=../bin/di-opt
if [ ! -x $DI_OPT ]
then	echo "$DI_OPT not found. Please build and install it first."
	echo "And invoke this script from an app directory."
	exit 1
fi

set -x
sudo DYNINSTAPI_RT_LIB=$DI/lib/libdyninstAPI_RT.so LD_LIBRARY_PATH=$DI/lib:$LD_LIBRARY_PATH $DI_OPT -load=`pwd`/../bin/fcfi_pass.di -fcfi_pass -binfo=$BINFO -args `pwd`/$exe $* 2>ta.log

