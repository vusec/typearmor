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

export DYNINST_ROOT=${HOME}/dyninst-9.3.1

export DYNINST_LIB=$DYNINST_ROOT/install/lib
export DYNINSTAPI_RT_LIB=$DYNINST_LIB/libdyninstAPI_RT.so
export LD_LIBRARY_PATH=$DYNINST_LIB:$LD_LIBRARY_PATH

