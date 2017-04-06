Thursday April 6. Starting from scratch... 
- Ubuntu Server 16.04.2 LTS in VirtualBox
- vusec / vusec
- I will use ~/testing/ to store old sources and previous attempts.
- !! remove .ssh/id_rsa !!

# install packages
sudo apt-get install build-essential cmake 
sudo apt-get install libboost-all-dev libelf-dev libiberty-dev
sudo apt-get install libpcre3-dev libssl-dev

# build Dyninst
wget https://github.com/dyninst/dyninst/archive/v9.3.1.tar.gz
tar -zxvf v9.3.1.tar.gz
cd dyninst-9.3.1
mkdir install
cd install
cmake .. -DCMAKE_INSTALL_PREFIX=`pwd`
make -j2
make install


# build static-analysis
cd 
git clone
cd typearmor
# edit build_envsetup
. build_envsetup
cd static
make
make install
cd ..
cd di-opt
make
make install
cd ..

# run typearmor on S&P binaries
cd server-bins
../run-ta-static.sh ./nginx
# output will be in ../out/binfo.*
# log in ta.log
