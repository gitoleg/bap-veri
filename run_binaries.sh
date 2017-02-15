#!/bin/bash

bash -ex .travis-opam.sh
eval `opam config env`

opam install piqi -y
opam install conf-bap-llvm
opam install bap --deps-only
opam install bap -v

# TODO should I use a current user ?
USER=${TRAVIS_REPO_SLUG%/*}

mkdir -p factory
cd factory

# getting sources
get_source() {
    if [ ! -e $1 ]; then
        git clone https://github.com/BinaryAnalysisPlatform/$1.git
    fi
}

# install bap-frames and libtrace
get_source "bap-frames"
cd bap-frames/libtrace
./autogen.sh
./configure
make
sudo make install
cd ../
oasis setup
./configure --prefix=`opam config var prefix`
make && make reinstall
cd ../

# install bap-veri
get_source "bap-veri"
cd bap-veri
oasis setup
/configure --prefix=`opam config var prefix`
make && make reinstall
cd ..

get_source "arm-binaries"
get_source "x86-binaries"
get_source "x86_64-binaries"

git clone https://github.com/gitoleg/veri-results
results="veri-results"

qemu_dir="qemu"
if [ ! -e $qemu_dir ]; then
    wget "https://github.com/BinaryAnalysisPlatform/qemu/releases/download/tracewrap-2.0-rc2/qemu-tracewrap-ubuntu-14.04.4-LTS.tgz"
    mkdir $qemu_dir
    tar xzf qemu-tracewrap-ubuntu-14.04.4-LTS.tgz -C $qemu_dir
fi
qemu_dir="qemu/bin"


# TODO: add to cache   - $HOME/opt
# pintrace_dir="pintrace"
# if [ ! -e $qemu_dir ]; then
#     wget "http://software.intel.com/sites/landingpage/pintool/downloads/pin-2.14-71313-gcc.4.4.7-linux.tar.gz"
#     tar xvz pin-2.14-71313-gcc.4.4.7-linux.tar.gz -C $HOME/opt
# fi
# export PIN_ROOT=$HOME/opt/pin-2.14-71313-gcc.4.4.7-linux
# export PATH=$PATH:$PIN_ROOT
# echo 'export PIN_ROOT=$HOME/opt/pin-2.14-71313-gcc.4.4.7-linux' >>$HOME/.bashrc
# echo 'export PATH=$PATH:$PIN_ROOT' >>$HOME/.bashrc

run_veri() {
    veri_out=$2.txt
    case $1 in
        arm) rules_file="bap-veri/rules/arm_qemu"
             ;;
        x86) rules_file="bap-veri/rules/x86_qemu"
             ;;
        x86_64) rules_file="bap-veri/rules/x86"
                ;;
        *) echo "didn't find rules for $1 arch"
    esac
    bap-veri --show_stat --output=$veri_out --rules $ruls_file $2
}

run_qemu() {
    name=$(basename $2).frames
    ./$qemu_dir/qemu-$1 -tracefile $name.frames $2 --help
    run_veri $1 $name
    dst=$(dirname $2)
    cat $veri_out
    mkdir -p "$results/$dst"
    cp $veri_out "$results/$dst"
}

# TODO: use basename for frames file ?
run_pin() {
    echo "launch: pin -injection child -t obj-intel64/bpt.so -o $1.frames -- $1 --help "
#    pin -injection child -t obj-intel64/bpt.so -o $1.frames -- $1 --help
}

# calculating diff

subdirs="binutils coreutils findutils"
arm_bin="arm-binaries"
x86_bin="x86-binaries/elf"
x86_64_bin="x86_64-binaries/elf"

for arch in $arm_bin $x86_bin $x86_64_bin; do
    for subdir in $subdirs; do
        src_path="$arch/$subdir"
        if [ -e $src_path ]; then
            for file in $src_path/*; do
                res="$results/$file.frames"
                if [ ! -e $res ]; then
                    files[$i]=$file
                    i=$i+1
                fi
            done
        fi
    done
done

arch_of_path() {
    ok_arm=$(echo $1 | grep  arm)
    ok_x86_64=$(echo $1 | grep x86_64)
    if [ ! -z $ok_arm ]; then
        arch="arm"
    else
        if [ ! -z $ok_x86_64 ]; then
            arch="x86_64"
        else arch="i386"
        fi
    fi
}

#run first 1 files in diff
# TODO: commit a file(s) every e.g. 10 iterations
for i in 0 ; do
    file=${files[i]}

    arch_of_path $file
    if [ $arch == "x86_64" ]; then
        tool="pin"
    else
        tool="qemu"
    fi

    if [ $tool == "qemu" ]; then
        run_qemu $arch $file
    else
        run_pin $arch $file
    fi
done
