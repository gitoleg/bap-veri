#!/bin/bash

bash -ex .travis-opam.sh
eval `opam config env`

opam install piqi -y
opam install conf-bap-llvm
opam install bap-std --deps-only
opam install bap-std -v

#TODO: rm this
opam_lib=$(opam config var prefix)/lib
rm -rf $opam_lib/bap-frames $opam_lib/bap-plugin-frames
rm -rf $opam_lib/bap/frames.plugin

opam install bap-frames

# TODO should I use a current user ?
USER=${TRAVIS_REPO_SLUG%/*}

workdir=$HOME/factory
mkdir -p $workdir
cd $workdir

# getting sources
get_source() {
    if [ ! -e $1 ]; then
        git clone https://github.com/BinaryAnalysisPlatform/$1.git
    fi
}

pkg_make_install() {
    if ocamlfind query $1 2>/dev/null ; then
        cd $1
        oasis setup
        ./configure --prefix=`opam config var prefix`
        make && make reinstall
        cd ..
    fi
}

get_source "bap-frames"
get_source "bap-veri"
get_source "bap-pintraces"
get_source "arm-binaries"
get_source "x86-binaries"
get_source "x86_64-binaries"

# install libtrace
cd bap-frames/libtrace
./autogen.sh && ./configure
make && sudo make install
cd $workdir

# install bap-frames bap-veri
# pkg_make_install bap-frames
pkg_make_install bap-veri

git clone https://github.com/gitoleg/veri-results
results="veri-results"

qemu_dir="qemu"
if [ ! -e $qemu_dir ]; then
    wget "https://github.com/BinaryAnalysisPlatform/qemu/releases/download/tracewrap-2.0-rc2/qemu-tracewrap-ubuntu-14.04.4-LTS.tgz"
    mkdir $qemu_dir
    tar xzf qemu-tracewrap-ubuntu-14.04.4-LTS.tgz -C $qemu_dir
fi
qemu_dir="qemu/bin"

pinroot="pinroot"
if [ ! -e $pinroot ]; then
    mkdir $pinroot
    wget "http://software.intel.com/sites/landingpage/pintool/downloads/pin-2.14-71313-gcc.4.4.7-linux.tar.gz"
    tar xzf pin-2.14-71313-gcc.4.4.7-linux.tar.gz -C $pinroot
fi
export PIN_ROOT=$HOME/$workdir/$pinroot/pin-2.14-71313-gcc.4.4.7-linux
export PATH=$PATH:$PIN_ROOT
echo 'export PIN_ROOT=$HOME/$workdir/$pinroot/pin-2.14-71313-gcc.4.4.7-linux' >>$HOME/.bashrc
echo 'export PATH=$PATH:$PIN_ROOT' >>$HOME/.bashrc

pintrace_dir="bap-pintraces"
cd $pintrace_dir
make
cd ..

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

run_with_qemu() {
    ./$qemu_dir/qemu-$1 -tracefile $3 $2 --help
    cp $3 ../
    run_veri $1 $name
    dst=$(dirname $2)
    cat $veri_out
    mkdir -p "$results/$dst"
    cp $veri_out "$results/$dst"
}

run_with_pin() {
    echo "launch: pin -injection child -t obj-intel64/bpt.so -o $2 -- $1 --help"
    cd $pintrace_dir
    pin -injection child -t obj-intel64/bpt.so -o $2 -- $1 --help
    cp $2 ../
    cd ..
}

# calculating diff

subdirs="binutils coreutils findutils"
arm_bin="arm-binaries"
x86_bin="x86-binaries/elf"
x86_64_bin="x86_64-binaries/elf"

i=0
for arch in $arm_bin $x86_bin $x86_64_bin; do
    for subdir in $subdirs; do
        src_path="$arch/$subdir"
        if [ -e $src_path ]; then
            for file in $src_path/*; do
                res="$results/$file.frames"
                if [ ! -e $res ]; then
                    files[$i]=$file
                    let i=i+1
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

    trace=$(basename $file).frames
    if [ $tool == "qemu" ]; then
        run_with_qemu $arch $file $trace
    else
        run_with_pin $file $trace
    fi

    run_veri $arch $trace
    dst=$(dirname $file)
    cat $veri_out
    mkdir -p "$results/$dst"
    cp $veri_out "$results/$dst"
done
