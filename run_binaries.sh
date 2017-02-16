#!/bin/bash

set -ex

bash -ex .travis-opam.sh
eval `opam config env`

opam install piqi -y
opam install conf-bap-llvm
opam install bap-std --deps-only
opam install bap-std -v

#TODO: rm this ??
opam_lib=$(opam config var prefix)/lib
rm -rf $opam_lib/{bap-frames,bap-plugin-frames,bap/frames.plugin}

opam install bap-frames

workdir=$HOME/factory
mkdir -p $workdir
cd $workdir

# getting sources
get_source() {
    if [ ! -e $1 ]; then
        git clone https://github.com/BinaryAnalysisPlatform/$1.git
    fi
}

# TODO : do I really need it ? it is used for bap-veri only
# and it's possible to install it through opam
pkg_make_install() {
    if ocamlfind query $1 2>/dev/null ; then
        cd $1
        oasis setup
        ./configure --prefix=`opam config var prefix`
        make && make install
        cd ..
    fi
}

wget_pkg () {
    if [ ! -e $1 ]; then
        mkdir $1
        wget $2
        tar xzf $(basename $2) -C $1
    fi
}

get_source bap-frames
get_source bap-veri
get_source bap-pintraces
get_source arm-binaries
get_source x86-binaries
get_source x86_64-binaries

# install libtrace
cd bap-frames/libtrace
./autogen.sh && ./configure
make && sudo make install
cd $workdir

# install bap-veri
pkg_make_install bap-veri

results_repo=https://github.com/gitoleg/veri-results
results="veri-results"
rm -rf $results
git clone $results_repo

# qemu_dir="qemu"
# wget_pkg $qemu_dir \
#          "https://github.com/BinaryAnalysisPlatform/qemu/releases/download/tracewrap-2.0-rc2/qemu-tracewrap-ubuntu-14.04.4-LTS.tgz"
# qemu_dir="qemu/bin"

rm -rf qemu

if [ ! -e qemu ] ; then
    get_source qemu
    cd qemu
    ./configure --prefix=$HOME --with-tracewrap=../bap-frames --target-list="`echo {arm,i386,x86_64,mips}-linux-user`" --disable-werror
    make
    mkdir -p bin
    cp arm-linux-user/qemu-arm bin
    cp i386-linux-user/qemu-i386 bin
    cp x86_64-linux-user/qemu-x86_64 bin
    cp mips-linux-user/qemu-mips bin
    cd ..
fi
qemu_dir="qemu/bin"

# TODO: rm : tmp
echo $PWD

cd $HOME
pinroot="opt"
wget_pkg $pinroot \
         "http://software.intel.com/sites/landingpage/pintool/downloads/pin-2.14-71313-gcc.4.4.7-linux.tar.gz"

export PIN_ROOT=$HOME/$pinroot/pin-2.14-71313-gcc.4.4.7-linux
export PATH=$PATH:$PIN_ROOT
echo 'export PIN_ROOT=$HOME/$pinroot/pin-2.14-71313-gcc.4.4.7-linux' >>$HOME/.bashrc
echo 'export PATH=$PATH:$PIN_ROOT' >>$HOME/.bashrc
cd $workdir



# TODO: tmp
if [ ! -e $PIN_ROOT/pin ]; then
    echo "no pin!!"
    ls $pinroot
    echo "....."
    ls $PIN_ROOT
    exit 1
fi

pintrace_dir="bap-pintraces"
cd $pintrace_dir
make
cd ..

# TODO : add a second file - with stat
run_veri() {
    veri_sum=$(basename $2).sum
    veri_stat=$(basename $2).stat
    case $1 in
        arm) rules_file="bap-veri/rules/arm_qemu"
             ;;
        x86) rules_file="bap-veri/rules/x86_qemu"
             ;;
        x86_64) rules_file="bap-veri/rules/x86"
                ;;
        *) echo "didn't find rules for $1 arch"
    esac
    bap-veri --show_stat --output=$veri_sum --rules $ruls_file $2 > $veri_stat
}

run_qemu() {
    echo "launch: $qemu_dir/qemu-$1 -tracefile $3 $2 --help"
    ./$qemu_dir/qemu-$1 -tracefile $3 $2 --help
    cp $3 ../
}

run_pin() {
    # TODO: rm : tmp
    echo $PWD

    echo "launch: pin -injection child -t obj-intel64/bpt.so -o $2 -- $1 --help"
    cd $pintrace_dir
    pin -injection child -t obj-intel64/bpt.so -o $2 -- $1 --help
    cp $2 ../
    cd ..
}

arch_of_path() {
    case $1 in
        *arm*) arch=arm
               ;;
        *x86_64*) arch=x86_64
                  ;;
        *x86*) arch=x86
               ;;
        *)  echo "didn't find rules for $1 arch"
    esac
}

deploy () {
    cd $results
    git config user.name "Travis CI"
    git config user.email "$COMMIT_AUTHOR_EMAIL"

    new_files=$(git ls-files --others --exclude-standard)
    changes=$(git diff)
    if [ ! -z "$new_files$changes" ]; then

        git add .
        git commit -m "added files : $new_files"

        ENCRYPTED_KEY_VAR="encrypted_${ENCRYPTION_LABEL}_key"
        ENCRYPTED_IV_VAR="encrypted_${ENCRYPTION_LABEL}_iv"
        ENCRYPTED_KEY=${!ENCRYPTED_KEY_VAR}
        ENCRYPTED_IV=${!ENCRYPTED_IV_VAR}
        openssl aes-256-cbc -K $ENCRYPTED_KEY -iv $ENCRYPTED_IV -in deploy_key.enc -out deploy_key -d
        chmod 600 deploy_key
        eval `ssh-agent -s`
        ssh-add deploy_key

        # DO i need some other branch ?
        git push $results_repo master
    fi
}



subdirs="binutils coreutils findutils"
arm_bin="arm-binaries"
x86_bin="x86-binaries/elf"
x86_64_bin="x86_64-binaries/elf"

# TODO: rm : tmp
echo $PWD
if [! -e $PIN_ROOT/pin ]; then
    echo "didn't find: pin"
fi

i=0
for arch in $x86_bin $x86_64_bin $arm_bin;  do
    for subdir in $subdirs; do
        src_path="$arch/$subdir"
        if [ -e $src_path ]; then
            for file in $src_path/*; do
                res="$results/$file.frames"
                if [ ! -e $res ]; then

                    # TODO : temp - for test purposes only!
                    let i=i+1
                    if [ $i -eq 10 ]; then
                        return 0
                    fi

                    arch_of_path $file
                    if [ $arch == "x86_64" ]; then
                        tool="pin"
                    else
                        tool="qemu"
                    fi

                    trace=$(basename $file).frames
                    if [ $tool == "qemu" ]; then
                        run_qemu $arch $file $trace
                    else
                        tmp=$PWD/$file
                        run_pin $tmp $trace
                    fi

                    run_veri $arch $trace
                    dst=$(dirname $file)
                    cat $veri_out
                    mkdir -p "$results/$dst"
                    cp $veri_stat $veri_sum "$results/$dst"

                    let c=$i%10
                    if [ $c -eq 0 ]; then
                        deploy
                    fi

                fi
            done
        fi
    done
done

deploy
