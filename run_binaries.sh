#!/bin/bash

#set -ex

#bash -ex .travis-opam.sh
eval `opam config env`

opam install piqi -y
opam install conf-bap-llvm
opam install bap-std --deps-only
opam install bap-std -v
opam install bap-llvm -y
opam install bap-x86 -y
opam install bap-arm -y
opam install pcre -y
opam install textutils -y

#TODO: rm? it's here due to a strange behaviour of bap-frames.
# opam_lib=$(opam config var prefix)/lib
# rm -rf $opam_lib/{bap-frames,bap-plugin-frames,bap/frames.plugin}
# opam reinstall bap-frames

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
# cd bap-frames/libtrace
# ./autogen.sh && ./configure
# make && sudo make install
# cd $workdir

# install bap-veri
# TODO: reinstall!
#pkg_make_install bap-veri

results_repo=https://github.com/gitoleg/veri-results
results="$workdir/veri-results"

# to ensure we're are working with fresh
#rm -rf $results
#git clone $results_repo

if [ ! -e qemu ] ; then
    get_source qemu
    cd qemu
    ./configure --prefix=$HOME --with-tracewrap=../bap-frames --target-list="`echo {arm,i386,x86_64,mips}-linux-user`" --disable-werror
    make
    mkdir -p bin
    cp arm-linux-user/qemu-arm bin
    cp i386-linux-user/qemu-i386 bin/qemu-x86
    cp x86_64-linux-user/qemu-x86_64 bin
    cp mips-linux-user/qemu-mips bin
    cd ..
fi
qemu_dir="$workdir/qemu/bin"

if [ -z "$PIN_ROOT" ]; then
    pinroot="$workdir/pinroot"
    wget_pkg $pinroot \
        "http://software.intel.com/sites/landingpage/pintool/downloads/pin-2.14-71313-gcc.4.4.7-linux.tar.gz"

    export PIN_ROOT=$pinroot/pin-2.14-71313-gcc.4.4.7-linux
    export PATH=$PATH:$PIN_ROOT
    echo 'export PIN_ROOT=$pinroot/pin-2.14-71313-gcc.4.4.7-linux' >>$HOME/.bashrc
    echo 'export PATH=$PATH:$PIN_ROOT' >>$HOME/.bashrc
    cd $workdir
fi

pintrace_dir="bap-pintraces"
cd $pintrace_dir
make
cd ..

#replace to a call from opam
run_veri() {
    veri_out=$(basename $2).sum
    case $1 in
        arm) rules_file="bap-veri/rules/arm_qemu"
             ;;
        x86) rules_file="bap-veri/rules/x86_qemu"
             ;;
        x86_64) rules_file="bap-veri/rules/x86"
                ;;
        *) echo "didn't find rules for $1 arch"
    esac
    echo "bap-veri --output=$veri_out --rules $rules_file $2.frames"
    ./bap-veri/veri_main.native --csv=$arch.csv --output=$veri_out --rules $rules_file $2.frames 1>/dev/null
}

run_qemu() {
    case $1 in
	*arm) qemu_args="-L /usr/arm-linux-gnueabi"
	    ;;
	*) qemu_args=""
	    ;;
    esac

    tracename=$(basename $2).frames
    echo "launch: $qemu_dir/qemu-$1 $qemu_args -tracefile $tracename $2 --help"
    cd $qemu_dir
    ./qemu-$1 $qemu_args -tracefile $tracename $2 --help 1>/dev/null 
    mv $tracename $workdir
    cd $workdir
}

run_pin() {
    tracename=$(basename $1).frames
    echo "launch: pin -injection child -t obj-intel64/bpt.so -o $tracename -- $1 --help"
    cd $pintrace_dir 
    pin -injection child -t obj-intel64/bpt.so -o $tracename -- $1 --help 1>/dev/null 
    mv $tracename $workdir
    cd $workdir
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
    return 0
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

i=0
for arch in $x86_bin $x86_64_bin $arm_bin; do
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

		    case $file in 
			*sysinfo) echo "will not process $file"
			    ;;
			*)
			    full=$PWD/$file
			    echo "full is $full"
			    if [ $tool == "qemu" ]; then
				run_qemu $arch $full
			    else
				run_pin $full
			    fi

			    name=$(basename $file)
			    run_veri $arch $name
			    dst=$(dirname $file)
			    mkdir -p "$results/$dst"
			    mv $veri_out "$results/$dst"
			    mv $name.frames "$results/$dst"		     
		    esac

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
