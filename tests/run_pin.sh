#! /bin/bash

bpt=$HOME/factory/bap-pintraces/obj-intel64/bpt.so

for file in $1*
do
    echo $file
    basename=${file##*/}
    output="$2$basename.frames"
    pin -injection child -t $bpt -o $output -- $file --help 1 > /dev/null
done

