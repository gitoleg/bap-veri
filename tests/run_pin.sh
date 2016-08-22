#! /bin/bash

bpt=$HOME/factory/bap-pintraces/obj-intel64/bpt.so

files=$(ls $1 | grep gcc | grep O0)
 
for file in $files
do
    echo $file
    input="$1$file"
    basename=${file##*/}
    output="$2$basename.frames"
    pin -injection child -t $bpt -o $output -- $input --help 1 > /dev/null
done

