#! /bin/bash

frames=$(find $1 -name "*.frames")
for file in $frames
do    
    res=$(./bil-verification/veri_main.native --show-stat --rules bil-verification/rules/x86 $file)
    echo "$file : $res"
done
