#!/bin/sh

set -ue

cd $1

tags=$2

for plugin in `ls .`; do
    if ocamlfind query veri-plugin-$plugin 2>/dev/null
    then
        touch $plugin.ml
        bapbuild -package veri-plugin-$plugin $plugin.plugin
        desc=`ocamlfind query -format "%D" veri-plugin-$plugin`
        if [ -z "$tags" ]; then
            bapbundle update -desc "$desc" $plugin.plugin
        else
            bapbundle update -desc "$desc" -tags $tags $plugin.plugin
        fi
        if [ -f $plugin/resources ]; then
            cd $plugin
            for line in `cat resources`; do
                bapbundle update -add-resources $line ../$plugin.plugin
            done
            cd ..
        fi
        echo "bapbundle install $plugin.plugin"
        bapbundle install $plugin.plugin
        bapbuild -clean
        rm $plugin.ml
    fi
done

cd ..
