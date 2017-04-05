#!/bin/sh

set -ue

cd $1

dst=`opam config var lib`/$2

for plugin in `ls`; do
    if ocamlfind query veri-plugin-$plugin 2>/dev/null
    then
        plugin_name=veri_$plugin
        touch $plugin_name.ml
        bapbuild -package veri-plugin-$plugin $plugin_name.plugin
        bapbundle update -desc "`ocamlfind query -format "%D" veri-plugin-$plugin`" $plugin_name.plugin
        if [ -f $plugin/resources ]; then
            cd $plugin
            for line in `cat resources`; do
                bapbundle update -add-resources $line ../$plugin_name.plugin
            done
            cd ..
        fi
        echo "bapbundle install $plugin_name.plugin"
        bapbundle install -destdir $dst $plugin_name.plugin
        bapbuild -clean
        rm $plugin_name.ml
    fi
done

cd ..
