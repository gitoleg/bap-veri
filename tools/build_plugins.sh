#!/bin/sh

set -ue

cd plugins

for plugin in `ls .`; do
    if ocamlfind query veri-plugin-$plugin 2>/dev/null
    then
        echo "we are here"
        touch $plugin.ml
        bapbuild -package veri-plugin-$plugin $plugin.plugin
        DESC=`ocamlfind query -format "%D" veri-plugin-$plugin`
        bapbundle update -desc "$DESC" -tags "veri" $plugin.plugin
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
