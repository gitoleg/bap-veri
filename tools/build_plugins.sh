#!/bin/sh

set -ue

cd $1

build_plugin() {
    plugin=veri_plugin_$1
    if ocamlfind query veri-plugin-$1 2>/dev/null
    then
        TMPDIR=`mktemp -d`
        cd $TMPDIR
        touch $plugin.ml
        bapbuild -package veri-plugin-$1 $plugin.plugin
        DESC=`ocamlfind query -format "%D" veri-plugin-$1`
        CONS=`ocamlfind query -format "%(constraints)" veri-plugin-$1`
        TAGS=`ocamlfind query -format "%(tags)" veri-plugin-$1`
        if [ ! -z "$CONS" ]; then
            bapbundle update -cons "$CONS" $plugin.plugin
        fi
        if [ ! -z "$TAGS" ]; then
            bapbundle update -tags "$TAGS" $plugin.plugin
        fi
        bapbundle update -desc "$DESC" $plugin.plugin
        bapbundle update -name $1 $plugin.plugin

        mv $plugin.plugin $1.plugin
        bapbundle install $1.plugin
        cd -
        rm -rf $TMPDIR
    fi

}

for plugin in `ls`; do
    build_plugin $plugin &
done

cd ..
wait
