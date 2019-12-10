#!/bin/sh

set -ue

plugin=bap_plugin_veri
TMPDIR=`mktemp -d`
cd $TMPDIR
touch $plugin.ml
bapbuild -package bap-plugin-veri $plugin.plugin
DESC="verifies bap lifters"
bapbundle update -name veri -desc "$DESC" -tags "verification" $plugin.plugin
mv $plugin.plugin veri.plugin
bapbundle install veri.plugin
cd -
rm -rf $TMPDIR
