#!/bin/sh

set -ue

cd plugins

dst=`opam config var lib`/bap

for plugin in `ls .`; do
    rm -f $dst/$plugin.plugin
done

cd ..
