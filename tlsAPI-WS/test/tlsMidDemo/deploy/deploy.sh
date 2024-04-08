#!/bin/sh

if [ -d mid_demo ]; then
    pushd mid_demo
    for i in *; do
        mkdir -p "$VWOS_APPS"/"$i"

        cp -R "$i" "$VWOS_APPS"/
    done
    popd
fi