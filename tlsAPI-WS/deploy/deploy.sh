#!/bin/sh

# copy binaries
cp -P lib/*.so "$VWOS_LIBS"

mkdir -p "$VWOS_DATA_STATIC"/tls
cp -P aux/*.tsv "$VWOS_DATA_STATIC"/tls