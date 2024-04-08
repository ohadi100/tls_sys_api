#!/bin/bash

# script for building linux rte for testing sok functionalities and flows
# can be executed from anywhere

MID_TLS_REPO_BASE_DIR=$( dirname $(cd "$(dirname "$0")" && pwd ) )
MID_TLS_REPO_RTE_DIR=$MID_TLS_REPO_BASE_DIR/rte
RTE_IMAGE_FOLDER=$MID_TLS_REPO_RTE_DIR/build/images

# clenup previous image
if [ -d "$RTE_IMAGE_FOLDER" ]; then rm -Rf $RTE_IMAGE_FOLDER; fi

if ! conan lock create $MID_TLS_REPO_RTE_DIR/mid_tls_rte.conanfile.py -pr linux-host --lockfile-out $MID_TLS_REPO_RTE_DIR/mid_tls_rte.linux.custum.lock; then
    echo failed creating lock file for RTE
    exit 0
fi

if ! conan install --update $MID_TLS_REPO_RTE_DIR/mid_tls_rte.conanfile.py --lockfile $MID_TLS_REPO_RTE_DIR/mid_tls_rte.linux.custum.lock -if $MID_TLS_REPO_RTE_DIR/build; then
    echo failed installing RTE
    exit 0
fi

if ! conan build $MID_TLS_REPO_RTE_DIR/mid_tls_rte.conanfile.py -bf $MID_TLS_REPO_RTE_DIR/build; then
    echo failed building RTE
    exit 0
fi

echo Built RTE successfully

exit 1