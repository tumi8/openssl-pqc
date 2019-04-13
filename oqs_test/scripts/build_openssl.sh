#!/bin/bash

###########
# Build OpenSSL
#
# Must be run after OQS has been installed inside the OpenSSL source code directory
###########

set -exo pipefail

cd ..
case "$OSTYPE" in
    darwin*)  ./Configure no-shared darwin64-x86_64-cc ;;
    linux*)   ./Configure no-shared linux-x86_64 -lm  ;;
    *)        echo "Unknown operating system: $OSTYPE" ; exit 1 ;;
esac

make # note make -j fails on OpenSSL <= 1.0.2
