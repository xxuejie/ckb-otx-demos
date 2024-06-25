#!/usr/bin/env bash
set -ex

CMD=$1

if [ "x$CMD" = "x" ]
then
  CMD="build"
  BUILD_SUFFIX="--release"
fi

cd dex-contracts
make $CMD
cd ..
cd offchain-modules
cargo $CMD $BUILD_SUFFIX
cd ..
