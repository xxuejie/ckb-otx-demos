#!/usr/bin/env bash
set -ex

cd dex-contracts
make build
cd ..
cd offchain-modules
cargo build --release
cd ..
