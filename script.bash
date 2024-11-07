#!/usr/bin/env bash
set -euxo pipefail

data=data.ignoreme
rm --force --recursive -- "$data"

db=db.ignoreme
rm --force -- "$db"
touch -- "$db"

cargo build
cargo run -- node \
    --dev \
    --dev.block-max-transactions=1 \
    --http.api all \
    --zeth.db-path="$db" \
    --datadir="$data" \
    &
node_pid=$!

acct01=0x14dC79964da2C08b23698B3D3cc7Ca32193d9955
acct02=0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65

ETH_RPC_URL=http://127.0.0.1:8551

mnemonic='test test test test test test test test test test test junk'
keystore_dir=keystore.ignoreme

rm --force --recursive -- "$keystore_dir"

cast wallet import \
    "$acct01" \
    --keystore-dir="$keystore_dir" \
    --mnemonic="$mnemonic" \
    --unsafe-password=''

: wait for RPC to come up
until cast balance "$acct01"; do sleep 1; done

cast balance "$acct01"
cast balance "$acct02"
cast block-number

cast send \
    --keystore="$keystore_dir/$acct01" \
    --password='' \
    --value=1ether \
    "$acct02"

cast balance "$acct01"
cast balance "$acct02"
cast block-number

kill $node_pid
