#!/usr/bin/env bash
set -euo pipefail

PROGRAM_NAME=${1:-validator_lock}
CLUSTER=${2:-devnet}

export ANCHOR_WALLET=/root/.config/solana/id.json

solana config set --url https://api.${CLUSTER}.solana.com >/dev/null
anchor --version

mkdir -p target/deploy
if [ ! -f target/deploy/${PROGRAM_NAME}-keypair.json ]; then
  solana-keygen new --no-passphrase -f -o target/deploy/${PROGRAM_NAME}-keypair.json >/dev/null
fi

PUB=$(solana-keygen pubkey target/deploy/${PROGRAM_NAME}-keypair.json)
sed -i -E "s#declare_id\!(\"[A-Za-z0-9]+\"\);#declare_id!(\"$PUB\");#" programs/${PROGRAM_NAME}/src/lib.rs

anchor clean
anchor build --no-idl
anchor deploy --provider.cluster ${CLUSTER} --program-name ${PROGRAM_NAME} --program-keypair target/deploy/${PROGRAM_NAME}-keypair.json

anchor keys list


