#!/bin/bash

set -e
set -x

sccache -s
mkdir -p $HOME/.ssh
chmod 0700 $HOME/.ssh
ssh-keyscan github.com > $HOME/.ssh/known_hosts
echo "$SSH_KEY" > $HOME/.ssh/id_rsa
echo "$SCCACHE_KEY" > $SCCACHE_GCS_KEY_PATH
chmod 600 $HOME/.ssh/id_rsa
eval `ssh-agent`
ssh-add -k $HOME/.ssh/id_rsa

yarn install
cargo install --path .

sccache -s
