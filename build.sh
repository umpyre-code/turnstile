#!/bin/bash

set -e
set -x

export SCCACHE_VERSION=0.2.9

apt-get update
apt-get install -yqq apt-transport-https lsb-release gnupg curl ssh

pushd /tmp
curl -sL https://github.com/mozilla/sccache/releases/download/${SCCACHE_VERSION}/sccache-${SCCACHE_VERSION}-x86_64-unknown-linux-musl.tar.gz > /tmp/sccache.tar.gz
tar xf sccache.tar.gz
mv sccache-${SCCACHE_VERSION}-x86_64-unknown-linux-musl/sccache /usr/bin/sccache
rm -rf sccache-*
popd

export SCCACHE_GCS_BUCKET=umpyre-sccache
export SCCACHE_GCS_RW_MODE=READ_WRITE
export SCCACHE_GCS_KEY_PATH=/workspace/sccache.json
# export SCCACHE_DIR=/workspace/sccache
export RUSTC_WRAPPER=sccache

# Install yarn, google cloud sdk, & nodejs (ugh)
curl -sL https://deb.nodesource.com/setup_10.x | bash -
curl -sS https://packages.cloud.google.com/apt/doc/apt-key.gpg | apt-key add -
curl -sS https://dl.yarnpkg.com/debian/pubkey.gpg | apt-key add -
echo "deb https://dl.yarnpkg.com/debian/ stable main" | tee /etc/apt/sources.list.d/yarn.list
echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" | tee /etc/apt/sources.list.d/google-cloud-sdk.list
apt-get update && apt-get install -yqq --allow-unauthenticated yarn google-cloud-sdk
apt-get clean && rm -rf /var/lib/apt/lists

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
