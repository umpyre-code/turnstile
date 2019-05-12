FROM rustlang/rust:nightly

ARG SSH_KEY
ARG SCCACHE_KEY

# add sccache
ENV SCCACHE_VERSION=0.2.8
ADD https://github.com/mozilla/sccache/releases/download/${SCCACHE_VERSION}/sccache-${SCCACHE_VERSION}-x86_64-unknown-linux-musl.tar.gz /tmp
RUN cd /tmp \
  && tar xf sccache-${SCCACHE_VERSION}-x86_64-unknown-linux-musl.tar.gz \
  && mv sccache-${SCCACHE_VERSION}-x86_64-unknown-linux-musl/sccache /usr/bin/sccache \
  && rm -rf /tmp/sccache-*
ENV SCCACHE_GCS_BUCKET=umpyre-sccache
ENV SCCACHE_GCS_RW_MODE=READ_WRITE
ENV SCCACHE_GCS_KEY_PATH=/root/sccache.json
ENV RUSTC_WRAPPER=sccache

ADD https://github.com/a8m/envsubst/releases/download/v1.1.0/envsubst-Linux-x86_64 /usr/bin/envsubst
RUN chmod +x /usr/bin/envsubst

# Install yarn & nodejs (ugh)
RUN apt-get update && apt-get install -yqq apt-transport-https apt-utils \
  && curl -sS https://dl.yarnpkg.com/debian/pubkey.gpg | apt-key add - \
  && echo "deb https://dl.yarnpkg.com/debian/ stable main" | tee /etc/apt/sources.list.d/yarn.list \
  && apt-get update && apt-get install -yqq yarn \
  && apt-get clean && rm -rf /var/lib/apt/lists

WORKDIR /app

COPY . /app/src
COPY entrypoint.sh /app

RUN mkdir -p $HOME/.ssh \
  && chmod 0700 $HOME/.ssh \
  && ssh-keyscan github.com > $HOME/.ssh/known_hosts \
  && echo "$SSH_KEY" > $HOME/.ssh/id_rsa \
  && echo "$SCCACHE_KEY" | base64 -d > $SCCACHE_GCS_KEY_PATH \
  && chmod 600 $HOME/.ssh/id_rsa \
  && eval `ssh-agent` \
  && ssh-add -k $HOME/.ssh/id_rsa \
  && cd src \
  && cargo install --path . \
  && cd .. \
  && rm -rf /usr/bin/sccache \
  && rm -rf src \
  && rm -rf $HOME/.cargo/registry \
  && rm -rf $HOME/.cargo/git

# Remove keys
RUN rm -rf /root/.ssh/ && rm $SCCACHE_GCS_KEY_PATH

ENV RUST_LOG=turnstile=info

ENTRYPOINT [ "/app/entrypoint.sh" ]
