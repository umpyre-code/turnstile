FROM gcr.io/umpyre/github.com/umpyre-code/rust:latest

ARG SSH_KEY
ARG SCCACHE_KEY

WORKDIR /app

COPY . /app/src
COPY entrypoint.sh /app

RUN sccache -s \
  && mkdir -p $HOME/.ssh \
  && chmod 0700 $HOME/.ssh \
  && ssh-keyscan github.com > $HOME/.ssh/known_hosts \
  && echo "$SSH_KEY" > $HOME/.ssh/id_rsa \
  && echo "$SCCACHE_KEY" > $SCCACHE_GCS_KEY_PATH \
  && chmod 600 $HOME/.ssh/id_rsa \
  && eval `ssh-agent` \
  && ssh-add -k $HOME/.ssh/id_rsa \
  && cd src \
  && yarn install \
  && cargo install --path . \
  && cd .. \
  && sccache -s \
  && rm -rf /usr/bin/sccache \
  && rm -rf src \
  && rm -rf $CARGO_HOME/registry $CARGO_HOME/git

# Remove keys
RUN rm -rf /root/.ssh/ \
  && rm $SCCACHE_GCS_KEY_PATH

ENV RUST_LOG=turnstile=info

ENTRYPOINT [ "/app/entrypoint.sh" ]
