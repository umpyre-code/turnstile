FROM gcr.io/umpyre/github.com/umpyre-code/rust:latest

ARG SSH_KEY
ARG SCCACHE_KEY

WORKDIR /app

COPY target/release/turnstile /usr/bin
COPY entrypoint.sh /app

ENV RUST_LOG=turnstile=info

ENTRYPOINT [ "/app/entrypoint.sh" ]
