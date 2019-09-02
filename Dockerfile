FROM gcr.io/umpyre/github.com/umpyre-code/rust:latest

# Install libcairo for SVG rendering
RUN apt-get update -qq \
    && apt-get install -yqq libcairo2 fonts-lato \
    && apt-get clean && rm -rf /var/lib/apt/lists

ARG SSH_KEY
ARG SCCACHE_KEY

WORKDIR /app

ADD out/* /usr/bin/
ADD entrypoint.sh /app

ENV RUST_LOG=turnstile=info
ENV RUST_BACKTRACE=full

ENTRYPOINT [ "/app/entrypoint.sh" ]
