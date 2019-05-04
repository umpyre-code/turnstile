#!/bin/sh

set -e
set -x

envsubst < /etc/config/Turnstile.toml.in > Turnstile.toml

exec turnstile "$@"
