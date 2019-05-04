#!/bin/sh

set -e
set -x

envsubst < /etc/config/Turnstile.toml.in > Turnstile.toml
envsubst < /etc/config/Rocket.toml.in > Rocket.toml

exec turnstile "$@"
