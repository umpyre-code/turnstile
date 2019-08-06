#!/bin/sh

set -e
set -x

envsubst < /etc/config/Turnstile.toml.in > Turnstile.toml
envsubst < /etc/config/Rocket.toml.in > Rocket.toml

# Active gcloud service account
gcloud auth activate-service-account --key-file=/etc/secrets/gcloud-sa.json

exec turnstile "$@"
