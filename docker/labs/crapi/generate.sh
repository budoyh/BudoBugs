#!/bin/sh
set -eu
umask 077
if [ ! -s /keys/jwks.json ]; then
  cp /keygen/jwks.fixture.json /keys/jwks.json
fi
