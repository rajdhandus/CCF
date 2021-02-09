#!/bin/sh
set -ex

npm install
npm run build

../../../tests/sandbox/sandbox.sh \
    --js-app-bundle ./dist \
    --workspace ./workspace \
    --binary-dir ../../../build \
    --verbose \
    "$@"
