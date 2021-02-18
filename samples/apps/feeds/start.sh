#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -ex

npm install
npm run build

../../../tests/sandbox/sandbox.sh \
    --js-app-bundle ./dist \
    --workspace ./workspace \
    --binary-dir ../../../build \
    --verbose \
    "$@"
