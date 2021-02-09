#!/bin/sh
set -e
curl --cacert workspace/sandbox_common/networkcert.pem "$@"
