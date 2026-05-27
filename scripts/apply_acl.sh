#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
python3 -m acl.acl_harness apply --rule drop_https

