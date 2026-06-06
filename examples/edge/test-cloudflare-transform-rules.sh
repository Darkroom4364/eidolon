#!/bin/sh
set -eu

cd "$(dirname "$0")/../.."
node --test examples/edge/cloudflare/test-eidolon-request-header-transform-rules.mjs
