#!/bin/bash
# entrypoint.sh — wrapper for technocore-verify inside the Docker container.
# All arguments passed to this script are forwarded to verify.py.
#
# Examples:
#   docker run --rm technocore-verify --version
#   docker run --rm technocore-verify --single --did ... --room ... --nonce ... --text-file /payload/message.txt
#   docker run --rm -v /path/to/room.json:/room.json technocore-verify --from-json /room.json

set -euo pipefail
exec python3 verify.py "$@"
