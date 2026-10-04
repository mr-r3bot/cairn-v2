#!/bin/sh
# Run the Cairn test suite inside a container (host stays clean).
# Usage: ./test-in-docker.sh [pytest args...]
# Integration tests additionally need: -e CAIRN_SANDBOX_INTEGRATION=1 and the
# rootless docker socket mounted (see the docker run invocation this script builds).
set -e
ROOT="$(cd "$(dirname "$0")" && pwd)"
EXTRA_ARGS=""

# docker-integration tests: enable via env, plus socket + shared scratch path
if [ "${CAIRN_SANDBOX_INTEGRATION:-0}" = "1" ]; then
  SOCK="${DOCKER_HOST#unix://}"
  [ -S "$SOCK" ] || { echo "no docker socket at $SOCK"; exit 1; }
  IT_ROOT="${CAIRN_IT_ROOT:-/tmp/cairn-it}"
  mkdir -p "$IT_ROOT"
  EXTRA_ARGS="-e DOCKER_HOST=unix://$SOCK -v $SOCK:$SOCK -v $IT_ROOT:$IT_ROOT -e CAIRN_IT_ROOT=$IT_ROOT -e CAIRN_SANDBOX_INTEGRATION=1"
fi

eval docker run --rm \
  -v "$ROOT":/src -w /src \
  -e UV_PROJECT_ENVIRONMENT=/tmp/venv \
  -e UV_INDEX_URL="${UV_INDEX_URL:-https://mirrors.aliyun.com/pypi/simple/}" \
  $EXTRA_ARGS \
  ghcr.io/astral-sh/uv:python3.13-trixie \
  uv run --project cairn --group dev pytest "$@"
