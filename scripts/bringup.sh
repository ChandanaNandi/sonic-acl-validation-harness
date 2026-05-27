#!/usr/bin/env bash
set -euo pipefail

CONTAINER_NAME="${CONTAINER_NAME:-sonic-vs-acl}"
IMAGE="${IMAGE:-docker-sonic-vs-fixed:latest}"

if docker inspect "$CONTAINER_NAME" >/dev/null 2>&1; then
  if [ "$(docker inspect -f '{{.State.Running}}' "$CONTAINER_NAME")" = "true" ]; then
    echo "container: already running ($CONTAINER_NAME)"
    exit 0
  fi
  docker start "$CONTAINER_NAME"
  echo "container: started ($CONTAINER_NAME)"
  exit 0
fi

docker run -d --name "$CONTAINER_NAME" --privileged "$IMAGE"
echo "container: created ($CONTAINER_NAME)"
