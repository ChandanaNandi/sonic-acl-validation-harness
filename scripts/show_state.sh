#!/usr/bin/env bash
set -euo pipefail

CONTAINER_NAME="${CONTAINER_NAME:-sonic-vs-acl}"

echo "CONFIG_DB ACL_TABLE"
docker exec "$CONTAINER_NAME" sonic-db-cli CONFIG_DB HGETALL "ACL_TABLE|DATAACL" || true

echo
echo "CONFIG_DB ACL_RULE"
docker exec "$CONTAINER_NAME" sonic-db-cli CONFIG_DB HGETALL "ACL_RULE|DATAACL|drop_https" || true

echo
echo "APP_DB keys matching DATAACL"
docker exec "$CONTAINER_NAME" sonic-db-cli APPL_DB KEYS "*DATAACL*" || true

echo
echo "ASIC_DB ACL object keys"
docker exec "$CONTAINER_NAME" sonic-db-cli ASIC_DB KEYS "ASIC_STATE:SAI_OBJECT_TYPE_ACL*" || true

