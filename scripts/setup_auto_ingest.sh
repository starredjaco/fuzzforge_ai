#!/usr/bin/env bash
# Stand up the Cognee/Ladybug ingestion pipeline (MinIO + RabbitMQ + dispatcher)
# and optionally push a sample file through the MinIO bucket to prove the
# RabbitMQ → dispatcher → Cognee path is healthy.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

PROJECT_ID="${PROJECT_ID:-demo123}"
VERIFY=0

usage() {
  cat <<'USAGE'
Usage: scripts/setup_auto_ingest.sh [--verify] [--project <id>]

  --verify         Upload a sample file into MinIO after services start.
  --project <id>   Project ID for the verification upload (default: demo123).

Environment overrides:
  PROJECT_ID       Same as --project.
  AWS_ENDPOINT     Override the MinIO endpoint (default http://minio:9000 inside Docker network).
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --verify)
      VERIFY=1
      shift
      ;;
    --project)
      PROJECT_ID="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage
      exit 1
      ;;
  esac
done

AWS_ENDPOINT="${AWS_ENDPOINT:-http://minio:9000}"

require_file() {
  if [[ ! -f "$1" ]]; then
    echo "Missing $1. Copy volumes/env/.env.template to volumes/env/.env first." >&2
    exit 1
  fi
}

run() {
  echo "[$(date +%H:%M:%S)] $*"
  "$@"
}

require_file "volumes/env/.env"

echo "Bootstrapping auto-ingestion stack from $ROOT_DIR"
run docker compose up -d
run docker compose -f docker/docker-compose.cognee.yml up -d

# Ensure MinIO buckets, lifecycle policies, and AMQP events are in place.
run docker compose up minio-setup

# Make sure the dispatcher is online (restarts to pick up env/file changes).
run docker compose up -d ingestion-dispatcher

echo "Current ingestion dispatcher status:"
docker compose ps ingestion-dispatcher

if [[ "$VERIFY" -eq 1 ]]; then
  TMP_FILE="$(mktemp)"
  SAMPLE_KEY="files/ingest_smoketest_$(date +%s).txt"
  cat <<EOF >"$TMP_FILE"
Automatic ingestion smoke test at $(date)
Project: $PROJECT_ID
EOF

  echo "Uploading $SAMPLE_KEY into s3://projects/$PROJECT_ID via aws-cli container..."
  run docker run --rm --network fuzzforge_temporal_network \
    -e AWS_ACCESS_KEY_ID=fuzzforge \
    -e AWS_SECRET_ACCESS_KEY=fuzzforge123 \
    -e AWS_DEFAULT_REGION=us-east-1 \
    -v "$TMP_FILE:/tmp/sample.txt:ro" \
    amazon/aws-cli s3 cp /tmp/sample.txt "s3://projects/${PROJECT_ID}/${SAMPLE_KEY}" \
    --endpoint-url "$AWS_ENDPOINT"

  rm -f "$TMP_FILE"
  cat <<EOF

Sample file enqueued. Watch the dispatcher logs with:
  docker logs -f fuzzforge-ingestion-dispatcher

Datasets will appear via:
  curl -s -X POST http://localhost:18000/api/v1/auth/login \\
    -d "username=project_${PROJECT_ID}@fuzzforge.dev&password=\$(python3 - <<'PY'
from hashlib import sha256
print(sha256(b"$PROJECT_ID").hexdigest()[:20])
PY
)" | python3 -c 'import sys,json; print(json.load(sys.stdin)["access_token"])'
EOF
fi

echo "Auto-ingestion stack ready."
