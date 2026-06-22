#!/usr/bin/env bash
# Create the sybsec Kafka topics (idempotent). Safe to re-run.
#
#   ./kafka/topics.sh                 # uses defaults / .env
#   KAFKA_CONTAINER=sybsec-kafka ./kafka/topics.sh
#
# In dev (single broker) replication factor is 1. In production set
# REPLICATION=3 and PARTITIONS to match broker count.
set -euo pipefail

KAFKA_CONTAINER="${KAFKA_CONTAINER:-sybsec-kafka}"
BOOTSTRAP="${KAFKA_BOOTSTRAP:-localhost:9092}"
REPLICATION="${REPLICATION:-1}"
PARTITIONS="${PARTITIONS:-6}"
RETENTION_MS="${RETENTION_MS:-604800000}"   # 7 days

# topic:partitions  (override partitions per topic as needed)
TOPICS=(
  "zeek-logs:${PARTITIONS}"
  "suricata-alerts:${PARTITIONS}"
  "wazuh-events:${PARTITIONS}"
  "sysmon-events:${PARTITIONS}"
  "security-anomalies:3"
  "soar-actions:3"
)

run() {
  if command -v kafka-topics >/dev/null 2>&1; then
    kafka-topics --bootstrap-server "${BOOTSTRAP}" "$@"
  else
    docker exec -i "${KAFKA_CONTAINER}" kafka-topics --bootstrap-server localhost:9092 "$@"
  fi
}

echo "Creating Kafka topics on ${KAFKA_CONTAINER} (rf=${REPLICATION})..."
for entry in "${TOPICS[@]}"; do
  name="${entry%%:*}"
  parts="${entry##*:}"
  if run --list | grep -qx "${name}"; then
    echo "  = ${name} (exists)"
  else
    run --create --topic "${name}" \
        --partitions "${parts}" \
        --replication-factor "${REPLICATION}" \
        --config "retention.ms=${RETENTION_MS}" \
        --config "compression.type=lz4"
    echo "  + ${name} (${parts} partitions)"
  fi
done

echo "Topics now present:"
run --list
