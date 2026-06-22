#!/usr/bin/env bash
# Wazuh active-response: terminate a malicious process by PID or image name.
# Input JSON carries the offending process under parameters.alert.data.
set -euo pipefail
LOG="/var/ossec/logs/active-responses.log"
read -r INPUT || true

PID=$(echo "${INPUT}"   | grep -oE '"pid"\s*:\s*"?[0-9]+' | grep -oE '[0-9]+' | head -1 || true)
IMAGE=$(echo "${INPUT}" | grep -oE '"process"\s*:\s*"[^"]+"' | head -1 | cut -d'"' -f4 || true)
ts="$(date '+%Y-%m-%d %H:%M:%S')"

if [ -n "${PID:-}" ] && kill -0 "${PID}" 2>/dev/null; then
  kill -9 "${PID}" && echo "${ts} kill-process: killed PID ${PID}" >> "${LOG}"
elif [ -n "${IMAGE:-}" ]; then
  pkill -9 -f "${IMAGE}" && echo "${ts} kill-process: killed by image ${IMAGE}" >> "${LOG}" \
    || echo "${ts} kill-process: no match for ${IMAGE}" >> "${LOG}"
else
  echo "${ts} kill-process: no pid/process in alert" >> "${LOG}"
fi
