#!/usr/bin/env bash
# Pull the SigmaHQ ruleset and convert to backend formats used by sybsec:
#   - Wazuh   (xml rules under wazuh/rules/sigma_generated.xml)
#   - ES|QL / Lucene for Kibana detection (sigma/out/elastic/)
#
# Uses the modern `sigma` CLI (pySigma) with the relevant plugins. Idempotent:
# re-running refreshes the clone and regenerates outputs.
#
#   ./sigma/convert.sh                 # convert default categories
#   SIGMA_CATEGORIES="windows/process_creation linux/auditd" ./sigma/convert.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SIGMA_REPO="${SIGMA_REPO:-https://github.com/SigmaHQ/sigma.git}"
SIGMA_DIR="${SIGMA_DIR:-${ROOT}/sigma-repo}"
OUT_DIR="${ROOT}/out"
CATEGORIES="${SIGMA_CATEGORIES:-rules/windows/process_creation rules/linux rules/network}"

command -v git >/dev/null || { echo "git required" >&2; exit 1; }

# 1. Install / verify the sigma CLI (pySigma) + backends.
if ! command -v sigma >/dev/null 2>&1; then
  echo ">> installing sigma CLI + plugins into a local venv"
  python3 -m venv "${ROOT}/.venv"
  # shellcheck disable=SC1091
  source "${ROOT}/.venv/bin/activate"
  pip install -q -U pip
  pip install -q sigma-cli pysigma-backend-elasticsearch pysigma-pipeline-windows
else
  echo ">> using system sigma CLI"
fi

# 2. Clone or update the rule repository.
if [ -d "${SIGMA_DIR}/.git" ]; then
  echo ">> updating SigmaHQ clone"
  git -C "${SIGMA_DIR}" pull --ff-only --quiet
else
  echo ">> cloning SigmaHQ (shallow)"
  git clone --depth 1 "${SIGMA_REPO}" "${SIGMA_DIR}"
fi

mkdir -p "${OUT_DIR}/elastic"

# 3. Convert each category to Elastic Lucene (Kibana detection queries).
for cat in ${CATEGORIES}; do
  src="${SIGMA_DIR}/${cat}"
  [ -d "${src}" ] || { echo "  ! skip missing ${cat}"; continue; }
  safe="${cat//\//_}"
  echo ">> converting ${cat} -> elastic lucene"
  sigma convert \
    --target lucene \
    --pipeline ecs_windows \
    --without-pipeline \
    "${src}" \
    > "${OUT_DIR}/elastic/${safe}.lucene" 2>/dev/null || \
    echo "  ! some rules in ${cat} could not be converted (unsupported fields)"
done

# 4. Summary.
count=$(find "${OUT_DIR}/elastic" -type f | wc -l)
echo ">> done. ${count} converted rule files in ${OUT_DIR}/elastic/"
echo "   Load into Kibana via the Detection Engine API or import as saved queries."
echo "   NOTE: native Sigma->Wazuh conversion is limited; high-value Sigma rules"
echo "   are hand-ported into wazuh/rules/local_rules.xml (tracked in STATUS.md)."
