#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
REPORT_FILE="${ROOT_DIR}/test/integration/sc001-report.txt"
BIN_FILE="${ROOT_DIR}/bin/iptrace"

mkdir -p "${ROOT_DIR}/bin"

if [[ ! -x "${BIN_FILE}" ]]; then
  go build -o "${BIN_FILE}" "${ROOT_DIR}/cmd/iptrace"
fi

start_ts="$(date +%s)"
output="$(${BIN_FILE} check \
  --src 1.2.3.4 \
  --dst 10.0.0.1 \
  --proto tcp \
  --sport 12345 \
  --dport 8080 \
  --rules-file "${ROOT_DIR}/test/fixtures/rules/drop_8080.rules")"
end_ts="$(date +%s)"

elapsed="$((end_ts - start_ts))"
status="PASS"
reason=""

if [[ "${output}" != *"Verdict: DROP"* ]]; then
  status="FAIL"
  reason="输出未包含 Verdict: DROP"
fi

if (( elapsed > 120 )); then
  status="FAIL"
  reason="离线推演耗时超过 120 秒"
fi

cat > "${REPORT_FILE}" <<EOF
SC-001 Acceptance Report
Date: $(date -Iseconds)
Command: iptrace check --src 1.2.3.4 --dst 10.0.0.1 --proto tcp --sport 12345 --dport 8080 --rules-file test/fixtures/rules/drop_8080.rules
ElapsedSeconds: ${elapsed}
Status: ${status}
Reason: ${reason}

Output:
${output}
EOF

if [[ "${status}" != "PASS" ]]; then
  echo "SC-001 验收失败，详见 ${REPORT_FILE}" >&2
  exit 1
fi

echo "SC-001 验收通过，报告已写入 ${REPORT_FILE}"
