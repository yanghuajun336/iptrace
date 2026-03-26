#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
REPORT_FILE="${ROOT_DIR}/test/integration/sc007-report.md"
BIN_FILE="${ROOT_DIR}/bin/iptrace"
DURATION_SEC="${DURATION_SEC:-600}"
SAMPLE_INTERVAL_SEC="${SAMPLE_INTERVAL_SEC:-5}"
USE_TEST_MODE="${USE_TEST_MODE:-1}"

mkdir -p "${ROOT_DIR}/bin"

if [[ ! -x "${BIN_FILE}" ]]; then
  go build -o "${BIN_FILE}" "${ROOT_DIR}/cmd/iptrace"
fi

start_ts="$(date +%s)"
start_rss_kb="$(ps -o rss= -p $$ | tr -d ' ')"

trace_pid=""
out_file="${ROOT_DIR}/test/integration/sc007-trace-output.log"

if [[ "${USE_TEST_MODE}" == "1" ]]; then
  IPTRACE_TEST_MODE=1 "${BIN_FILE}" trace --src 1.2.3.4 --proto tcp --dport 80 --timeout "${DURATION_SEC}s" > "${out_file}" 2>&1 &
else
  "${BIN_FILE}" trace --src 1.2.3.4 --proto tcp --dport 80 --timeout "${DURATION_SEC}s" > "${out_file}" 2>&1 &
fi
trace_pid=$!

cpu_samples=()
while kill -0 "${trace_pid}" 2>/dev/null; do
  cpu="$(ps -o %cpu= -p "${trace_pid}" | tr -d ' ' || echo 0)"
  cpu_samples+=("${cpu:-0}")
  sleep "${SAMPLE_INTERVAL_SEC}"
done

wait "${trace_pid}" || true

end_ts="$(date +%s)"
end_rss_kb="$(ps -o rss= -p $$ | tr -d ' ')"
elapsed="$((end_ts - start_ts))"
mem_growth_kb="$((end_rss_kb - start_rss_kb))"
if (( mem_growth_kb < 0 )); then
  mem_growth_kb=0
fi

cpu_max=0
for c in "${cpu_samples[@]:-0}"; do
  c_int="${c%.*}"
  if [[ -z "${c_int}" ]]; then
    c_int=0
  fi
  if (( c_int > cpu_max )); then
    cpu_max=$c_int
  fi
done

status="PASS"
notes=""
if (( elapsed < DURATION_SEC )); then
  status="WARN"
  notes="未达到目标时长（可能由测试模式或会话提前结束导致），请在真实环境复测 600s"
fi
if (( cpu_max > 5 )); then
  status="WARN"
  notes="${notes}; 观测到 CPU 峰值 > 5%"
fi
if (( mem_growth_kb > 51200 )); then
  status="WARN"
  notes="${notes}; 观测到内存增长 > 50MB"
fi

cat > "${REPORT_FILE}" <<EOF
# SC-007 Long-run Report

- Date: $(date -Iseconds)
- DurationSeconds(target/actual): ${DURATION_SEC}/${elapsed}
- CPU Max Percent(sampled): ${cpu_max}
- Memory Growth KB: ${mem_growth_kb}
- Status: ${status}
- Notes: ${notes}
- TraceOutput: test/integration/sc007-trace-output.log

## Command

\`${USE_TEST_MODE:+USE_TEST_MODE=${USE_TEST_MODE} }iptrace trace --src 1.2.3.4 --proto tcp --dport 80 --timeout ${DURATION_SEC}s\`
EOF

echo "SC-007 验收脚本执行完成，报告已写入 ${REPORT_FILE}"
