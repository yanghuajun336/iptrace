# SC-007 Long-run Report

- Date: 2026-03-26T20:42:35+08:00
- DurationSeconds(target/actual): 600/5
- CPU Max Percent(sampled): 0
- Memory Growth KB: 164
- Status: WARN
- Notes: 未达到目标时长（可能由测试模式或会话提前结束导致），请在真实环境复测 600s
- TraceOutput: test/integration/sc007-trace-output.log

## Command

`USE_TEST_MODE=0 iptrace trace --src 1.2.3.4 --proto tcp --dport 80 --timeout 600s`
