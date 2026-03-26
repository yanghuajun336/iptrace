# TDD 可追溯矩阵（Feature: 001-packet-trace）

## 1. 说明

本矩阵用于验证“测试任务先于实现任务”并建立任务—测试—实现的可追溯关系。

## 2. US1（离线推演）

| 任务 | 类型 | 对应文件 |
|------|------|---------|
| T015 | 合约测试 | `test/contract/check_contract_test.go` |
| T016 | 单元测试 | `internal/parser/iptables_parser_test.go` |
| T017 | 单元测试 | `internal/matcher/simulate_test.go` |
| T018 | 集成测试 | `test/integration/offline_check_test.go` |
| T019/T020/T021/T022/T023 | 实现 | `internal/parser/iptables_parser.go` / `internal/matcher/simulate.go` / `cmd/iptrace/check.go` / `test/fixtures/rules/*` / `internal/output/hints.go` |

结论：US1 测试任务先于实现任务。

## 3. US2（在线追踪）

| 任务 | 类型 | 对应文件 |
|------|------|---------|
| T024 | 合约测试 | `test/contract/trace_contract_test.go` |
| T025 | 单元测试 | `internal/tracer/nflog_decode_test.go` |
| T026 | 单元测试 | `internal/tracer/session_test.go` |
| T027 | 集成测试 | `test/integration/online_trace_test.go` |
| T028/T029/T030/T031/T032 | 实现 | `internal/tracer/session.go` / `internal/tracer/nflog_decode.go` / `internal/tracer/xt_trace.go` / `cmd/iptrace/trace.go` / `internal/output/stream.go` |

结论：US2 测试任务先于实现任务。

## 4. US3（导出与报告）

| 任务 | 类型 | 对应文件 |
|------|------|---------|
| T033 | 合约测试 | `test/contract/export_contract_test.go` |
| T034 | 单元测试 | `internal/exporter/export_test.go` |
| T035 | 集成测试 | `test/integration/export_then_check_test.go` |
| T036/T037/T038/T039 | 实现 | `internal/exporter/export.go` / `cmd/iptrace/export.go` / `internal/output/export_summary.go` / `test/fixtures/firewalld/zones.txt` |

结论：US3 测试任务先于实现任务。

## 5. Cross-Cutting（Polish）

| 任务 | 类型 | 对应文件 |
|------|------|---------|
| T040 | 性能测试 | `test/integration/perf_budget_test.go` |
| T041 | 一致性实现 | `cmd/iptrace/main.go` / `internal/output/errors.go` |
| T042 | 重构 | `internal/matcher/simulate.go` 等 |
| T043 | 冒烟验证 | `specs/001-packet-trace/quickstart.md` |
| T044 | 全量回归 | `test/integration/test-report.txt` |

## 6. 验证结论

- `tasks.md` 在收敛边界前任务均已完成；
- 合约测试、单元测试、集成测试与实现文件存在明确映射；
- 满足宪章中的 Test-First 标准。
