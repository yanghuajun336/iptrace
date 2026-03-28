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
| T045 | SC-001 验收 | `test/integration/sc001_acceptance.sh` / `test/integration/sc001-report.txt` |
| T046 | SC-007 验收 | `test/integration/sc007_longrun.sh` / `test/integration/sc007-report.md` |

## 6. 验证结论

- `tasks.md` 在收敛边界前任务均已完成；
- 合约测试、单元测试、集成测试与实现文件存在明确映射；
- 满足宪章中的 Test-First 标准。

## 7. UX 改进（后续补丁）

本节记录在主收敛周期完成后追加的 UX 改进任务（T048~T052）及其测试—实现映射。

| 任务 | 类型 | 描述 | 对应文件 |
|------|------|------|---------|
| T048 | 实现 | `check` 删除 `--sport` 必填参数；`SrcPort=0` 视为任意源端口 | `cmd/iptrace/check.go` / `internal/matcher/simulate.go` |
| T049 | 实现 | `trace --timeout` 默认改为 `0`（永不超时，Ctrl+C 停止） | `cmd/iptrace/trace.go` |
| T050 | 实现 | `trace` 新增 `--verbose`/`-v` 详细输出模式；默认简洁模式每报文一行 | `cmd/iptrace/trace.go` / `internal/output/stream.go` |
| T051 | 实现 | `TraceStep` 新增 `TraceID uint32` 字段；`nfttrace.go` 解析 per-packet ID 用于报文分组 | `pkg/model/types.go` / `internal/tracer/nfttrace.go` |
| T052 | 单元测试 | `pkg/model/types_test.go` 新增 "可不指定源端口" 测试用例；4 个集成/合约测试文件同步去除 `--sport` 与 PREROUTING 断言 | `pkg/model/types_test.go` / `test/contract/check_contract_test.go` / `test/contract/trace_contract_test.go` / `test/integration/offline_check_test.go` / `test/integration/export_then_check_test.go` / `test/integration/online_trace_test.go` |
| T053 | 实现 | 新建 `internal/tracer/rulecache.go`：启动时执行 `nft --handle list ruleset`，按 `table/chain/handle` 建索引，供 verbose 模式查找规则原文 | `internal/tracer/rulecache.go` / `cmd/iptrace/trace.go` |
| T054 | 实现 | `nfttrace.go` 解析 `NFTA_TRACE_NETWORK_HEADER`（IPv4 头）与 `NFTA_TRACE_TRANSPORT_HEADER`（TCP/UDP 头），填充 `TraceStep.PktSrcIP/DstIP/Proto/SrcPort/DstPort` | `internal/tracer/nfttrace.go` / `pkg/model/types.go` |
| T055 | 实现 | `stream.go` 更新：`RenderBriefPacket` 在 DROP/REJECT 行后追加 `└─ <rule>` 规则原文；`RenderVerbosePacket` header 行显示五元组 `src:port → dst:port proto` | `internal/output/stream.go` |
| T056 | 单元测试 | `internal/tracer/rulecache_test.go`：验证 `BuildRuleCache` 正确解析 nft 输出建立 handle 索引；nft 不可用时返回空 cache（graceful degradation） | `internal/tracer/rulecache_test.go` |
| T057 | 单元测试 | `internal/tracer/nfttrace_test.go`：验证 `nftParsePacketHeaders` 从模拟 IP/TCP/UDP header bytes 正确提取五元组 | `internal/tracer/nfttrace_test.go` |

**验证状态**: `go test ./...` 全 10 包通过（含上述变更）。
