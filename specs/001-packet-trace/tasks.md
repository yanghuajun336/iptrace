# Tasks: iptrace — iptables/firewalld 报文调试工具

**Input**: 设计文档来自 `/specs/001-packet-trace/`
**Prerequisites**: plan.md（必需）, spec.md（必需）, research.md, data-model.md, contracts/, quickstart.md

**Tests**: 所有实现任务必须先有失败测试任务（Red），再实现（Green），最后重构（Refactor）。

**Organization**: 按用户故事分组，确保每个故事可独立实现与独立验收。

## Phase 1: Setup（共享基础搭建）

**Purpose**: 初始化 Go CLI 项目结构与最小依赖环境

- [x] T001 [P] [Skill: speckit-tech-lead] 创建目录骨架 `cmd/iptrace/`, `internal/{backend,parser,matcher,tracer,exporter,output}/`, `pkg/model/`, `test/{contract,integration,fixtures}/`
- [x] T002 [Skill: speckit-tech-lead] 初始化模块文件 `go.mod`（Go 1.21+）并仅引入 `golang.org/x/sys`
- [x] T003 [P] [Skill: speckit-tech-lead] 创建 CLI 入口文件 `cmd/iptrace/main.go`（仅子命令路由骨架）
- [x] T004 [P] [Skill: speckit-tech-lead] 创建通用错误码与错误类型 `internal/output/errors.go`（0/1/2/3 约定）
- [x] T005 [Skill: speckit-tech-lead] 新建开发任务入口 `Makefile`（`test`, `build`, `fmt`）并对齐 `quickstart.md`

---

## Phase 2: Foundational（阻塞性前置）

**Purpose**: 所有用户故事共用的核心能力，完成前不得进入 US 实现

**⚠️ CRITICAL**: 本阶段完成前，US1/US2/US3 不可开始

- [x] T006 [P] [Skill: speckit-developer] 编写后端检测单元测试 `internal/backend/detect_test.go`（legacy/nft/firewalld/unknown）
- [x] T007 [Skill: speckit-developer] 实现后端检测 `internal/backend/detect.go`
- [x] T008 [P] [Skill: speckit-developer] 编写报文与结果模型校验测试 `pkg/model/types_test.go`
- [x] T009 [Skill: speckit-developer] 实现核心数据模型 `pkg/model/types.go`（Packet/RuleSet/TraceStep/TraceResult/Backend）
- [x] T010 [P] [Skill: speckit-developer] 编写统一输出格式测试 `internal/output/format_test.go`（human/json 字段语义一致）
- [x] T011 [Skill: speckit-developer] 实现输出渲染器 `internal/output/render.go`
- [x] T012 [P] [Skill: speckit-developer] 编写子命令参数校验测试 `cmd/iptrace/main_test.go`
- [x] T013 [Skill: speckit-developer] 实现子命令参数解析与分发 `cmd/iptrace/main.go`
- [x] T014 [Skill: speckit-architect] 复核并更新架构图一致性 `specs/001-packet-trace/{c4,uml}/`（若结构变动则同步）

**Checkpoint**: 基础能力可复用，用户故事可并行推进

---

## Phase 3: User Story 1 - 单报文规则路径定位（离线推演）(Priority: P1) 🎯 MVP

**Goal**: 用户基于规则快照文件获得单报文命中规则与最终判决

**Independent Test**: 使用 `test/fixtures/rules/drop_8080.rules` 与固定五元组执行 `iptrace check`，应稳定返回 DROP 命中规则

### Tests for User Story 1（必须先写且先失败）

- [x] T015 [P] [US1] [Skill: speckit-developer] 编写 CLI 合约测试 `test/contract/check_contract_test.go`（参数、输出字段、退出码）
- [x] T016 [P] [US1] [Skill: speckit-developer] 编写解析器单元测试 `internal/parser/iptables_parser_test.go`（表/链/规则/默认策略）
- [x] T017 [P] [US1] [Skill: speckit-developer] 编写推演引擎单元测试 `internal/matcher/simulate_test.go`（JUMP/RETURN/默认策略）
- [x] T018 [US1] [Skill: speckit-developer] 编写离线集成测试 `test/integration/offline_check_test.go`（端到端 check）

### Implementation for User Story 1

- [x] T019 [US1] [Skill: speckit-developer] 实现规则解析器 `internal/parser/iptables_parser.go`
- [x] T020 [US1] [Skill: speckit-developer] 实现离线推演核心 `internal/matcher/simulate.go`
- [x] T021 [US1] [Skill: speckit-developer] 实现 `check` 子命令执行器 `cmd/iptrace/check.go`
- [x] T022 [US1] [Skill: speckit-developer] 增加离线示例规则夹具 `test/fixtures/rules/{drop_8080.rules,default_accept.rules,return_jump.rules}`
- [x] T023 [US1] [Skill: speckit-developer] 实现错误输出与修复建议映射 `internal/output/hints.go`

**Checkpoint**: US1 可独立交付（MVP）

---

## Phase 4: User Story 2 - 实时报文追踪（在线模式）(Priority: P2)

**Goal**: 用户实时观察报文在 Netfilter 各钩子点的命中路径

**Independent Test**: 在模拟 NFLOG 事件输入下执行 `iptrace trace`，输出流应包含连续 TraceStep 且首条输出时间满足预算

### Tests for User Story 2（必须先写且先失败）

- [x] T024 [P] [US2] [Skill: speckit-developer] 编写 CLI 合约测试 `test/contract/trace_contract_test.go`（权限/参数/输出/退出码）
- [x] T025 [P] [US2] [Skill: speckit-developer] 编写 netlink 解码单元测试 `internal/tracer/nflog_decode_test.go`
- [x] T026 [P] [US2] [Skill: speckit-developer] 编写追踪生命周期测试 `internal/tracer/session_test.go`（注入/清理/中断）
- [x] T027 [US2] [Skill: speckit-developer] 编写在线集成测试 `test/integration/online_trace_test.go`（模拟事件流）

### Implementation for User Story 2

- [x] T028 [US2] [Skill: speckit-developer] 实现追踪会话与 netlink 监听 `internal/tracer/session.go`
- [x] T029 [US2] [Skill: speckit-developer] 实现 NFLOG 消息解码 `internal/tracer/nflog_decode.go`
- [x] T030 [US2] [Skill: speckit-developer] 实现 trace 规则注入/清理 `internal/tracer/xt_trace.go`
- [x] T031 [US2] [Skill: speckit-developer] 实现 `trace` 子命令执行器 `cmd/iptrace/trace.go`
- [x] T032 [US2] [Skill: speckit-developer] 实现实时流式输出（human/ndjson）`internal/output/stream.go`

**Checkpoint**: US2 可独立运行，且不影响 US1

---

## Phase 5: User Story 3 - 规则快照导出与诊断报告 (Priority: P3)

**Goal**: 用户可导出当前规则快照并生成结构化诊断摘要

**Independent Test**: 执行 `iptrace export --output ...` 后可被 `iptrace check --rules-file ...` 直接消费

### Tests for User Story 3（必须先写且先失败）

- [x] T033 [P] [US3] [Skill: speckit-developer] 编写 CLI 合约测试 `test/contract/export_contract_test.go`
- [x] T034 [P] [US3] [Skill: speckit-developer] 编写导出器单元测试 `internal/exporter/export_test.go`（legacy/nft/firewalld）
- [x] T035 [US3] [Skill: speckit-developer] 编写导出-推演集成测试 `test/integration/export_then_check_test.go`

### Implementation for User Story 3

- [x] T036 [US3] [Skill: speckit-developer] 实现规则导出器 `internal/exporter/export.go`
- [x] T037 [US3] [Skill: speckit-developer] 实现 `export` 子命令执行器 `cmd/iptrace/export.go`
- [x] T038 [US3] [Skill: speckit-developer] 实现导出摘要 JSON 输出结构 `internal/output/export_summary.go`
- [x] T039 [US3] [Skill: speckit-developer] 补充 firewalld 导出夹具 `test/fixtures/firewalld/zones.txt`

**Checkpoint**: US3 独立可用，US1/US2 不回归

---

## Phase 6: Polish & Cross-Cutting Concerns（Phase N-1）

**Purpose**: 跨用户故事的质量收敛、性能与一致性强化

- [x] T040 [P] [Skill: speckit-developer] 增加性能基准测试 `test/integration/perf_budget_test.go`（SC-003/SC-006/SC-007）
- [x] T041 [Skill: speckit-developer] 统一 CLI 错误文案与帮助信息 `cmd/iptrace/main.go` + `internal/output/errors.go`
- [x] T042 [P] [Skill: speckit-developer] 重构重复逻辑并清理技术债 `internal/{parser,matcher,tracer,exporter}/`
- [x] T043 [Skill: speckit-developer] 完成 quickstart 冒烟验证 `specs/001-packet-trace/quickstart.md`（逐命令执行核对）
- [x] T044 [Skill: speckit-developer] 执行全量测试并记录结果 `go test ./...`（输出保存至 `test/integration/test-report.txt`）
- [x] T045 [Skill: speckit-developer] 补充 SC-001 可执行验收脚本与报告 `test/integration/{sc001_acceptance.sh,sc001-report.txt}`
- [x] T046 [Skill: speckit-developer] 补充 SC-007 长时性能验收脚本与报告模板 `test/integration/{sc007_longrun.sh,sc007-report.md}`
- [x] T047 [Skill: speckit-developer] 扩展离线推演引擎 `internal/matcher/simulate.go`：多表遍历（raw/mangle/nat/filter）、多链（PREROUTING/INPUT/FORWARD/OUTPUT/POSTROUTING）、自定义链 JUMP/RETURN 递归、CIDR 匹配（之前仅支持 filter/INPUT 精确 IP）

<!-- CONVERGENCE_BOUNDARY -->

## Phase 7: System Convergence（Phase N）

**Purpose**: 将 `specs/` 临时知识蒸馏到长期文档并同步系统地图

- [x] TN01 [Skill: speckit-librarian] 创建 ADR `docs/adr/0001-trace-mechanism.md`（基于 `research.md` 的追踪机制决策）
- [x] TN02 [Skill: speckit-librarian] 创建 ADR `docs/adr/0002-language-and-dependency-policy.md`（Go 主实现与最小依赖策略）
- [x] TN03 [Skill: speckit-librarian] 创建架构总览 `docs/architecture/iptrace-overview.md`（蒸馏 `specs/001-packet-trace/{c4,uml}/`）
- [x] TN04 [Skill: speckit-librarian] 创建 CLI 参考文档 `docs/reference/iptrace-cli.md`（蒸馏 `specs/001-packet-trace/contracts/README.md`）
- [x] TN05 [Skill: speckit-librarian] 创建性能基线文档 `docs/performance/iptrace-baseline.md`
- [x] TN06 [Skill: speckit-librarian] 更新系统地图 `.specify/memory/system-map.md`（新增永久文档条目，更新时间戳，状态改为 ✅）
- [x] TN07 [Skill: speckit-librarian] 扫描并清理系统地图中所有 `specs/` 引用（若存在先蒸馏再替换）
- [x] TN08 [Skill: speckit-librarian] 验证任务与测试一一对应并记录于 `docs/quality/tdd-traceability.md`
- [x] TN09 [Skill: speckit-librarian] 更新 CLI 参考文档 `docs/reference/iptrace-cli.md`：`trace` 新增 `--verbose/-v` 标志、`--timeout` 默认改为 `0`（无超时）；`check` 删除 `--sport` 参数
- [x] TN10 [Skill: speckit-librarian] 更新 `docs/quality/tdd-traceability.md`：新增 T048~T052 UX 改进任务的测试—实现映射（去 sport、timeout=0、verbose 输出、TraceID 分组）
- [x] TN11 [Skill: speckit-librarian] 更新 `specs/001-packet-trace/spec.md`：修订 FR-001（源端口非必须）、US1/US2 验收场景示例命令去掉 `--sport`
- [x] TN12 [Skill: speckit-librarian] 更新 `README.md`：`check` 示例去 `--sport`，`trace` 增加 verbose 与无超时说明
- [x] TN13 [Skill: speckit-librarian] 同步 `.specify/memory/system-map.md`：更新 CLI 参考和 TDD Traceability 的 Last Updated 时间戳
- [x] TN14 [Skill: speckit-librarian] 更新 `docs/quality/tdd-traceability.md`：新增 T053~T055 规则文本显示与五元组解析任务的测试—实现映射
- [x] TN15 [Skill: speckit-librarian] 更新 `docs/reference/iptrace-cli.md` 与 `.specify/memory/system-map.md`：反映 verbose header 五元组显示与 brief 模式规则文本输出

---

## Dependencies & Execution Order

### Phase Dependencies

- **Phase 1（Setup）**: 可立即开始
- **Phase 2（Foundational）**: 依赖 Phase 1，阻塞所有用户故事
- **Phase 3/4/5（US1/US2/US3）**: 均依赖 Phase 2 完成
- **Phase 6（Polish）**: 依赖已交付用户故事完成
- **Phase 7（Convergence）**: 依赖 Phase 6，且由 `/speckit.converge` 执行

### User Story Dependencies

- **US1 (P1)**: 无故事依赖，MVP
- **US2 (P2)**: 可在 Phase 2 后启动；与 US1 共享输出与模型
- **US3 (P3)**: 可在 Phase 2 后启动；对 US1 形成导出→推演闭环验证

### Within Each User Story

- 先测试（Red）→ 再实现（Green）→ 再重构（Refactor）
- 解析/模型先于命令执行器
- 命令执行器先于集成验证

### Parallel Opportunities

- Phase 1 中 `T001/T003/T004` 可并行
- Phase 2 中 `T006/T008/T010/T012` 可并行
- 每个故事中的单测与合约测试可并行
- US2 与 US3 在 Phase 2 后可并行开发

---

## Parallel Example: User Story 1

- 并行任务 A: `T015`（CLI 合约测试）
- 并行任务 B: `T016`（解析器单测）
- 并行任务 C: `T017`（推演引擎单测）

随后串行：`T019` → `T020` → `T021` → `T018`

---

## Parallel Example: User Story 2

- 并行任务 A: `T024`（trace 合约测试）
- 并行任务 B: `T025`（NFLOG 解码单测）
- 并行任务 C: `T026`（会话生命周期测试）

随后串行：`T028` → `T029` → `T030` → `T031` → `T027`

---

## Parallel Example: User Story 3

- 并行任务 A: `T033`（export 合约测试）
- 并行任务 B: `T034`（导出器单测）

随后串行：`T036` → `T037` → `T038` → `T035`

---

## Implementation Strategy

### MVP First（仅 US1）

1. 完成 Phase 1 + Phase 2
2. 完成 US1（Phase 3）
3. 通过离线端到端验收后再扩展

### Incremental Delivery

1. US1：先交付离线推演核心价值
2. US2：补齐在线追踪实时能力
3. US3：完善导出与报告闭环
4. 每步均可单独演示并回归

### Parallel Team Strategy

- A：`parser + matcher` 路径（US1 主体）
- B：`tracer` 路径（US2）
- C：`exporter + output` 路径（US3）
