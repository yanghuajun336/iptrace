# Implementation Plan: iptrace — iptables/firewalld 报文调试工具

**Branch**: `feat/001-packet-trace` | **Date**: 2026-03-25 | **Spec**: /specs/001-packet-trace/spec.md
**Input**: Feature specification from `/specs/001-packet-trace/spec.md`

## Skill Alignment Strategy（技能对齐策略）

| Requirement (User Story/Tech) | Matched Skill | Usage Strategy |
|-------------------------------|---------------|----------------|
| US1/US2/US3（iptables/firewalld 报文追踪） | None | 当前唯一领域技能 `release-server-developer` 不适用于该领域，按自定义实现执行 |
| 架构设计与图表产出 | speckit-architect | 已按技能要求产出 C4 + 序列图 + 流程图，并补充状态图 |

## Summary（摘要）

本特性实现一个 Linux CLI 工具 `iptrace`，用于精准定位报文被哪条 iptables/firewalld
规则丢弃或放通，支持：

1. 离线规则推演（P1，MVP）；
2. 在线实时追踪（P2）；
3. 规则快照导出与诊断报告（P3）。

技术路线：以 Go 为主，采用 stdlib-first 策略，在满足功能前提下将外部依赖最小化为
`golang.org/x/sys`（用于 netlink syscall）；不使用数据库；默认只读诊断，不修改防火墙。

## Task Decomposition Principles（任务拆解原则）

后续 `/speckit.tasks` 阶段采用以下拆解准则：

1. **模块化**：按 `backend`、`parser`、`matcher`、`tracer`、`exporter`、`output` 六个核心模块拆分任务，
    每个模块独立定义“测试任务 + 实现任务 + 集成任务”。
2. **精细化**：每个任务聚焦单一可交付结果（单文件或单职责变更），任务描述必须带明确文件路径、前置依赖和验收标准。
3. **测试先行**：每个实现任务必须存在前置失败测试任务（unit/contract/integration），遵循 Red-Green-Refactor。
4. **可并行性显式标注**：仅对无依赖冲突任务标记 `[P]`，优先在同阶段内并行推进模型/解析/输出等独立工作。
5. **按用户故事收敛**：P1（离线推演）形成 MVP 闭环后，再推进 P2（在线追踪）与 P3（导出报告）。

## Technical Context（技术上下文）

**Language/Version**: Go 1.21+（主实现）；C 语言仅保留兜底接口位，不作为当前实现路径  
**Primary Dependencies**: Go stdlib + `golang.org/x/sys/unix`  
**Storage**: N/A（无数据库，仅文件输入输出）  
**Testing**: `go test`（单元、集成、CLI 合约测试）  
**Target Platform**: Linux（Netfilter/iptables/firewalld）  
**Project Type**: 单体 CLI 工具（single project）  
**Performance Goals**: 首条在线追踪输出 ≤ 3s；1000 规则单报文离线推演 ≤ 1s  
**Constraints**: 默认只读；最小依赖；最少代码；trace 需 root/CAP_NET_ADMIN  
**Scale/Scope**: 单机运维排障工具，面向中小规模规则集（百到千级）

## Constitution Check（宪章门禁）

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

### Gate A — 代码质量优先
- 方案采用明确分层（`cmd`/`internal`），职责单一；
- 约束：所有提交必须通过 `go test ./...` 与格式/静态检查。

### Gate B — 用户体验一致性
- 子命令统一：`check`、`trace`、`export`；
- 统一输出语义：human/JSON 双格式字段一一映射；
- 统一退出码：0/1/2/3。

### Gate C — 性能预算与可验证目标
- 预算显式写入 success criteria（SC-003/SC-006/SC-007）；
- 在 tasks 阶段增加基准测试与回归验证任务。

### Gate D — Test-First Testing Standard
- tasks 阶段按“先失败测试再实现”拆解；
- 为规则匹配、链跳转、在线追踪与错误处理提供对应测试。

**结论**: 通过（PASS）。当前无未解释例外项。

## Project Structure（项目结构）

### Documentation (this feature)

```text
specs/001-packet-trace/
├── plan.md
├── research.md
├── data-model.md
├── quickstart.md
├── contracts/
│   └── README.md
├── c4/
│   ├── context.md
│   └── container.md
└── uml/
    ├── sequence-offline.md
    ├── sequence-online.md
    ├── flowchart-rule-traverse.md
    └── state-trace-step.md
```

### Source Code (repository root)

```text
cmd/
└── iptrace/
    └── main.go

internal/
├── backend/
├── parser/
├── matcher/
├── tracer/
├── exporter/
└── output/

pkg/
└── model/

test/
├── contract/
├── integration/
└── fixtures/
```

**Structure Decision**: 采用单项目 CLI 结构；避免过度模块拆分，以最小目录层级满足可维护性。

## Complexity Tracking（复杂度跟踪）

No constitution violations detected.

## Relevant System Context（相关系统上下文）

| Component/Document | Location | Relevance |
|--------------------|----------|-----------|
| Project Constitution | `.specify/memory/constitution.md` | 定义代码质量、UX、一致性、性能与测试强制约束 |
| System Map | `.specify/memory/system-map.md` | 提供现有工件索引与文档缺口判断依据 |
| Plan Template | `.specify/templates/plan-template.md` | 本计划结构与输出边界规范 |
| Tasks Template | `.specify/templates/tasks-template.md` | 下一阶段任务拆分与 TDD 约束来源 |
| Skills Protocol | `.specify/templates/instructions/speckit-skills.instructions.md` | 约束技能优先策略和执行方式 |

**Gaps Detected**: system-map 中未标注“⚠️ Missing”项；但缺少长期架构文档与 ADR 索引，应在 Phase N 创建并回填。

## Documentation State Matrix（文档状态矩阵）

| Event/Change | Affected Document | Action Required | Phase |
|--------------|-------------------|-----------------|-------|
| 选定在线追踪机制（xt_TRACE + NFLOG） | `docs/adr/0001-trace-mechanism.md` | Create | Phase N |
| 确认“Go 主实现 + 可选 C 兜底但当前不启用” | `docs/adr/0002-language-and-dependency-policy.md` | Create | Phase N |
| 引入 C4/动态图建模 | `docs/architecture/iptrace-overview.md` | Create（整合 specs 图表） | Phase N |
| 明确 CLI 契约（check/trace/export） | `docs/reference/iptrace-cli.md` | Create（从 contracts 提炼） | Phase N |
| 明确性能预算与基线指标 | `docs/performance/iptrace-baseline.md` | Create | Phase N |

## Gap Analysis（缺口分析）

### Missing Artifacts

| Missing Artifact | Required For | Bootstrap Priority | Owner |
|------------------|--------------|-------------------|-------|
| ADR: 在线追踪机制决策 | 架构可追溯与后续演进 | High | Maintainers |
| ADR: 依赖最小化策略 | 控制依赖扩散与发布复杂度 | High | Maintainers |
| 架构总览文档（长期） | 新成员理解与跨版本维护 | Medium | Maintainers |
| CLI 参考文档（长期） | 用户一致体验与自动化集成 | Medium | Maintainers |
| 性能基线文档 | 变更回归评估 | Medium | Maintainers |

### Bootstrapping Tasks

> These tasks will be added to Phase N (System Convergence) of tasks.md

- [ ] Create `docs/adr/0001-trace-mechanism.md`
- [ ] Create `docs/adr/0002-language-and-dependency-policy.md`
- [ ] Create `docs/architecture/iptrace-overview.md`（吸收 C4/UML 图）
- [ ] Create `docs/reference/iptrace-cli.md`（吸收 `contracts/README.md`）
- [ ] Create `docs/performance/iptrace-baseline.md`
- [ ] Update `.specify/memory/system-map.md` to include above permanent docs

