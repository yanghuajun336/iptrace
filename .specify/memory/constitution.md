<!--
Sync Impact Report
- Version change: template (unversioned) → 1.0.0
- Modified principles:
	- Principle 1 → I. 代码质量优先
	- Principle 2 → II. 用户体验一致性
	- Principle 3 → III. 性能预算与可验证目标
	- Principle 4 → IV. Test-First Testing Standard
	- Principle 5 → 已移除（合并为四项核心原则）
- Added sections:
	- 工程约束
	- 交付流程与质量门禁
- Removed sections:
	- 独立的第五原则占位段落
- Templates requiring updates:
	- ✅ .specify/templates/plan-template.md（Constitution Check 机制与本宪章兼容）
	- ✅ .specify/templates/spec-template.md（测试与可测验收场景要求与本宪章兼容）
	- ✅ .specify/templates/tasks-template.md（Article IV 测试先行要求与本宪章一致）
	- ⚠ .specify/templates/commands/*.md（目录不存在，需在引导脚本中确认路径约定）
	- ✅ .github/agents/speckit.constitution.agent.md（.specify.specify 路径引用已修复）
- Follow-up TODOs: None
-->

# iptrace Constitution

## Core Principles

### I. 代码质量优先
所有合入主干的代码 MUST 满足静态检查、格式检查与可读性要求。关键逻辑 MUST 具备
清晰命名、单一职责和可维护边界；未经说明的复杂实现不得进入主分支。任何技术债务
MUST 在同一变更中记录偿还计划与截止版本。
Rationale: 调试工具需要长期维护，代码质量直接决定故障定位速度与变更安全性。

### II. 用户体验一致性
CLI 参数、输出格式、错误提示和退出码 MUST 在各命令间保持一致语义。
同一类诊断结果 MUST 采用统一字段命名与展示顺序；破坏一致性的变更 MUST 提供迁移
说明与兼容窗口。所有用户可见文本 MUST 面向排障场景，避免歧义术语。
Rationale: 一致体验可降低学习成本，减少高压排障场景下的误判风险。

### III. 性能预算与可验证目标
功能设计 MUST 声明性能预算（如处理时延、资源占用或吞吐目标），并在合并前通过
可复现基线验证。任何导致预算超限的改动 MUST 附带优化方案或豁免批准记录。
实时分析路径 MUST 优先保障低延迟，离线推演路径 MUST 优先保障吞吐稳定性。
Rationale: 性能退化会直接削弱工具在生产环境中的可用性与可信度。

### IV. Test-First Testing Standard
所有新功能和缺陷修复 MUST 先写失败测试，再实现代码，并完成
Red-Green-Refactor 循环。涉及规则匹配、诊断结论或性能预算的改动 MUST 同时提供
单元测试与集成测试；测试结果 MUST 可在 CI 中稳定复现。
Rationale: 测试先行是防止回归、保证结论正确性和性能可控性的最小约束。

## 工程约束

- 目标运行环境 MUST 为 Linux；不满足环境前置条件时，系统 MUST 明确失败并返回
	可执行修复建议。
- 诊断输出 MUST 支持结构化格式（如 JSON）与人类可读格式，且字段语义保持一致。
- 新增依赖 MUST 说明许可、维护状态与引入收益；无明确收益不得引入。

## 交付流程与质量门禁

- 需求与方案文档 MUST 明确对应四项核心原则，未通过 Constitution Check 不得实现。
- 合并请求 MUST 包含：测试证据、用户可见变更说明、性能验证摘要（或豁免记录）。
- 涉及交互输出的改动 MUST 提供前后对比样例，确保用户体验一致性可审查。
- 发布前 MUST 完成一次全链路回归：功能正确性、错误处理一致性、性能预算校验。

## Governance

本宪章高于项目内其他流程性约定。修订流程 MUST 包含：

1. 提交修订提案，说明变更动机、影响范围、迁移或兼容策略；
2. 至少一名维护者审批，并完成模板与流程一致性复核；
3. 合并后同步更新 `.specify/memory/system-map.md` 和相关指令文件。

版本策略采用语义化版本：

- MAJOR：删除或重定义核心原则，或引入不兼容治理变更；
- MINOR：新增原则或新增强约束章节；
- PATCH：措辞澄清、错别字修复、非语义编辑。

合规审查要求：每个 `spec.md`、`plan.md`、`tasks.md` 与实现 PR MUST 记录对四项核心
原则的符合性。若存在豁免，MUST 记录责任人、原因、过期时间与回收计划。

**Version**: 1.0.0 | **Ratified**: 2026-03-25 | **Last Amended**: 2026-03-25
