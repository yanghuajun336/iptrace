# System Map

**Purpose**: Centralized index of all authoritative documentation for the project. Enables AI agents to quickly locate relevant context without scanning the entire codebase.

**Template Version**: 2.0.0
**Version**: 1.0.0 | **Created**: 2026-03-25 | **Last Updated**: 2026-03-26
**Maintained By**: iptrace Maintainers
**Review Frequency**: After each major feature completion

---

## Project Identity

**Project**: iptrace
**Description**: Linux 报文调试工具，用于定位报文被哪条 iptables/firewalld 规则丢弃或放通，支持实时分析与事后推演。

### Core Principles

1. 代码质量优先：主干代码必须通过质量门禁并可维护。
2. 用户体验一致性：CLI 交互、输出语义、错误码与提示保持一致。
3. 性能预算与可验证目标：改动必须声明并验证性能预算。
4. Test-First Testing Standard：先写失败测试，再实现并回归验证。

### Technology Stack

<!-- List the primary languages, frameworks, and tools used in this project. -->

| Category | Technology | Purpose |
|----------|-----------|---------|
| Platform | Linux + Netfilter (iptables/firewalld) | 报文过滤链路与规则判定基础 |
| Scripting | Bash | 规范化流程与自动化脚本 |
| Tooling | Python 3 | 技能解析与流程支持脚本 |
| Documentation | Markdown | 规范、流程和项目记忆沉淀 |

### Project Components

<!-- List the major components/modules of this project. -->

| Component | Location | Technology | Purpose |
|-----------|----------|------------|---------|
| Memory Center | .specify/memory/ | Markdown | 保存宪章与系统地图 |
| Template Set | .specify/templates/ | Markdown | 定义 spec/plan/tasks/system-map 模板 |
| Automation Scripts | .specify/scripts/ | Bash/Python | 特性创建、计划初始化与上下文更新 |
| Agent Definitions | .github/agents/ | Markdown | 各 Speckit 命令的执行规则 |
| Prompt Definitions | .github/prompts/ | Markdown | 命令入口与提示路由 |
| Skill Library | .github/skills/ | Markdown/YAML | 领域技能与适配器规范 |

---

## Essential Artifacts

<!--
Status values: ✅ Active | ⚠️ Missing | 🗑️ Deprecated
Fill tables based on your project type. Not all categories apply to every project.

Common artifacts by project type:
- Web Backend: System Architecture, Database Schema, API Design, Deployment Config
- CLI Tool: Command Structure, Plugin Architecture, Distribution Config
- Frontend App: Component Hierarchy, State Management, Routing Map
- Library/SDK: Public API Reference, Compatibility Matrix, Usage Examples
- Microservices: Service Topology, Contract Catalog, Inter-service Auth
- Data Pipeline: Data Flow Diagram, Schema Registry, Processing SLAs

Add rows that are relevant; remove or leave empty categories that don't apply.
-->

### 🏛️ Architecture & Design

| Artifact | Location | Status | Last Updated | Description |
|----------|----------|--------|--------------|-------------|
| Project Constitution | .specify/memory/constitution.md | ✅ Active | 2026-03-25 | 项目治理原则、质量标准与性能约束 |
| Architecture Overview | docs/architecture/iptrace-overview.md | ✅ Active | 2026-03-26 | iptrace 组件边界、关键流程与演进路线 |
| Trace Mechanism ADR | docs/adr/0001-trace-mechanism.md | ✅ Active | 2026-03-26 | 在线追踪机制选型与后续补充策略 |
| Language & Dependency ADR | docs/adr/0002-language-and-dependency-policy.md | ✅ Active | 2026-03-26 | Go 主实现与最小依赖治理策略 |

### 📐 Configuration & Infrastructure

| Artifact | Location | Status | Last Updated | Description |
|----------|----------|--------|--------------|-------------|
| Speckit Config | .speckit.yaml | ✅ Active | 2026-03-25 | 技能扫描目录与项目记忆路径配置 |
| Workspace Settings | .vscode/settings.json | ✅ Active | 2026-03-25 | 编辑器行为与工作区配置 |

### 🧪 Quality & Testing

| Artifact | Location | Status | Last Updated | Description |
|----------|----------|--------|--------------|-------------|
| Tasks Template | .specify/templates/tasks-template.md | ✅ Active | 2026-03-25 | 定义测试先行、阶段执行与收敛验证模式 |
| Plan Template | .specify/templates/plan-template.md | ✅ Active | 2026-03-25 | 包含 Constitution Check 与技术上下文门禁 |
| Performance Baseline | docs/performance/iptrace-baseline.md | ✅ Active | 2026-03-26 | 收敛后的性能预算与验证基线 |
| TDD Traceability | docs/quality/tdd-traceability.md | ✅ Active | 2026-03-26 | 任务—测试—实现可追溯矩阵 |

### 🧭 Project Memory

<!--
  These entries anchor the Gap Analysis in /speckit.plan.
  Always keep status up to date so agents do not incorrectly create bootstrap tasks
  for files that already exist on disk.
-->

| Artifact | Location | Status | Last Updated | Description |
|----------|----------|--------|--------------|-------------|
| System Map | `.specify/memory/system-map.md` | ✅ Active | 2026-03-26 | Living index of all project components and documentation |
| Project Constitution | `.specify/memory/constitution.md` | ✅ Active | 2026-03-25 | Governing principles and architectural constraints |

### 📚 Decisions & Standards

| Artifact | Location | Status | Last Updated | Description |
|----------|----------|--------|--------------|-------------|
| Constitution Agent Guide | .github/agents/speckit.constitution.agent.md | ✅ Active | 2026-03-25 | 宪章更新流程与一致性校验规则 |
| Skills Protocol | .specify/templates/instructions/speckit-skills.instructions.md | ✅ Active | 2026-03-25 | 规定技能优先与激活流程 |
| CLI Reference | docs/reference/iptrace-cli.md | ✅ Active | 2026-03-26 | check/trace/export 契约化命令参考 |

---

## Integration Points

### External Services

<!-- List third-party services, APIs, or platforms the project depends on. Leave empty if none. -->

| Service | Type | Documentation | Purpose |
|---------|------|---------------|---------|

### Internal Dependencies

<!-- List internal modules or services that this project depends on or exposes. Leave empty if not applicable. -->

| Module | Location | Interface | Description |
|--------|----------|-----------|-------------|

---

## Knowledge Sources

### Documentation

<!-- List user-facing and developer-facing documentation. -->

| Topic | Location | Type | Description |
|-------|----------|------|-------------|
| Governance Rules | .specify/memory/constitution.md | Governance | 核心原则、修订流程与合规要求 |
| Documentation Index | .specify/memory/system-map.md | Index | 项目文档与组件目录 |
| Agent Workflow Docs | .github/agents/ | Process | 命令执行策略与约束说明 |
| Prompt Catalog | .github/prompts/ | Process | 代理触发入口与提示配置 |

### Technical Context

<!-- List domain-specific resources, guides, or references relevant to this project. -->

| Domain | Resource | Description |
|--------|----------|-------------|
| Project Automation | .specify/scripts/ | 特性脚手架、环境检查与上下文更新脚本 |

---

## Using the System Map

### For Planning (`/speckit.plan`)

1. **Identify Touched Components**: Cross-reference feature requirements with the Architecture & Design section.
2. **Flag Gaps**: If a touched component has status "⚠️ Missing", add a Bootstrapping Task to Phase N.
3. **Extract Context**: Include relevant artifacts in the "Relevant System Context" section of `plan.md`.

### For Task Generation (`/speckit.tasks`)

1. **Bind Context to Tasks**: For tasks touching specific modules, append `(Ref: <location>)` to task descriptions.
2. **Verify Prerequisites**: Check the Configuration & Infrastructure section for setup requirements.

### For Implementation (`/speckit.implement`)

1. **Follow Standards**: Reference the Code Style Guide and Development Guidelines.
2. **Check Decisions**: Review related ADRs before making architectural changes.

---

## Maintenance Protocol

### When a Feature is Completed

1. **Update Status**: Change artifact status from "⚠️ Missing" to "✅ Active".
2. **Record Location**: Fill in the actual file path or URL.
3. **Update Timestamp**: Set "Last Updated" to the current date.
4. **Add Description**: Briefly describe what the artifact contains.

### When an Artifact is Deprecated

1. **Change Status**: Mark as "🗑️ Deprecated".
2. **Add Reason**: Note why it was deprecated and what replaced it.
3. **Archive**: Move to an `archive/` directory if still needed for reference.

---

## Bootstrap Checklist

Review the Essential Artifacts tables above. Any artifact with status "⚠️ Missing" that is critical to your project should be prioritized for creation. The `/speckit.converge` phase will use this map to identify and close documentation gaps.

---

**Instructions for Agents**:

- **DO** treat this map as the authoritative index of documentation.
- **DO** propose updates to this map when creating or discovering new artifacts.
- **DO** flag missing artifacts during planning phases.
- **DO NOT** assume artifacts exist if not listed here or marked as "⚠️ Missing".
- **DO NOT** create duplicate documentation without updating this index.
- **DO NOT** add new sections or restructure this document. Only fill tables and update status fields.
- **DO NOT** add entries from `specs/` to this map. The `specs/` directory contains transient development artifacts (feature specs, plans, tasks). Their knowledge should be distilled into permanent documentation during the Converge phase — only those resulting permanent documents belong in this map.
