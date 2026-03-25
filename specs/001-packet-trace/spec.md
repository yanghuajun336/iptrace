# Feature Specification: iptrace — iptables/firewalld 报文调试工具

**Feature Branch**: `feat/001-packet-trace`
**Created**: 2026-03-25
**Status**: Draft
**Input**: User description: "我想开发一个iptrace - iptables/firewalld 报文调试工具，一个用于Linux系统的调试工具，帮助你精准定位报文被哪条iptables/firewalld规则丢弃，或者被哪条规则放通。支持在线实时抓包分析和事后推演。"

## Available Skills Analysis

None applicable

*`release-server-developer` 技能关注 Release Server 组件的构建与发布流程，与本特性的报文调试领域无直接关联。*

## Assumptions

- 工具以 CLI（命令行界面）形式交付，面向 Linux 系统管理员和网络工程师。
- 默认支持 IPv4；IPv6（ip6tables）支持作为后续扩展，不在本次规格范围内。
- "在线实时分析"模式通过内核 Netfilter 追踪机制（如 `xt_trace` 模块或 nftables 追踪）实现；工具不在默认模式下捕获原始流量，而是追踪规则命中路径。
- "事后推演"模式：用户提供报文描述（五元组）和规则快照文件，工具在本地模拟规则遍历，无需网络实时流量。
- 工具默认以只读方式运行，不修改防火墙配置。
- 支持 iptables（legacy 与 nft 后端）和 firewalld（通过其底层 iptables/nftables 规则集）。
- 诊断结果同时支持人类可读格式和 JSON 结构化输出。

## User Scenarios & Testing *(mandatory)*

### User Story 1 — 单报文规则路径定位（事后推演） (Priority: P1)

运维工程师遇到某个 IP 地址无法访问某服务，怀疑被防火墙规则拦截。
他提供报文的源/目标 IP、端口和协议，并导出当前 iptables 规则快照，
使用 iptrace 进行离线推演，立刻看到哪条规则（链、表、行号、规则内容）命中该报文，
以及最终判定结果（DROP / ACCEPT / REJECT 及原因）。

**Linked Skills**: None

**Why this priority**: 这是工具的核心价值主张，也是最常见的排障场景。无需内核特权即可运行，可在最多环境下验证并交付 MVP。

**Independent Test**: 在测试规则集快照（无需真实网络环境）下，输入一个已知会被 DROP 的五元组，验证工具输出正确的命中规则与决策结果。

**Acceptance Scenarios**:

1. **Given** 用户提供一份包含若干 INPUT 链规则的 iptables 规则快照（其中第 3 条为 `-s 1.2.3.4 -p tcp --dport 8080 -j DROP`），**When** 用户执行 `iptrace check --src 1.2.3.4 --dst 10.0.0.1 --proto tcp --dport 8080 --rules-file snapshot.rules`，**Then** 工具输出：命中表/链/规则序号、原始规则文本、决策 `DROP`，退出码为 0。
2. **Given** 同一规则快照，但五元组不匹配任何规则，**When** 用户执行相同命令，**Then** 工具输出：遍历所有规则后无匹配，最终决策为链默认策略（ACCEPT 或 DROP），并注明来源为链默认策略。
3. **Given** 规则文件路径不存在，**When** 用户执行命令，**Then** 工具退出码非零，错误信息明确指出文件路径无效，不输出任何诊断结果。

---

### User Story 2 — 实时报文追踪（在线模式） (Priority: P2)

网络工程师需要在流量发生时追踪真实报文经过 Netfilter 的完整路径，包括 NAT 转换、PREROUTING/FORWARD/OUTPUT 等各阶段命中规则，实时查看每个钩子点的决策。

**Linked Skills**: None

**Why this priority**: 在线追踪是工具的差异化能力，对生产环境实时排障至关重要，但需要更高权限（root）和内核支持，独立于 P1 的离线推演可单独开发验证。

**Independent Test**: 在测试环境（可模拟内核追踪输出）下，触发一条已知规则，验证工具实时输出该报文在每个 Netfilter 钩子点的命中规则与决策链路。

**Acceptance Scenarios**:

1. **Given** 系统内核支持追踪模块且用户以 root 身份运行，**When** 用户执行 `iptrace trace --filter "src 1.2.3.4 dport 80"` 并有符合条件的报文到达，**Then** 工具实时输出：到达时间戳、钩子点名称（PREROUTING/INPUT/FORWARD/OUTPUT/POSTROUTING）、命中规则（表/链/规则序号/规则内容）、每步决策；最终输出完整路径摘要。
2. **Given** 内核不支持所需追踪机制，**When** 用户执行追踪命令，**Then** 工具以非零退出码失败，错误信息说明缺少哪个内核模块/能力，并提供修复建议（如加载 `xt_LOG` 或 `nf_log` 模块）。
3. **Given** 用户以非 root 身份运行，**When** 用户执行在线追踪命令，**Then** 工具立即退出并提示权限不足，建议使用 `sudo`。

---

### User Story 3 — 规则快照导出与诊断报告（辅助工具） (Priority: P3)

系统管理员希望在维护窗口前后导出完整的 iptables/firewalld 规则快照，并生成可读性高的诊断摘要，以便与团队共享或存档留证。

**Linked Skills**: None

**Why this priority**: 快照导出和报告是追踪工作流的重要辅助工具，但不影响核心 P1/P2 场景的可用性，可在基础能力稳定后补充。

**Independent Test**: 执行导出命令，验证输出文件格式合法（可被 P1 的规则文件参数直接使用），且快照内容与系统当前规则一致。

**Acceptance Scenarios**:

1. **Given** 用户以 root 身份在有效的 iptables 规则环境下运行，**When** 用户执行 `iptrace export --output snapshot.rules`，**Then** 工具输出规则快照文件，文件格式可被 `iptrace check --rules-file` 直接使用，退出码为 0。
2. **Given** 用户已完成一次离线推演，**When** 用户追加 `--report json` 参数，**Then** 工具以 JSON 格式输出包含五元组、命中规则、决策结果的结构化报告，字段定义与人类可读格式语义一致。
3. **Given** 用户在 firewalld 管理的系统上运行导出命令，**When** 执行 `iptrace export`，**Then** 工具识别 firewalld 并通过其底层规则集导出完整快照，输出注明规则管理来源（firewalld）。

---

### Edge Cases

- 若系统同时运行 iptables-legacy 和 iptables-nft，工具需检测后端类型并明确告知用户使用了哪个后端；若两者冲突，工具以错误退出并给出诊断建议。
- 报文五元组匹配到含有 `RETURN` 目标的规则时，工具需继续追踪父链处理逻辑，直到最终决策，不得误报 RETURN 为最终结果。
- 规则快照包含自定义链（user-defined chain）时，工具需递归追踪，正确呈现完整跳转路径。
- 若默认链策略为 ACCEPT 且所有规则均不匹配，工具需明确输出"默认策略 ACCEPT"而非空结果或静默通过。
- 在线追踪模式下，若追踪输出流量过大（高速网络环境），工具需支持流量限速或采样，避免输出淹没终端，且不影响系统稳定性。
- 涉及 NAT 规则（PREROUTING DNAT / POSTROUTING SNAT）时，工具需呈现 NAT 转换前后的地址变化，避免用户因地址变换误判规则未命中。

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: 系统 MUST 接受报文五元组（源 IP、目标 IP、源端口、目标端口、协议）作为追踪输入参数。
- **FR-002**: 系统 MUST 在离线推演模式下，基于用户提供的规则快照文件模拟报文经过各 Netfilter 表/链的遍历过程。
- **FR-003**: 系统 MUST 在推演结束后输出最终决策结果（ACCEPT、DROP 或 REJECT），并明确指出命中的规则（表名、链名、规则序号、原始规则内容）。
- **FR-004**: 系统 MUST 在在线追踪模式下，利用系统内核追踪能力捕获真实报文经过 Netfilter 各钩子点的路径，并实时输出每步决策。
- **FR-005**: 系统 MUST 支持从当前系统导出 iptables/firewalld 规则快照，导出格式可直接用于离线推演。
- **FR-006**: 系统 MUST 同时支持人类可读格式输出（默认）和 JSON 结构化输出（通过参数切换），两种格式字段语义一致。
- **FR-007**: 系统 MUST 在默认模式下为只读操作，不修改任何防火墙配置。
- **FR-008**: 系统 MUST 在环境不满足前置条件时（如缺少内核模块、权限不足、文件不存在）以非零退出码失败，并输出可执行的修复建议。
- **FR-009**: 系统 MUST 正确处理自定义链跳转（JUMP/RETURN），在输出中呈现完整的链遍历路径，包括链名、跳转原因和 RETURN 返回路径。
- **FR-010**: 系统 MUST 同时识别并支持 iptables-legacy、iptables-nft 两种后端以及 firewalld 管理的规则环境，并在输出中注明检测到的后端类型。
- **FR-011**: 在线追踪模式中，系统 MUST 支持基于五元组的过滤条件，仅追踪符合条件的报文。

### Key Entities

- **Packet（报文描述）**: 一次追踪的输入对象，由五元组（协议、源IP、目标IP、源端口、目标端口）加上可选的入口网卡（ingress interface）构成；无状态，不携带实际载荷。
- **RuleSet（规则集快照）**: 特定时刻系统防火墙规则的完整镜像，包含表（table）、链（chain）、默认策略和规则列表；可来自实时导出或文件加载。
- **TraceStep（追踪步骤）**: 报文在一个具体规则上的匹配事件，包含：钩子点名称、表名、链名、规则序号、规则内容、匹配结果（命中/未命中）、产生的动作（目标）。
- **TraceResult（追踪结果）**: 完整的推演/追踪输出，由有序的 TraceStep 序列和最终判决（ACCEPT/DROP/REJECT + 依据）组成。
- **Backend（规则后端）**: 检测到的规则管理层，取值为 iptables-legacy、iptables-nft 或 firewalld，决定规则读取与解析方式。

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: 用户可在 2 分钟内完成从输入报文五元组到获得命中规则输出的完整离线推演，无需阅读任何手册。
- **SC-002**: 离线推演模式下，工具对标准 iptables 规则集的遍历结论与手工逐条核对结论一致率达 100%（覆盖 ACCEPT、DROP、REJECT、RETURN、自定义链跳转场景）。
- **SC-003**: 在线追踪模式从用户下达命令到第一条追踪输出出现的延迟不超过 3 秒（正常内核环境下）。
- **SC-004**: 所有错误场景（权限不足、文件不存在、不支持的内核）均产生非零退出码，错误信息中包含具体原因和至少一条可执行的修复建议；不出现空错误信息或未捕获异常。
- **SC-005**: JSON 输出中每个字段名称与人类可读输出中对应信息的语义完全一致，无同名字段含义不同的情况。
- **SC-006**: 工具在 1000 条规则规模的规则集上完成离线推演的耗时不超过 1 秒（单报文）。
- **SC-007**: 工具在实时追踪模式下运行 10 分钟，系统 CPU 额外占用不超过 5%，内存增长不超过 50MB（低流量场景基准）。
