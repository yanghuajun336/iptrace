# iptrace 架构总览

## 1. 目标与范围

`iptrace` 是 Linux 防火墙报文诊断 CLI，覆盖三类能力：

- `check`：离线规则推演（规则快照 + 五元组）；
- `trace`：在线追踪报文路径（实时事件流）；
- `export`：导出规则快照供离线分析复用。

本文件蒸馏自特性阶段的 C4/UML 设计文档，并以当前代码结构为准。

## 2. 运行时边界

外部边界：

1. Linux 运维用户（CLI 操作方）；
2. Linux Kernel / Netfilter（在线事件来源）；
3. `iptables-save` / `iptables-nft-save` / `firewall-cmd`（规则来源命令）；
4. 规则快照文件（离线输入与导出输出）。

## 3. 模块视图（代码映射）

- `cmd/iptrace/`：命令分发、参数解析、退出码输出。
- `internal/backend/`：后端检测（legacy/nft/firewalld）。
- `internal/parser/`：iptables-save 文本解析为内存规则模型。
- `internal/matcher/`：离线匹配与链路推演。
- `internal/tracer/`：在线会话、事件解码、追踪注入/清理。
- `internal/exporter/`：规则快照导出。
- `internal/output/`：human/json 输出与错误提示统一层。
- `pkg/model/`：共享数据模型（Packet/RuleSet/TraceStep/TraceResult）。

## 4. 关键流程

### 4.1 离线推演（check）

1. 解析参数并校验报文输入；
2. 加载规则文件并解析为 `RuleSet`；
3. `matcher.Simulate()` 遍历规则并输出 `TraceResult`；
4. `output` 层渲染 human/json。

### 4.2 在线追踪（trace）

1. 校验权限与运行模式；
2. 创建 `tracer.Session` 并启动事件流；
3. 将 `TraceStep` 流式输出（human/NDJSON）；
4. 会话退出时执行清理。

### 4.3 快照导出（export）

1. 校验输出路径与格式；
2. 调用导出器生成规则快照；
3. 输出统一摘要（human/json）。

## 5. 设计约束

- **一致性约束**：CLI 错误与提示由 `internal/output` 统一；
- **性能约束**：离线推演和在线首条输出需满足既定预算；
- **可维护性约束**：TDD 先行、最小依赖、分层清晰。

## 6. 演进方向

1. 补齐 nft 场景的追踪增强路径；
2. 提升规则解析与导出的后端覆盖度；
3. 持续用性能基线与可追溯矩阵约束文档和实现同步。
