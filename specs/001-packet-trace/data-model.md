# Data Model: 001-packet-trace

**Feature**: iptrace — iptables/firewalld 报文调试工具  
**Branch**: `feat/001-packet-trace`  
**Phase**: 1 — Design & Contracts  
**Date**: 2026-03-25

---

## 概述

iptrace 不使用持久化数据库，所有实体均为内存中的值对象，生命周期限于单次命令执行。  
以下模型描述 Go 中的核心结构体、字段语义、校验规则和状态转换。

---

## 实体定义

### 1. Packet（报文描述）

报文是一次追踪的输入对象，由五元组与可选的入口网卡构成，无状态，不携带载荷。

**字段**

| 字段 | Go 类型 | 必填 | 语义 |
|------|---------|------|------|
| `Protocol` | `string` | 是 | 协议：`tcp`、`udp`、`icmp`、`all` |
| `SrcIP` | `net.IP` | 是 | 源 IP 地址（IPv4） |
| `DstIP` | `net.IP` | 是 | 目标 IP 地址（IPv4） |
| `SrcPort` | `uint16` | 条件 | 源端口（Protocol 为 tcp/udp 时必填） |
| `DstPort` | `uint16` | 条件 | 目标端口（Protocol 为 tcp/udp 时必填） |
| `InInterface` | `string` | 否 | 入口网卡名称（如 `eth0`，用于 PREROUTING INPUT 钩子匹配） |

**校验规则**

- `Protocol` 必须为 `tcp`、`udp`、`icmp`、`all` 之一
- `SrcIP`、`DstIP` 必须为合法 IPv4 地址
- `SrcPort`、`DstPort` 范围 0–65535；Protocol 为 `icmp` 或 `all` 时忽略端口
- 不合法时以非零退出码失败，输出具体字段错误信息（满足 SC-004）

---

### 2. RuleSet（规则集快照）

特定时刻系统防火墙规则的完整快照，可来自文件（离线）或实时导出（在线）。

**字段**

| 字段 | Go 类型 | 语义 |
|------|---------|------|
| `Backend` | `Backend` | 规则来源后端类型 |
| `Tables` | `[]Table` | 表列表（filter / nat / mangle / raw） |
| `LoadedAt` | `time.Time` | 快照加载时间（仅元信息，不影响匹配逻辑） |
| `SourceFile` | `string` | 来源文件路径（从文件加载时填充，导出场景为空） |

**子结构：Table**

| 字段 | Go 类型 | 语义 |
|------|---------|------|
| `Name` | `string` | 表名：`filter`、`nat`、`mangle`、`raw` |
| `Chains` | `[]Chain` | 链列表 |

**子结构：Chain**

| 字段 | Go 类型 | 语义 |
|------|---------|------|
| `Name` | `string` | 链名：`INPUT`、`OUTPUT`、`FORWARD`、自定义链 |
| `DefaultPolicy` | `string` | 内建链默认策略：`ACCEPT`、`DROP`；自定义链为空 |
| `Rules` | `[]Rule` | 规则列表（按 iptables-save 顺序） |

**子结构：Rule**

| 字段 | Go 类型 | 语义 |
|------|---------|------|
| `Number` | `int` | 规则序号（1-based，对应 iptables -L 中的行号） |
| `RawText` | `string` | 原始规则文本（用于输出时展示） |
| `Matches` | `[]Match` | 匹配条件列表 |
| `Target` | `string` | 目标动作：`ACCEPT`、`DROP`、`REJECT`、`LOG`、`RETURN`、链名（JUMP） |
| `TargetOptions` | `map[string]string` | 目标参数（如 `--reject-with tcp-reset`） |

**校验规则**

- 同一 Table 内不得有重名 Chain
- `DefaultPolicy` 非空时只能为 `ACCEPT` 或 `DROP`

---

### 3. TraceStep（追踪步骤）

报文在一个具体规则或链策略上的单次匹配事件。

**字段**

| 字段 | Go 类型 | 语义 |
|------|---------|------|
| `HookPoint` | `string` | Netfilter 钩子点：`PREROUTING`、`INPUT`、`FORWARD`、`OUTPUT`、`POSTROUTING` |
| `Table` | `string` | 所属表名 |
| `Chain` | `string` | 所属链名 |
| `RuleNumber` | `int` | 规则序号；0 表示默认策略 |
| `RawRule` | `string` | 原始规则文本；默认策略时为 `"policy: <POLICY>"` |
| `Matched` | `bool` | 是否命中该规则 |
| `Action` | `string` | 产生的动作（仅 Matched=true 时有效）：`ACCEPT`、`DROP`、`REJECT`、`JUMP <chain>`、`RETURN`、`CONTINUE` |
| `JumpTarget` | `string` | JUMP 时的目标链名（否则为空） |

**状态转换**

```
未匹配 (Matched=false) → CONTINUE（继续下一条规则）
匹配 (Matched=true)   →
  ├─ ACCEPT           → 终止（最终判决 ACCEPT）
  ├─ DROP             → 终止（最终判决 DROP）
  ├─ REJECT           → 终止（最终判决 REJECT，附带 reject-with 类型）
  ├─ RETURN           → 返回父链继续匹配
  ├─ JUMP <chain>     → 进入目标链
  └─ LOG/其他扩展      → CONTINUE（非终止动作）
到达链末尾（无规则命中）→ 使用链默认策略（内建链）或 RETURN（自定义链）
```

---

### 4. TraceResult（追踪结果）

完整推演/追踪输出，为有序 TraceStep 序列 + 最终判决。

**字段**

| 字段 | Go 类型 | 语义 |
|------|---------|------|
| `Packet` | `Packet` | 输入报文描述（回显） |
| `Backend` | `Backend` | 使用的后端类型 |
| `Steps` | `[]TraceStep` | 有序匹配步骤，按遍历顺序排列 |
| `Verdict` | `string` | 最终判决：`ACCEPT`、`DROP`、`REJECT` |
| `VerdictRule` | `*TraceStep` | 决定最终判决的步骤（nil = 由默认策略决定） |
| `DefaultPolicyApplied` | `bool` | 是否由默认链策略决定最终结果 |
| `Duration` | `time.Duration` | 推演耗时（用于性能验证 SC-006） |

---

### 5. Backend（规则后端）

检测到的规则管理层，决定规则读取与解析方式。

**枚举值**

| 值 | Go 常量 | 语义 |
|----|---------|------|
| `iptables-legacy` | `BackendLegacy` | 使用 `iptables-save`（xtables-legacy 栈） |
| `iptables-nft` | `BackendNFT` | 使用 `iptables-nft-save`（xtables over nftables） |
| `firewalld` | `BackendFirewalld` | 使用 `firewall-cmd`，规则由 firewalld 管理 |
| `unknown` | `BackendUnknown` | 检测失败（工具以错误退出） |

**检测策略**

1. 检查 `firewalld` 服务状态（`systemctl is-active firewalld`）→ 若活跃则为 `BackendFirewalld`
2. 检查 `iptables-nft-save` 命令是否存在且版本支持 → `BackendNFT`
3. 回退 `iptables-save` → `BackendLegacy`
4. 均失败 → `BackendUnknown`，退出非零并输出修复建议

---

## 说明

本项目不使用持久化数据库，所有上述实体生命周期限于单次命令执行内存中。  
规则快照文件（`--rules-file`）为 iptables-save 格式的纯文本，无需专用序列化库。
