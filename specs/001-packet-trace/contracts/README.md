# Contracts: 001-packet-trace

**Feature**: iptrace — iptables/firewalld 报文调试工具  
**Contract Type**: CLI Interface Contract（非 REST API）  
**Date**: 2026-03-25

---

## 说明

iptrace 是一个 CLI 工具，不提供 HTTP/REST/gRPC 接口，因此本目录不包含 OpenAPI 或 GraphQL schema。  
本文件定义 **CLI 接口契约**：子命令结构、参数规范、输出格式和退出码约定。  
这是 `internal/output` 和 `cmd/iptrace` 包的权威行为规范。

---

## CLI 接口结构

```
iptrace <subcommand> [flags]

子命令:
  check    离线推演模式（US1 P1）
  trace    在线追踪模式（US2 P2）
  export   规则快照导出（US3 P3）
```

---

## 子命令：`iptrace check`

**用途**: 基于规则快照文件离线推演报文路径（US1）

**参数**

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `--src` | `string` | 是 | 源 IP 地址，如 `1.2.3.4` |
| `--dst` | `string` | 是 | 目标 IP 地址，如 `10.0.0.1` |
| `--proto` | `string` | 是 | 协议：`tcp`、`udp`、`icmp`、`all` |
| `--sport` | `int` | 条件 | 源端口（proto=tcp/udp 时必填） |
| `--dport` | `int` | 条件 | 目标端口（proto=tcp/udp 时必填） |
| `--iif` | `string` | 否 | 入口网卡名称 |
| `--rules-file` | `string` | 是 | 规则快照文件路径（iptables-save 格式） |
| `--format` | `string` | 否 | 输出格式：`human`（默认）、`json` |

**标准输出（human 格式）**

```
Backend:    iptables-legacy
Packet:     tcp 1.2.3.4:12345 → 10.0.0.1:8080

Step  Hook         Table   Chain   Rule  Action
----  -----------  ------  ------  ----  ------
  1   PREROUTING   raw     PREROUTING  -  CONTINUE
  2   INPUT        filter  INPUT   3   DROP (matched)

Verdict: DROP
  Matched rule: filter INPUT rule 3
  Rule text:    -A INPUT -s 1.2.3.4 -p tcp --dport 8080 -j DROP
```

**标准输出（json 格式）**

```json
{
  "backend": "iptables-legacy",
  "packet": {
    "protocol": "tcp",
    "src_ip": "1.2.3.4",
    "src_port": 12345,
    "dst_ip": "10.0.0.1",
    "dst_port": 8080
  },
  "steps": [
    {
      "hook_point": "PREROUTING",
      "table": "raw",
      "chain": "PREROUTING",
      "rule_number": 0,
      "raw_rule": "",
      "matched": false,
      "action": "CONTINUE"
    },
    {
      "hook_point": "INPUT",
      "table": "filter",
      "chain": "INPUT",
      "rule_number": 3,
      "raw_rule": "-A INPUT -s 1.2.3.4 -p tcp --dport 8080 -j DROP",
      "matched": true,
      "action": "DROP"
    }
  ],
  "verdict": "DROP",
  "verdict_rule": {
    "hook_point": "INPUT",
    "table": "filter",
    "chain": "INPUT",
    "rule_number": 3,
    "raw_rule": "-A INPUT -s 1.2.3.4 -p tcp --dport 8080 -j DROP",
    "matched": true,
    "action": "DROP"
  },
  "default_policy_applied": false,
  "duration_ms": 2
}
```

---

## 子命令：`iptrace trace`

**用途**: 在线实时追踪模式，捕获真实报文经过 Netfilter 的路径（US2）

**参数**

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `--src` | `string` | 否 | 过滤源 IP |
| `--dst` | `string` | 否 | 过滤目标 IP |
| `--proto` | `string` | 否 | 过滤协议 |
| `--sport` | `int` | 否 | 过滤源端口 |
| `--dport` | `int` | 否 | 过滤目标端口 |
| `--timeout` | `duration` | 否 | 超时时间，如 `30s`（0 为不限，默认 0） |
| `--format` | `string` | 否 | 输出格式：`human`（默认）、`json` |

**权限要求**: 需要 root 权限（或 `CAP_NET_ADMIN`），否则以非零退出并提示 `sudo iptrace trace ...`

**行为边界**: `trace` 允许为诊断目的临时注入追踪规则，但这些规则 MUST 在会话退出、超时或中断后自动清理，不得形成持久化配置漂移。

**标准输出（human 格式，流式）**

```
[15:04:05.123] PREROUTING  raw       PREROUTING  rule 1  CONTINUE
[15:04:05.124] PREROUTING  mangle    PREROUTING  rule -  CONTINUE (policy ACCEPT)
[15:04:05.125] INPUT       filter    INPUT       rule 3  DROP ← VERDICT
```

**标准输出（json 格式，每行一个 JSON 对象，NDJSON）**

```json
{"timestamp":"2026-03-25T15:04:05.123Z","hook_point":"PREROUTING","table":"raw","chain":"PREROUTING","rule_number":1,"matched":false,"action":"CONTINUE"}
{"timestamp":"2026-03-25T15:04:05.125Z","hook_point":"INPUT","table":"filter","chain":"INPUT","rule_number":3,"matched":true,"action":"DROP","verdict":true}
```

---

## 子命令：`iptrace export`

**用途**: 导出当前系统规则快照，可直接用于 `check` 命令（US3）

**参数**

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `--output` | `string` | 是 | 输出文件路径，如 `snapshot.rules` |
| `--format` | `string` | 否 | 输出格式：`human`（默认）、`json` |

**标准输出（成功，human）**

```
Exported 47 rules from iptables-legacy to snapshot.rules
```

**标准输出（成功，json）**

```json
{"status":"ok","backend":"iptables-legacy","rule_count":47,"output_file":"snapshot.rules"}
```

---

## 退出码约定

| 退出码 | 语义 |
|--------|------|
| `0` | 成功 |
| `1` | 用户输入错误（参数缺失、格式非法） |
| `2` | 环境错误（权限不足、内核模块缺失、文件不存在） |
| `3` | 内部错误（解析失败、意外状态） |

所有非零退出：标准错误流输出错误原因 + 至少一条可执行修复建议（满足 FR-008、SC-004）。

---

## 字段语义一致性约定

JSON 字段名与 human 格式列标题的映射（满足 FR-006、SC-005）：

| human 列 | JSON 字段 | 说明 |
|----------|-----------|------|
| Hook | `hook_point` | Netfilter 钩子点 |
| Table | `table` | 所属表 |
| Chain | `chain` | 所属链 |
| Rule | `rule_number` | 规则序号（0=默认策略） |
| Action | `action` | 产生的动作 |
| Verdict | `verdict` / `"verdict": true` | 最终判决标记 |

任何同名字段在两种格式中的语义 MUST 完全一致（宪章 II）。
