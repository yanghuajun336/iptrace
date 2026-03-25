# Research: 001-packet-trace

**Feature**: iptrace — iptables/firewalld 报文调试工具  
**Branch**: `feat/001-packet-trace`  
**Phase**: 0 — Outline & Research  
**Date**: 2026-03-25

---

## 调研问题索引

| # | 调研主题 | 状态 |
|---|---------|------|
| R-01 | Go + CGo vs 纯 Go 内核接口 | ✅ 已决策 |
| R-02 | 在线追踪内核机制选型 | ✅ 已决策 |
| R-03 | 依赖最小化策略（stdlib-first） | ✅ 已决策 |

---

## R-01: Go + CGo vs 纯 Go 内核接口

**背景**: 用户要求 Go 为主要语言，仅在内核耦合极高时允许使用 C。  
需评估各功能组件是否需要 CGo。

### 决策

**选择：纯 Go（Zero CGo）**

所有组件均可以纯 Go 实现，无需 CGo 边界。

### 各组件分析

| 组件 | 实现方式 | CGo 需求 |
|------|---------|---------|
| iptables-save 格式解析 | `os/exec` 执行 + bufio 文本解析 | ❌ 不需要 |
| nftables 规则读取 | `os/exec` 执行 `nft list ruleset -j` + `encoding/json` | ❌ 不需要 |
| firewalld 规则读取 | `os/exec` 执行 `firewall-cmd --list-all-zones` + 文本解析 | ❌ 不需要 |
| Netfilter NFLOG 在线追踪 | `golang.org/x/sys/unix` 原生 netlink socket | ❌ 不需要 |

### 理由

- `iptables-save` / `nft` / `firewall-cmd` 均为用户态命令，输出为结构化文本或 JSON，`os/exec` + stdlib 解析完全足够
- `golang.org/x/sys/unix` 提供 `AF_NETLINK`/`NETLINK_NETFILTER` 原生 syscall 访问，无需 C 绑定
- 纯 Go 方案无需 C 工具链，静态编译友好，简化发布流程

### 备选方案及否决原因

- **libnetfilter_log (CGo)**：增加 C 编译时依赖，不支持 `go build` 静态链接，收益为零（纯 Go 方案等效）
- **libmnl + CGo**：同上，iptables-save 文本格式已稳定，不需要 netlink 原生 API 来读取规则

---

## R-02: 在线追踪内核机制选型

**背景**: FR-004 要求在线追踪模式利用系统内核追踪能力，捕获报文经过 Netfilter 各钩子点的路径。

### 决策

**主要机制：xt_TRACE target + NFLOG**  
**备选机制：nftables trace（当检测到 iptables-nft 后端时自动降级）**

### 机制详情

#### xt_TRACE + NFLOG（主要，P2 实现目标）

| 属性 | 说明 |
|------|------|
| 工作原理 | 临时注入 `xt_TRACE` 规则 → 内核通过 NFLOG 发送每条规则匹配事件 → 用户空间 netlink socket 接收 |
| 兼容性 | iptables-legacy（Linux 2.6+）、iptables-nft 均支持 |
| 内核模块依赖 | `xt_LOG`、`nf_log_ipv4`（启动时检测，缺失则报错提示用户） |
| 实现复杂度 | 中等（netlink socket 绑定 + TLV 属性解析） |
| 侵入性 | 低（仅临时注入追踪规则，退出时自动清理） |
| Go 实现方式 | `golang.org/x/sys/unix`: `AF_NETLINK`，`NETLINK_NETFILTER`，`NFNL_SUBSYS_ULOG` |

#### nftables trace（备选，iptables-nft 环境优化）

| 属性 | 说明 |
|------|------|
| 工作原理 | 在 nftables 规则中添加 `meta nftrace set 1` → 监听 netlink `NFNL_SUBSYS_NFTABLES` 事件 |
| 兼容性 | 仅限 iptables-nft 或纯 nftables 环境（内核 4.13+，推荐 5.0+） |
| 优势 | 非侵入性（无需注入规则） |
| Go 实现方式 | 同 xt_TRACE，通过 `unix.NETLINK_NETFILTER` 读取不同子系统消息 |

#### eBPF kprobes（否决）

| 属性 | 说明 |
|------|------|
| 否决原因 | 内核版本要求高（5.8+），实现复杂度为 xt_TRACE 的 3 倍，收益边际（xt_TRACE 已解决问题） |

### 实现注意事项

- 工具启动时需检测 `xt_LOG` 模块是否已加载，未加载时以明确错误 + 修复建议退出（满足 FR-008）
- 追踪规则注入/清理使用 defer 模式确保异常退出时也能清理（确保 FR-007 只读语义在正常流程外也成立）
- NFLOG 消息解析需处理 `NFULA_PREFIX`（规则位置标识）+ `NFULA_PACKET_HDR`（报文五元组）

---

## R-03: 依赖最小化策略（stdlib-first）

**背景**: 用户要求尽可能减少外部依赖和代码量。

### 决策

**选择：stdlib-first，单一外部依赖 `golang.org/x/sys`**

### 各层选型

| 层次 | 选择 | 否决备选 |
|------|------|---------|
| CLI 参数解析 | stdlib `flag`（每个子命令独立 FlagSet） | cobra（~20KB 二进制膨胀，本项目子命令数量不值得） |
| JSON 输出 | stdlib `encoding/json` | goccy/go-json（CLI I/O 场景无性能意义） |
| 表格输出 | stdlib `text/tabwriter` | tablewriter（依赖冗余）、lipgloss（样式过度） |
| 子进程调用 | stdlib `os/exec` | 无备选 |
| Netlink socket | `golang.org/x/sys/unix` | mdlayher/netlink（抽象层过重），vishvananda/netlink（功能超出需求） |
| 单元测试断言 | stdlib `testing`（table-driven） | testify/assert（便利语法不值得引入依赖） |

### 外部依赖清单（最终）

| 包 | 版本策略 | 用途 | 维护方 |
|----|---------|------|--------|
| `golang.org/x/sys` | 最新稳定版 | netlink socket 原生 syscall | Go 官方团队 |

**总外部依赖数：1**

### 理由

- `golang.org/x/sys` 是 Go 官方 `x/` 仓库，与语言版本同步维护，视同准标准库
- `flag` 对 3 个子命令结构完全够用（each ~5-8 flags）
- iptables-save 格式为稳定文本协议，无需专用解析库
- 预估核心代码量：~1500–2000 行（不含测试）

---

## 决策汇总

| 决策 | 选择 | 关键约束 |
|------|------|---------|
| 语言策略 | 纯 Go，Zero CGo | 不引入 C 工具链依赖 |
| 在线追踪机制 | xt_TRACE + NFLOG（主），nft trace（备） | 内核模块前置检测必须实现 |
| 依赖策略 | stdlib-first，单一外部包 `golang.org/x/sys` | 新依赖须说明许可、维护状态与收益 |
| 规则读取 | exec + 文本/JSON 解析 | 兼容 legacy/nft/firewalld 三后端 |
| CLI 框架 | stdlib `flag` | 3 子命令规模不需要 cobra |
