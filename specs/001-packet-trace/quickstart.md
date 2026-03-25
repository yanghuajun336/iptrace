# Quickstart: iptrace

**Feature**: 001-packet-trace  
**Audience**: Linux 系统管理员、网络工程师、运维开发人员  
**Last Updated**: 2026-03-25

---

## 前置条件

| 要求 | 说明 |
|------|------|
| 操作系统 | Linux（支持 Netfilter 的内核，≥ 3.13） |
| iptables 后端 | iptables-legacy、iptables-nft 或 firewalld（三选一） |
| 权限 | 离线推演（`check`）无需 root；在线追踪（`trace`）需要 root 或 `CAP_NET_ADMIN` |
| 在线追踪内核模块 | `xt_LOG`、`nf_log_ipv4`（工具启动时自动检测，缺失会提示加载命令） |

---

## 安装

```bash
# 从源码构建（Go 1.21+ 必须）
git clone https://github.com/your-org/xtables/iptrace
cd iptrace
go build -o iptrace ./cmd/iptrace
sudo cp iptrace /usr/local/bin/
```

---

## 使用场景 1：离线推演（无需 root）

**问题**：某台服务器的 iptables 规则较多，你想知道一个来自 `1.2.3.4`、目标端口 `8080` 的 TCP 报文会被哪条规则处理。

### 步骤 1：导出当前规则快照

```bash
sudo iptrace export --output snapshot.rules
# Exported 47 rules from iptables-legacy to snapshot.rules
```

### 步骤 2：执行离线推演

```bash
iptrace check \
  --src 1.2.3.4 \
  --dst 10.0.0.1 \
  --proto tcp \
  --sport 12345 \
  --dport 8080 \
  --rules-file snapshot.rules
```

**输出示例**：

```
Backend:    iptables-legacy
Packet:     tcp 1.2.3.4:12345 → 10.0.0.1:8080

Step  Hook      Table   Chain   Rule  Action
----  --------  ------  ------  ----  ------
  1   INPUT     filter  INPUT   3     DROP (matched)

Verdict: DROP
  Matched rule: filter INPUT rule 3
  Rule text:    -A INPUT -s 1.2.3.4 -p tcp --dport 8080 -j DROP
```

### 获取 JSON 输出

```bash
iptrace check --src 1.2.3.4 --dst 10.0.0.1 --proto tcp --sport 12345 --dport 8080 \
  --rules-file snapshot.rules --format json | jq .verdict
# "DROP"
```

---

## 使用场景 2：在线实时追踪（需 root）

**问题**：你想实时观察某个连接的报文在内核 Netfilter 链路上的完整路径。

```bash
sudo iptrace trace --src 1.2.3.4 --proto tcp --dport 80
```

**输出示例（流式）**：

```
[15:04:05.001] PREROUTING  raw      PREROUTING  rule -   CONTINUE (policy ACCEPT)
[15:04:05.002] INPUT       filter   INPUT       rule 5   DROP ← VERDICT
```

按 `Ctrl+C` 停止追踪。工具退出后自动清理临时注入的追踪规则。

---

## 使用场景 3：规则快照导出用于脚本

```bash
# 以 JSON 格式导出导出摘要
sudo iptrace export --output /tmp/fw-snapshot.rules --format json
# {"status":"ok","backend":"iptables-legacy","rule_count":47,"output_file":"/tmp/fw-snapshot.rules"}

# 后续可将 snapshot.rules 传到其他机器离线分析
scp /tmp/fw-snapshot.rules analyst@10.0.0.5:~/
```

---

## 错误处理参考

| 场景 | 退出码 | 提示示例 |
|------|--------|---------|
| 参数缺失 | 1 | `error: --dst is required for 'check' subcommand` |
| 权限不足 | 2 | `error: 'trace' requires root; try: sudo iptrace trace ...` |
| 内核模块缺失 | 2 | `error: kernel module xt_LOG not loaded; run: sudo modprobe xt_LOG` |
| 规则文件不存在 | 2 | `error: rules file 'snapshot.rules' not found` |
| 后端检测失败 | 2 | `error: no supported firewall backend detected (iptables-legacy/nft/firewalld)` |

---

## 常见问题

**Q: 离线推演结论和实际防火墙行为不一致？**  
A: 确认规则快照是否是当前状态，重新执行 `iptrace export` 后再次推演。

**Q: `trace` 命令退出后规则残留？**  
A: iptrace 在退出时（包括 `Ctrl+C`）自动清理所有临时注入的追踪规则。如异常崩溃，可运行 `sudo iptables -t raw -L` 手动检查并删除含 `iptrace-trace` 注释的规则。

**Q: firewalld 环境下 `check` 命令不工作？**  
A: 确保已执行 `iptrace export`，firewalld 的规则通过 export 命令转换为 iptables-save 格式。
