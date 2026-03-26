# iptrace CLI 参考

## 命令总览

```text
iptrace <subcommand> [flags]

subcommand:
  check   离线推演报文路径
  trace   在线追踪报文路径
  export  导出规则快照
```

退出码约定：

- `0`：成功
- `1`：输入错误
- `2`：环境错误
- `3`：内部错误

---

## `iptrace check`

用途：根据规则快照离线推演五元组报文路径与最终判决。

常用参数：

- `--src`、`--dst`、`--proto`
- `--dport`（tcp/udp 场景必须；源端口可选，不指定则视为任意源端口）
- `--rules-file`
- `--format human|json`

示例：

```bash
iptrace check --src 1.2.3.4 --dst 10.0.0.1 --proto tcp --dport 8080 --rules-file snapshot.rules
```

---

## `iptrace trace`

用途：在线输出报文经过 Netfilter 路径的实时步骤。

常用参数：

- `--src`、`--dst`、`--proto`、`--sport`、`--dport`
- `--timeout`（默认 `0`，永不超时；按 Ctrl+C 停止）
- `--verbose` / `-v`（详细模式：输出每报文完整路径块，含 `══ Packet #N ══` 边框；默认简洁模式：每报文仅输出最终判决一行）
- `--format human|json`

输出模式说明：

- **简洁模式**（默认）：每报文一行，格式 `[HH:MM:SS.mmm] <verdict>  <table/chain>  rule#<n>`，聚焦到实际判决点；DROP/REJECT 时追加一行 `  └─ <nft 规则原文>`。
- **详细模式**（`-v`）：每报文以 `══ Packet #N  id=0x...  src:port → dst:port proto ══` 为头、`────` 为尾包围完整路径，判决行以 `▶` 标记，命中规则下方同样追加 `      └─ <nft 规则原文>`。

其他说明：

- 默认需要 root/CAP_NET_ADMIN；
- 支持测试模式环境变量 `IPTRACE_TEST_MODE=1` 用于受控验证。

示例：

```bash
# 简洁模式（默认，Ctrl+C 停止）
sudo iptrace trace --src 1.2.3.4 --proto tcp --dport 80

# 详细模式，含完整路径
sudo iptrace trace --src 1.2.3.4 --proto tcp --dport 80 --verbose

# 30 秒超时
sudo iptrace trace --src 1.2.3.4 --proto tcp --dport 80 --timeout 30s
```

---

## `iptrace export`

用途：导出当前规则快照，供 `check` 复用。

常用参数：

- `--output`
- `--format human|json`

示例：

```bash
iptrace export --output snapshot.rules
iptrace export --output snapshot.rules --format json
```

JSON 摘要字段：

- `status`
- `backend`
- `rule_count`
- `output_file`

---

## 输出一致性原则

human 与 JSON 在语义上保持一致：

- 判决语义一致（`Verdict` ↔ `verdict`）
- 路径语义一致（hook/table/chain/rule/action）
- 错误语义一致（错误原因 + 可执行 hint）

---

## 常见错误与建议

- 缺少 `--rules-file`：补全规则文件路径。
- 缺少 `--output`：补全导出目标文件。
- 非 root 执行 `trace`：使用 `sudo` 或授予能力。
- `--format` 非法：改为 `human` 或 `json`。
