# iptrace

`iptrace` 是一个面向 Linux 的防火墙报文诊断 CLI，用于帮助运维人员定位：

- 某个报文会命中哪条 `iptables` / `firewalld` 规则；
- 报文在在线追踪模式下经过哪些 Netfilter 钩子点；
- 当前规则快照如何导出并用于离线复现。

## 主要能力

- `check`：基于规则快照执行离线推演；
- `trace`：在线追踪报文路径；
- `export`：导出当前规则快照供后续分析。

## 环境要求

- Linux
- Go 1.21+
- 在线追踪模式需要 root 或 `CAP_NET_ADMIN`

## 构建步骤

### 方式一：直接使用 Go

```bash
go build -o iptrace ./cmd/iptrace
```

### 方式二：使用 Makefile

```bash
make build
```

默认会在仓库根目录生成二进制：`./iptrace`。

## 测试步骤

```bash
make test
```

或：

```bash
go test ./...
```

## 常用命令

### 1. 离线推演

```bash
./iptrace check \
	--src 1.2.3.4 \
	--dst 10.0.0.1 \
	--proto tcp \
	--dport 8080 \
	--rules-file ./test/fixtures/rules/drop_8080.rules
```

`--sport` 为可选参数，省略时匹配任意源端口。

### 2. 在线追踪

```bash
# 简洁模式（默认）：每报文一行，显示最终判决与命中规则；Ctrl+C 停止
sudo ./iptrace trace --src 1.2.3.4 --proto tcp --dport 80

# 详细模式：显示完整 Netfilter 路径，相邻报文有清晰边界
sudo ./iptrace trace --src 1.2.3.4 --proto tcp --dport 80 --verbose
```

说明：`trace` 允许临时注入追踪规则，但会在退出、超时或中断后自动清理。默认无超时（永久运行），可用 `--timeout 30s` 指定超时时长。

### 3. 导出规则快照

```bash
./iptrace export --output snapshot.rules
```

## 性能与验收

- 全量测试报告：`test/integration/test-report.txt`
- SC-001 验收报告：`test/integration/sc001-report.txt`
- SC-007 长时验收脚本：`test/integration/sc007_longrun.sh`

真实环境长时基线建议执行：

```bash
USE_TEST_MODE=0 DURATION_SEC=600 ./test/integration/sc007_longrun.sh
```

## 文档索引

- 架构总览：`docs/architecture/iptrace-overview.md`
- CLI 参考：`docs/reference/iptrace-cli.md`
- 性能基线：`docs/performance/iptrace-baseline.md`
- TDD 可追溯矩阵：`docs/quality/tdd-traceability.md`
- ADR：`docs/adr/`
