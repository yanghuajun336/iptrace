# ADR 0001: 在线追踪机制采用 xt_TRACE + NFLOG（nft trace 作为后续补充）

- **Status**: Accepted
- **Date**: 2026-03-26

## Context

`iptrace` 需要在在线模式下满足以下要求：

1. 能实时输出报文经过 Netfilter 钩子点与命中规则路径（FR-004、FR-011）；
2. 首条输出时延不超过 3 秒（SC-003）；
3. 支持 iptables-legacy、iptables-nft 与 firewalld 生态（FR-010）；
4. 保持实现简洁并控制依赖数量（宪章 I、III，研究 R-03）。

候选方案包括：

- `xt_TRACE + NFLOG`
- `nft trace`
- eBPF/kprobe 方案

## Decision

采用 **`xt_TRACE + NFLOG` 作为当前主方案**，并将 **`nft trace` 作为后续在 nft 环境下的增强路线**。

实现落点：

- 在线会话入口位于 `internal/tracer/session.go`；
- 事件解码位于 `internal/tracer/nflog_decode.go`；
- 规则注入/清理接口位于 `internal/tracer/xt_trace.go`；
- CLI 入口位于 `cmd/iptrace/trace.go`。

eBPF/kprobe 不纳入当前实现范围。

## Consequences

### Positive

- 与当前 Linux 发行版和 iptables 生态兼容度高；
- 可用 Go + `golang.org/x/sys/unix` 直接实现，避免 CGo 复杂度；
- 与现有 CLI 与输出模型耦合低，便于继续演进。

### Negative

- 对内核模块与运行权限有明确前置条件（root/CAP_NET_ADMIN）；
- 追踪注入/清理流程需要额外鲁棒性保障（异常退出清理）。

### Follow-up

1. 在 nft 场景补充 `nft trace` 分支以降低注入侵入性；
2. 增加更接近生产的长时基准，覆盖 CPU/内存曲线采样；
3. 在 CLI 文档中持续同步模块依赖与故障排查指引；
4. 基于 `test/integration/sc007_longrun.sh` 在真实内核环境完成 600 秒基线复测并归档结果。
