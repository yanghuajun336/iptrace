# Linux Kernel Packet Tracing Mechanisms for iptrace

**Research Date**: 2026-03-25  
**Tool**: iptrace (iptables/netfilter debugging)  
**Scope**: Real-time packet tracing at Netfilter hook points  
**Language**: Go (primary), C permitted for kernel coupling  

---

## 1. xt_TRACE Target + NFLOG

### 1.1 How xt_TRACE Works

**Mechanism Overview**:
- `xt_TRACE` is a kernel module (built-in or loadable) that acts as a logging target for iptables rules
- When a rule has `-j TRACE`, the kernel logs the packet traversal to the netfilter logging subsystem (`nf_log`)
- Unlike `-j LOG`, which logs at the application layer, `xt_TRACE` logs **inside the kernel's rule evaluation loop**, capturing every rule comparison attempt (matched or not)
- The kernel hooks into netfilter's internal `nf_log_packet()` function with a dedicated callback

**Key Technical Details**:
- Located in kernel source: `net/netfilter/xt_LOG.c` (both LOG and TRACE targets)
- Logs are written to the kernel's ring buffer and exported via:
  - **Dmesg/printk**: Traditional kernel log (readable via `/proc/sys/kernel/printk` and `dmesg` command)
  - **NFLOG netlink**: Modern approach via `NETLINK_NETFILTER` family
- Each trace entry includes:
  - Hook point (PREROUTING, INPUT, FORWARD, OUTPUT, POSTROUTING)
  - Table name (filter, nat, mangle, raw, security)
  - Chain name (INPUT, FORWARD, OUTPUT, or custom)
  - Rule number (position in chain)
  - Whether packet matched the rule
  - Target/action (ACCEPT, DROP, JUMP chain name, etc.)

**Kernel Module Dependencies**:
```
Requires:
- xt_LOG module (provides both LOG and TRACE)
  Depends on: netfilter_ipv4, netfilter_core, x_tables
- nf_log_ipv4 module (registers IPv4 handler for nf_log)
- nf_log module (provides the logging infrastructure)

Typically auto-loaded when first TRACE rule is loaded,
but may need explicit modprobe in minimal kernel builds.
```

### 1.2 Reading TRACE Logs via NFLOG

**NFLOG Socket Method (Preferred)**:
- **Protocol**: AF_NETLINK, NETLINK_NETFILTER family
- **Mechanism**: User-space opens a netlink socket and binds to a specific netlink group
- Kernel writes trace logs to the bound group; userspace receives via `recvmsg()`
- **Group ID**: Configurable via iptables `-j NFLOG --nflog-group N` parameter (default: 0, copied to group 100)
- **Delivery**: Asynchronous; kernel buffers up to a max number of log entries before dropping

**Reading from `/proc/net/nf_log`**:
- Shows which protocol families have logging handlers registered
- Does NOT show log entries themselves—only registration status
- Example output:
  ```
  ipv4 NFLOG
  ipv6 NFLOG
  ```
- Not suitable for reading actual trace output

**Via Dmesg/syslog**:
- Older systems without NFLOG support
- Kernel logs are buffered in ring buffer and appear in `dmesg` output
- Less reliable for high-throughput scenarios (logs can be dropped)
- Requires parsing unstructured text output

### 1.3 Workflow: User's Perspective

```
User runs: iptrace trace --filter "src 1.2.3.4 dport 80"
                        ↓
iptrace (Go) checks kernel capabilities + loads xt_TRACE if needed
                        ↓
iptrace temporarily adds NFLOG rule to EVERY netfilter hook/table:
  - For each hook (PREROUTING, INPUT, FORWARD, OUTPUT, POSTROUTING)
  - For each table (raw, mangle, filter, nat)
  - Insert at position 1: -A <chain> -p tcp --dport 80 -s 1.2.3.4 -j NFLOG --nflog-group 100
                        ↓
iptrace opens AF_NETLINK socket, binds to group 100
                        ↓
Packet arrives matching filter; kernel traces it through all rules
  - For each rule in path: writes NFLOG message to group 100
                        ↓
iptrace receives messages via recvmsg(), parses, outputs in real-time
                        ↓
User exits (Ctrl+C); iptrace removes temporarily added rules, closes socket
```

**Does it require modifying user's iptables rules?**: **YES, temporarily**
- The TRACE target must be inserted into actual iptables rules or a temporary NFLOG rule must be added
- iptrace would need to:
  1. Back up existing rules (optional, for safety)
  2. Insert TRACE/NFLOG rules at strategic points
  3. Restore rules after tracing (critical to avoid leaving debugging rules in production)
- This is intrusive and carries risk if the tool crashes before cleanup

### 1.4 Pros & Cons

**Pros**:
- ✅ Native kernel mechanism—highly detailed, captures every rule evaluation
- ✅ Works with both iptables-legacy and iptables-nft backends (both feed netfilter)
- ✅ NFLOG socket is reliable and well-documented
- ✅ No external dependencies beyond kernel modules (already present in most systems)
- ✅ Low kernel overhead when TRACE is active

**Cons**:
- ❌ Requires modifying user's iptables rules (temporary insertion of TRACE rules)
- ❌ Requires root privilege
- ❌ If tool crashes, may leave debugging rules behind (cleanup required)
- ❌ Must parse kernel netlink messages (complex struct definitions)
- ❌ Rules modification means all rules must be temporarily updated; cannot selectively trace single chain
- ❌ High-traffic scenarios: kernel NFLOG buffer can overflow, dropping log entries
- ❌ Parsing NFLOG netlink format requires CGo or pure netlink implementation in Go

---

## 2. nftables Trace (`nft monitor trace`)

### 2.1 How nftables Trace Works

**Mechanism Overview**:
- `nft monitor trace` is a **debugging mode** built into nftables that outputs real-time tracing without modifying rules
- When enabled, **every** rule evaluation (match, action) is logged to a dedicated netlink group (`NFNL_SUBSYS_NFTABLES`)
- The trace output includes the exact same information as xt_TRACE: hook, table, chain, rule, match result, action

**Key Technical Details**:
- Enabled via: `nft monitor trace` (listening mode) + `sysctl net.netfilter.nf_tables_trace=1` (enable kernel tracing)
- Kernel source: `net/netfilter/nf_tables_core.c`, `net/netfilter/nf_tables_trace.c`
- Trace delivery mechanism:
  - Kernel writes trace events to `NFNL_SUBSYS_NFTABLES` netlink group
  - Includes: hook, chain, rule content, verdict, packet info
- **Critical advantage**: Does NOT require modifying rules; tracing is orthogonal to rule configuration
- Native output is human-readable multiline format (when viewed via `nft` CLI)

**Example nft Trace Output**:
```
trace id 3f8e3da5 inet filter input packet: iif "eth0" oif unset proto ip 1.2.3.4 -> 10.0.0.1 tcp dport 80
  [ payload load 4b @ network header + 12 => reg 1 ]
  [ cmp eq reg 1 0x04030201 ]
  [ immediate reg 0 set 0x00000000 ] -- rule 1: ip saddr 1.2.3.4 counter packets 1 bytes 60 drop
  [ verdict reg 0 set drop ]
```

### 2.2 Kernel Version & Backend Requirements

**Kernel Version**:
- nftables trace support: Linux **4.13+** (introduced nf_tables_trace infrastructure)
- Reliable trace output: Linux **5.0+** (fixes to netlink message handling)
- **Recommended**: 5.10+ for production use

**Backend Requirement**:
- nftables kernel support: `CONFIG_NF_TABLES=y` (or =m)
- If system uses **iptables-legacy backend only**, nftables kernel modules may not be loaded
- If system uses **iptables-nft backend**, nftables support is guaranteed to be present

**Compatibility with iptables-legacy**:
- ❌ **Cannot** use `nft monitor trace` when the system is purely iptables-legacy
- iptables-legacy rules bypass the nftables kernel layer entirely
- However, iptables-legacy rules can be translated to nftables rules for tracing purposes
- Workaround: Use `iptables-translate` tool to convert legacy rules to nftables, then trace; NOT practical for real-time tracing

### 2.3 Workflow: User's Perspective

```
User runs: iptrace trace --filter "src 1.2.3.4 dport 80"
                        ↓
iptrace detects backend (iptables-legacy or iptables-nft)
                        ↓
If iptables-legacy:
  → Output error: "nftables trace unavailable on iptables-legacy system"
  → Suggest fallback: xt_TRACE + NFLOG or offline mode
                        ↓
If iptables-nft (or both):
  → Enable kernel tracing: sysctl net.netfilter.nf_tables_trace=1
  → Open netlink socket, bind to NFNL_SUBSYS_NFTABLES group
  → (Optional) Inject temporary rules to filter output by source IP
                        ↓
Packet arrives; kernel evaluates all rules in nftables layer
  → For each rule: emit trace event to netlink group
                        ↓
iptrace receives netlink messages, parses trace events, outputs in real-time
                        ↓
User exits; iptrace disables tracing (sysctl net.netfilter.nf_tables_trace=0)
```

### 2.4 Reading Trace from Go

**Netlink Socket Approach** (preferred):
- Library: [`github.com/mdlayher/netlink`](https://pkg.go.dev/github.com/mdlayher/netlink) + [`github.com/mdlayher/netfilter`](https://pkg.go.dev/github.com/mdlayher/netfilter) (pure Go)
- Bind to netfilter family, subscribe to trace subsystem messages
- Parse TLV (Type-Length-Value) encoded trace events
- Example:
  ```go
  conn, _ := netlink.Dial(unix.NETLINK_NETFILTER, nil)
  // Subscribe to trace group
  // Listen for NFNL_SUBSYS_NFTABLES messages
  // Parse trace records
  ```

**Alternative: Exec `nft monitor trace`**:
- Simpler implementation: spawn `nft` subprocess and parse its text output
- Cons: Spawning subprocess overhead, text parsing fragile, not guaranteed across nftables versions

### 2.5 Pros & Cons

**Pros**:
- ✅ No rule modification required—completely non-intrusive
- ✅ Detailed trace output, captures every rule evaluation
- ✅ Native support for iptables-nft backend (modern systems trending toward nft)
- ✅ Clean netlink protocol, well-documented API
- ✅ Pure Go libraries available (`mdlayher/netfilter`)
- ✅ Kernel overhead minimal when tracing is enabled

**Cons**:
- ❌ **Unavailable on iptables-legacy–only systems** (no nftables kernel layer)
- ❌ Requires sysctl write privilege (`net.netfilter.nf_tables_trace=1`)
- ❌ Kernel 4.13+, recommended 5.10+ (may not work on older systems)
- ❌ Requires nftables kernel module to be loaded (may need explicit modprobe)
- ❌ Trace output is raw netlink format (complex TLV parsing required)
- ❌ Cannot easily filter by packet properties (filter rule must be injected into nftables)

---

## 3. perf/eBPF/ftrace

### 3.1 eBPF Kprobes on Netfilter Functions

**Mechanism Overview**:
- Attach eBPF kprobes to key netfilter functions:
  - `ip_do_table()` (iptables-legacy rule evaluation)
  - `nft_do_chain()` (nftables rule evaluation)
  - `ipt_do_table()` (IPv4 specific variant)
- eBPF kprobe fires on function entry/exit, captures register values (packet info, rule matches)
- Kernel exposes kprobe data via perf event buffer or eBPF ring buffers
- Userspace reads via `/sys/kernel/debug/tracing` or perf tool

**Kernel Requirements**:
- CONFIG_KPROBES=y (enabled in most modern kernels)
- CONFIG_BPF=y, CONFIG_BPF_SYSCALL=y (ubiquitous in 5.0+)
- Dynamic kprobes available (default in 5.0+)

**Example eBPF Kprobe**:
```c
BPF_PERF_OUTPUT(trace_events);

KPROBE_RETURN(ip_do_table, int ret) {
    struct trace_event event = {};
    event.verdict = ret;  // Captured from return value
    event.timestamp = bpf_ktime_get_ns();
    trace_events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}
```

### 3.2 Pros & Cons

**Pros**:
- ✅ No rule modification; completely non-intrusive
- ✅ Works with both iptables-legacy and iptables-nft (kprobes on both layers)
- ✅ Can attach arbitrary logic (filter, sample, aggregate packets)
- ✅ High performance potential (in-kernel execution)
- ✅ Modern systems (5.0+) have stable eBPF support

**Cons**:
- ❌ **Significantly more complex** than xt_TRACE or nft trace
- ❌ Requires deep kernel internals knowledge (function signatures, register conventions)
- ❌ Kprobe attachment is fragile—function names/signatures change across kernel versions
- ❌ Must use libbpf (C + some boilerplate) or higher-level tools (bcc)
- ❌ Go tooling for eBPF is immature (cilium/ebpf library available but complex)
- ❌ Hard to capture full rule context (function signature not part of rule metadata)
- ❌ Requires kernel >= 5.0 with CONFIG_DEBUG_INFO=y for kprobes (vmlinux-BTF)
- ❌ Error handling and version compatibility is tedious
- ❌ Cannot reliably capture rule text or chain names without significant reverse engineering
- ❌ Unrelated rule matches (on other interfaces, tables) are difficult to filter in kernel

**Conclusion**: Overkill for iptrace's use case; xt_TRACE and nft trace provide the necessary detail with far less complexity.

---

## 4. Reading NFLOG from Go

### 4.1 Pure Go Approach via `github.com/mdlayher/netlink`

**Architecture**:
```
Go Application
    ↓
github.com/mdlayher/netlink (pure Go netlink transport)
    ↓
AF_NETLINK socket (kernel interface)
    ↓
Kernel NFLOG subsystem (nf_log)
    ↓
xt_LOG/xt_TRACE targets (log outputs)
```

**Implementation Steps**:

1. **Open Netlink Socket**:
   ```go
   conn, err := netlink.Dial(unix.NETLINK_NETFILTER, nil)
   ```

2. **Subscribe to NFLOG Group**:
   ```go
   // NFLOG uses multicast group mechanism
   // Bind to group 100 (default or custom via iptables rule)
   conn.JoinGroup(100)
   ```

3. **Receive & Parse Messages**:
   ```go
   // Receive raw netlink message
   messages, err := conn.Receive()
   
   // Parse NFLOG TLV format (Type-Length-Value)
   // Extract: timestamp, payload, source IP, dest IP, protocol, ports, etc.
   ```

4. **Decode NFLOG Payload**:
   - NFLOG messages contain packet data in structured format
   - Use kernel header definitions (already in `unix` package) or write custom decoder
   - Fields: NF_INET_LOCAL_IN hook, IP header, TCP/UDP header, etc.

**Code Skeleton** (conceptual):
```go
package main

import (
    "fmt"
    "golang.org/x/sys/unix"
    "github.com/mdlayher/netlink"
)

func main() {
    // 1. Open netlink socket
    conn, err := netlink.Dial(unix.NETLINK_NETFILTER, nil)
    if err != nil { /* handle */ }
    defer conn.Close()
    
    // 2. Join multicast group 100
    if err := conn.JoinGroup(100); err != nil { /* handle */ }
    
    // 3. Receive & parse loop
    for {
        messages, err := conn.Receive()
        if err != nil { /* handle */ }
        
        for _, msg := range messages {
            // Parse NFLOG TLV attributes
            // Extract packet info, rule info
            fmt.Println("Packet traced:", msg)
        }
    }
}
```

### 4.2 CGo Approach via libnfnetlink + libnetfilter_log

**Architecture**:
```
Go Application
    ↓
CGo binding (unsafe C calls)
    ↓
libnfnetlink (C library, NFLOG socket abstraction)
    ↓
libnetfilter_log (C library, NFLOG message parsing)
    ↓
AF_NETLINK socket (kernel)
```

**Libraries**:
- **libnfnetlink**: Low-level netlink transport for netfilter
- **libnetfilter_log**: Higher-level NFLOG message parsing; provides callback-based API

**Advantages**:
- ✅ Easier message parsing (libnfnetlink handles struct definitions)
- ✅ Handles protocol nuances automatically
- ✅ Well-tested in userspace netfilter tools (ulogd, conntrack, etc.)

**Disadvantages**:
- ❌ Requires C dependencies (dev packages: `libnetfilter-log-dev`, `libnfnetlink-dev`)
- ❌ CGo introduces overhead and complexity
- ❌ Harder to deploy (C libraries must be present on target system)
- ❌ Violates stated goal: "Minimize dependencies"

### 4.3 Comparison: Pure Go vs CGo

| Aspect | Pure Go | CGo |
|--------|---------|-----|
| **Dependencies** | None (stdlib only) | libnfnetlink, libnetfilter_log |
| **Deployment** | Single binary | Binary + .so files |
| **Performance** | Slightly slower | Slightly faster |
| **Complexity** | Moderate (TLV parsing) | Lower (C lib handles it) |
| **Portability** | High (Go guarantees) | Low (libc dependent) |
| **Maintenance** | Easier | Need C API knowledge |

**Recommendation**: **Pure Go approach** aligns with iptrace's stated goal to "minimize dependencies."

---

## 5. Comprehensive Decision Matrix

| Mechanism | Works Legacy | Works NF | Non-Intrusive | Pure Go | Maturity | Kernel Ver | Complexity |
|-----------|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| xt_TRACE+NFLOG | ✅ | ✅ | ❌ (modifies rules) | ✅ | ⭐⭐⭐⭐ | 3.0+ | Medium |
| nft trace | ❌ | ✅ | ✅ | ✅ | ⭐⭐⭐ | 4.13+ (5.0+ rec) | Medium |
| eBPF kprobes | ✅ | ✅ | ✅ | ❌ (libbpf) | ⭐⭐⭐ | 5.0+ | High |

---

## FINAL DECISION & RECOMMENDATION

### **Decision: Hybrid Approach (Recommended)**

**Primary Mechanism**: **xt_TRACE + NFLOG (Pure Go)**  
**Fallback Mechanism**: **nft monitor trace (when nftables available)**  
**Excluded**: eBPF kprobes (too complex, marginal benefit)

---

## 6. Implementation Architecture

### 6.1 Core Implementation Design

```
iptrace/
├── pkg/
│   ├── backend/
│   │   ├── detector.go      # Detect iptables-legacy vs iptables-nft
│   │   ├── legacy.go        # iptables-legacy backend interface
│   │   └── nft.go           # iptables-nft backend interface
│   ├── trace/
│   │   ├── xt_trace.go      # xt_TRACE + NFLOG implementation
│   │   │                    # - Add temp NFLOG rules
│   │   │                    # - Parse NFLOG netlink messages
│   │   │                    # - Cleanup on exit
│   │   ├── nft_trace.go     # nft monitor trace implementation
│   │   │                    # - Enable sysctl trace
│   │   │                    # - Parse nftables trace events
│   │   │                    # - Cleanup on exit
│   │   └── common.go        # Common interfaces (TraceStep, TraceResult)
│   ├── netlink/
│   │   └── nflog.go         # NFLOG socket handling (AF_NETLINK)
│   │                        # - Pure Go netlink transport
│   │                        # - TLV parsing for NFLOG format
│   └── offline/
│       └── simulator.go     # Offline rule traversal (P1 feature)
└── cmd/
    └── iptrace/
        └── main.go
```

### 6.2 Selection Logic at Runtime

```go
// Pseudo-code
func SelectTraceBackend(system *SystemInfo) TraceBackend {
    if system.IsIPTablesNFT() {
        // Try nft trace first (non-intrusive, modern)
        if system.CanUseSysctl() && system.HasNFTablesKernel() {
            return NewNftTraceBackend()
        }
    }
    
    // Fallback: xt_TRACE + NFLOG (works everywhere)
    if system.CanLoadModules() && system.HasRoot() {
        return NewXtTraceBackend()
    }
    
    // Offline only (no root, no kernel support)
    return NewOfflineBackend()
}
```

### 6.3 Detailed Implementation: xt_TRACE + NFLOG

#### Step 1: Module Loading
```go
func (b *XtTraceBackend) EnsureModules() error {
    modules := []string{"xt_LOG", "nf_log_ipv4", "nf_log"}
    for _, mod := range modules {
        // Check if loaded
        if !isModuleLoaded(mod) {
            // Attempt modprobe (requires root)
            if err := exec.Command("modprobe", mod).Run(); err != nil {
                return fmt.Errorf("failed to load %s: %w", mod, err)
            }
        }
    }
    return nil
}
```

#### Step 2: Temporary Rule Injection
```go
func (b *XtTraceBackend) InjectNFLOGRules(filter *PacketFilter) error {
    // Add rules to each relevant chain
    chains := []string{"PREROUTING", "INPUT", "FORWARD", "OUTPUT", "POSTROUTING"}
    
    for _, chain := range chains {
        // Example: iptables -t filter -I INPUT 1 -p tcp --dport 80 -s 1.2.3.4 -j NFLOG --nflog-group 100
        iptablesCmd := []string{
            "-t", "filter", "-I", chain, "1",
            "-p", filter.Proto,
            "--dport", strconv.Itoa(filter.DPort),
            "-s", filter.SrcIP,
            "-j", "NFLOG", "--nflog-group", "100",
        }
        if err := iptables.Append(iptablesCmd...); err != nil {
            return err
        }
    }
    return nil
}
```

#### Step 3: NFLOG Netlink Socket Handling
```go
func (b *XtTraceBackend) OpenNFLOGSocket() (net.Conn, error) {
    // Open netlink socket for NETLINK_NETFILTER
    fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_NETFILTER)
    if err != nil {
        return nil, err
    }
    
    // Bind to netlink socket with multicast group 100
    nlAddr := &unix.SockaddrNetlink{
        Family: unix.AF_NETLINK,
        Groups: 1 << (100 - 1), // Group bitmask for group 100
    }
    if err := unix.Bind(fd, nlAddr); err != nil {
        return nil, err
    }
    
    return os.NewFile(uintptr(fd), "nflog"), nil
}
```

#### Step 4: NFLOG Message Parsing (TLV Decoding)
```go
// NFLOG Netlink Header + Attributes (TLV format)
type NFLOGMessage struct {
    Timestamp  time.Time
    HookPoint  string    // "INPUT", "FORWARD", etc.
    TableName  string    // "filter", "nat", etc.
    ChainName  string    // User-defined or built-in chain
    RuleNum    int       // Rule position in chain
    RuleText   string    // Original rule text
    Verdict    string    // "ACCEPT", "DROP", etc.
    SrcIP      string
    DstIP      string
    Protocol   string
    SrcPort    int
    DstPort    int
}

func ParseNFLOGAttribute(attr []byte) (NFLOGMessage, error) {
    // Decode TLV-encoded netlink message
    // Reference: kernel include/uapi/netfilter/nfnetlink_log.h
    msg := NFLOGMessage{}
    
    // Iterate over TLV attributes
    for len(attr) >= 4 {
        nlaLen := binary.LittleEndian.Uint16(attr[0:2])
        nlaType := binary.LittleEndian.Uint16(attr[2:4])
        
        payload := attr[4 : 4+nlaLen-4]
        
        switch nlaType {
        case NFULA_TIMESTAMP:
            // Parse timestamp
        case NFULA_HWTYPE, NFULA_PAYLOAD:
            // Parse payload (contains IP header, then TCP/UDP header)
            msg = parseIPPayload(payload)
        // ... other attributes
        }
        
        // Next TLV
        attr = attr[nlaLen:]
    }
    
    return msg, nil
}
```

#### Step 5: Rule Cleanup (Critical)
```go
func (b *XtTraceBackend) CleanupRules() error {
    // Must be called on exit (defer), even if tracing failed
    chains := []string{"PREROUTING", "INPUT", "FORWARD", "OUTPUT", "POSTROUTING"}
    
    for _, chain := range chains {
        // Delete the NFLOG rule we inserted (it should be at position 1)
        iptablesCmd := []string{"-t", "filter", "-D", chain, "1"}
        _ = iptables.Run(iptablesCmd...) // Ignore error if rule already gone
    }
    return nil
}

func (b *XtTraceBackend) Trace(ctx context.Context, filter *PacketFilter) {
    defer b.CleanupRules() // Ensure cleanup even on panic/error
    
    // ... actual tracing ...
}
```

### 6.4 Detailed Implementation: nft monitor trace

#### Step 1: Backend Detection
```go
func (b *NftTraceBackend) IsAvailable() bool {
    // Check 1: nftables kernel module loaded
    if _, err := os.Stat("/proc/net/nf_tables"); err != nil {
        return false // nf_tables not available
    }
    
    // Check 2: Kernel version >= 4.13 (trace support)
    version := getKernelVersion()
    if version < (4, 13, 0) {
        return false
    }
    
    // Check 3: Verify `nft` command available
    if err := exec.Command("nft", "--version").Run(); err != nil {
        return false
    }
    
    return true
}
```

#### Step 2: Enable Kernel Tracing
```go
func (b *NftTraceBackend) EnableKernelTracing() error {
    // Write 1 to sysctl net.netfilter.nf_tables_trace
    return syscall.Sysctl("net/netfilter/nf_tables_trace", "1")
    // Or via: echo 1 > /proc/sys/net/netfilter/nf_tables_trace
}

func (b *NftTraceBackend) DisableKernelTracing() error {
    return syscall.Sysctl("net/netfilter/nf_tables_trace", "0")
}
```

#### Step 3: Parse nft monitor trace Output
```go
// Option A: Parse text output from `nft monitor trace` subprocess
func (b *NftTraceBackend) ParseNftMonitorOutput(line string) (TraceStep, error) {
    // Example line:
    // "trace id 3f8e3da5 inet filter input packet: iif "eth0" oif unset proto ip 1.2.3.4 -> 10.0.0.1 tcp dport 80"
    // "  [ payload load 4b @ network header + 12 => reg 1 ]"
    // "  [ cmp eq reg 1 0x04030201 ]"
    // "  [ immediate reg 0 set 0x00000000 ] -- rule 1: ip saddr 1.2.3.4 counter packets 1 bytes 60 drop"
    
    step := TraceStep{}
    // Parse using regex or simple string matching
    // Extract: hook, table, chain, rule number, verdict
    
    return step, nil
}

// Option B: Read netlink NFNL_SUBSYS_NFTABLES messages directly (advanced)
func (b *NftTraceBackend) ReadNftTraceNetlink(ctx context.Context) {
    conn, _ := netlink.Dial(unix.NETLINK_NETFILTER, nil)
    defer conn.Close()
    
    // Bind to nftables trace group
    // Receive and parse trace event messages
}
```

#### Step 4: Cleanup
```go
func (b *NftTraceBackend) Cleanup() error {
    // Disable kernel tracing
    return b.DisableKernelTracing()
}
```

### 6.5 Common Interface

```go
// All backends implement this interface
type TraceBackend interface {
    IsAvailable() bool
    Trace(ctx context.Context, filter *PacketFilter) chan TraceStep
    Cleanup() error
}

type TraceStep struct {
    Timestamp   time.Time
    HookPoint   string    // "INPUT", "FORWARD", etc.
    TableName   string    // "filter", "nat", etc.
    ChainName   string
    RuleNum     int
    RuleText    string
    Matched     bool      // Did packet match this rule?
    Verdict     string    // "ACCEPT", "DROP", "JUMP somechain", etc.
    PacketInfo  PacketInfo
}

type TraceResult struct {
    TraceID  string
    Steps    []TraceStep
    Final    FinalVerdict // "ACCEPT", "DROP", "REJECT"
    Reason   string       // Why (rule num or default policy)
}
```

---

## 7. Decision Rationale

### **Why xt_TRACE + NFLOG as Primary?**

1. **Universal Compatibility**: Works on both iptables-legacy and iptables-nft backends
   - Legacy users are still common in older RHEL/CentOS deployments
   - iptrace must support both to maximize user base

2. **Mature & Stable**: Kernel module exists since Linux 2.4; proven in production
   - No version compatibility issues with older kernels (2.6+)
   - Battle-tested by netfilter tools (ulogd, firewalld debug mode)

3. **Predictable Information Flow**: 
   - NFLOG provides every rule evaluation (matched or not)
   - Can correlate trace events directly to user's iptables rules
   - Captures rule text as user configured it

4. **Pure Go Implementation Viable**:
   - Standard library provides netlink transport (unix package)
   - TLV parsing is straightforward
   - No external C dependencies required

### **Why nft trace as Fallback/Modern Alternative?**

1. **Non-Intrusive**: No rule modification; tracing is completely orthogonal
   - Safer for production use (no risk of leaving debugging rules)
   - No cleanup complexity

2. **Future-Proof**: iptables-nft is the future; nftables adoption is accelerating
   - On modern systems (5.10+), nftables is preferred path
   - CentOS 9, Ubuntu 22.04+, Debian 12+ default to iptables-nft

3. **Cleaner API**: Netfilter subsystem trace events are well-structured
   - Easier to parse than NFLOG format
   - Pure Go libraries available (mdlayher/netfilter)

### **Why NOT eBPF?**

1. **Overkill Complexity**: Solving 90% of the problem with 200% code complexity
   - Kprobe attachment, version-dependent function signatures, BTF requirements
   - Go eBPF tooling (cilium/ebpf) is immature for this use case

2. **Fragility**: Kernel function signatures change across versions
   - `ip_do_table()` may be inlined or renamed in future kernels
   - Kprobe attachment fails silently or crashes if symbol missing

3. **Minimal Marginal Benefit**: xt_TRACE already captures all necessary information
   - eBPF would only add filtering/sampling capabilities (nice-to-have, not P1)

---

## 8. Kernel Module Requirements & Auto-Loading

### **For xt_TRACE + NFLOG**:

```bash
# Modules needed:
- xt_LOG        (provides LOG and TRACE targets)
- nf_log        (netfilter logging framework)
- nf_log_ipv4   (IPv4 handler for nf_log)

# Check if loaded:
lsmod | grep xt_LOG
lsmod | grep nf_log

# Auto-load on first rule:
iptables -A INPUT -j TRACE   # Kernel auto-loads xt_LOG
iptables -A INPUT -j NFLOG --nflog-group 100  # Kernel auto-loads nf_log

# Manual load (if needed):
modprobe xt_LOG
modprobe nf_log_ipv4
modprobe nf_log
```

**iptrace Implementation**:
```go
func EnsureXtLogModules() error {
    modules := []string{"nf_log", "nf_log_ipv4", "xt_LOG"}
    
    for _, mod := range modules {
        if !isLoaded(mod) {
            if err := exec.Command("modprobe", mod).Run(); err != nil {
                // Log warning but don't fail—kernel may auto-load
                log.Printf("Warning: failed to preload %s: %v", mod, err)
            }
        }
    }
    
    // Try inserting a test rule to trigger auto-load
    exec.Command("iptables", "-t", "filter", "-I", "INPUT", "1", 
                 "-d", "127.0.0.1", "-j", "NFLOG", "--nflog-group", "100").Run()
    exec.Command("iptables", "-t", "filter", "-D", "INPUT", "1").Run()
    
    return nil
}
```

### **For nft trace**:

```bash
# Modules needed:
- nf_tables    (nftables framework)
- nf_tables_ipv4 (or auto-loaded)

# Check if available:
cat /proc/sys/net/netfilter/nf_tables_trace  # Must be writable
lsmod | grep nf_tables

# Enable tracing:
echo 1 > /proc/sys/net/netfilter/nf_tables_trace

# Disable tracing:
echo 0 > /proc/sys/net/netfilter/nf_tables_trace
```

---

## 9. Testing Strategy

### **Unit Tests**:
- TLV parsing for NFLOG messages (mock byte arrays)
- nft output parsing (mock subprocess output)
- Rule cleanup logic (safe to mock iptables commands)

### **Integration Tests** (Requires Root + Testbed):
- Insert test rules, trigger matching packets, verify trace output
- Verify rule cleanup (no dangling NFLOG rules after tool exit)
- Verify compatibility on iptables-legacy vs iptables-nft systems

### **Compatibility Matrix**:
| System | Backend | Kernel | Method | Status |
|--------|---------|--------|--------|--------|
| RHEL 7 | iptables-legacy | 3.10 | xt_TRACE | ✅ |
| RHEL 8 | iptables-nft | 4.18 | xt_TRACE (fallback) | ✅ |
| Ubuntu 20.04 | iptables-nft | 5.4 | nft trace (preferred) | ✅ |
| Ubuntu 22.04 | iptables-nft | 5.15 | nft trace (preferred) | ✅ |

---

## Summary Table

| Aspect | xt_TRACE + NFLOG | nft trace | eBPF |
|--------|------------------|-----------|------|
| **Primary Use** | Universal tracing, iptables-legacy support | Modern systems, non-intrusive | Advanced filtering (future) |
| **Compatibility** | iptables-legacy ✅, iptables-nft ✅ | iptables-legacy ❌, iptables-nft ✅ | Both ✅ |
| **Rule Modification** | Yes (temporary) | No | No |
| **Kernel Version** | 2.6+ | 4.13+ (5.0+ recommended) | 5.0+ with BTF |
| **Go Implementation** | Pure Go ✅ | Pure Go ✅ | CGo required |
| **Complexity** | Medium | Medium | High |
| **Production Ready** | ✅✅✅ | ✅✅ | ✅ (with caveats) |
| **Recommendation** | **PRIMARY** | Secondary (modern systems) | Not recommended for P1 |

---

## Conclusion

**Recommended Implementation Path**:

1. **Phase 1 (P1)**: Offline rule simulator—no kernel involvement needed; foundation for all modes
2. **Phase 2 (P2a)**: xt_TRACE + NFLOG backend—universal online tracing (both iptables backends)
3. **Phase 2 (P2b)**: nft trace backend—modern, non-intrusive alternative; fallback to xt_TRACE if unavailable
4. **Phase 3+ (Future)**: eBPF kprobes (only if sampling/filtering requirements emerge)

This approach maximizes compatibility, minimizes deployment friction, and leverages mature kernel mechanisms.
