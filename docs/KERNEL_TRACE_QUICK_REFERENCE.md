# Quick Reference: Kernel Tracing Mechanisms for iptrace

## TL;DR Decision

**Use**: xt_TRACE + NFLOG (primary) with nft trace fallback (modern systems)

| Aspect | xt_TRACE + NFLOG | nft trace |
|--------|-----------------|-----------|
| **Works on** | iptables-legacy + nft | nft only (4.13+) |
| **Non-intrusive** | ❌ (modifies rules temp) | ✅ (sysctl only) |
| **Maturity** | ⭐⭐⭐⭐⭐ (since 2.4) | ⭐⭐⭐ (4.13+) |
| **Go Deps** | None (pure stdlib) | None (pure stdlib) |
| **Complexity** | Medium (TLV parsing) | Medium (netlink) |
| **Use When** | Any Linux, maximize compat | Modern nft systems, prefer non-intrusive |

---

## 1. xt_TRACE + NFLOG Details

### Kernel Modules
```bash
# Auto-loaded on first use, or preload:
modprobe xt_LOG nf_log_ipv4 nf_log
```

### Rule Injection Pattern
```bash
# For each hook (PREROUTING, INPUT, FORWARD, OUTPUT, POSTROUTING):
iptables -t filter -I {HOOK} 1 -p {PROTO} --dport {PORT} -s {SRC_IP} -j NFLOG --nflog-group 100

# Example:
iptables -t filter -I INPUT 1 -p tcp --dport 80 -s 1.2.3.4 -j NFLOG --nflog-group 100
```

### AF_NETLINK Socket Binding (Go)
```go
import (
    "golang.org/x/sys/unix"
)

// Open netlink socket for NETLINK_NETFILTER
fd, _ := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_NETFILTER)

// Bind to multicast group 100
nlAddr := &unix.SockaddrNetlink{
    Family: unix.AF_NETLINK,
    Groups: 1 << (100 - 1),  // Bit mask for group 100
}
unix.Bind(fd, nlAddr)

// Receive messages
buffer := make([]byte, 65535)
n, _, _ := unix.Recvfrom(fd, buffer, 0)
```

### NFLOG TLV Message Format
```
Netlink Header (16 bytes)
  ├─ nlmsg_len   : uint32
  ├─ nlmsg_type  : uint16 (NFNL_SUBSYS_ULOG << 8 | operation)
  ├─ nlmsg_flags : uint16
  └─ nlmsg_seq   : uint32

NFNL Prefix (4 bytes)
  ├─ nfgen_family : uint8  (NFPROTO_IPV4 = 2)
  ├─ version      : uint8  (0)
  └─ res_id       : uint16 (0)

Attributes (TLV format)
  Each attribute: [ len (2B) | type (2B) | payload ]
  
  Common types:
  - NFULA_TIMESTAMP  : timeval struct
  - NFULA_PAYLOAD    : raw packet data (IP header + payload)
  - NFULA_PREFIX     : syslog prefix string
  - NFULA_UID        : uid_t
  - NFULA_GID        : gid_t
  - NFULA_MARK       : nfmark
  - NFULA_IFINDEX_INDEV  : input interface index
  - NFULA_IFINDEX_OUTDEV : output interface index
  - NFULA_HWTYPE     : hardware type
  - NFULA_HWLEN      : hardware address length
  - NFULA_HWADDR     : hardware address
```

### Example: Parsing NFLOG Attribute
```go
// Parse TLV attributes
func parseNFLOGAttrs(buf []byte) map[uint16][]byte {
    attrs := make(map[uint16][]byte)
    
    for len(buf) >= 4 {
        nlaLen := binary.BigEndian.Uint16(buf[0:2])
        nlaType := binary.BigEndian.Uint16(buf[2:4])
        
        payloadLen := nlaLen - 4
        if payloadLen > 0 && len(buf) >= int(nlaLen) {
            attrs[nlaType] = buf[4 : 4+payloadLen]
        }
        
        // Next attribute (aligned to 4 bytes)
        nlaLen = (nlaLen + 3) &^ 3
        if nlaLen < 4 {
            break
        }
        buf = buf[nlaLen:]
    }
    
    return attrs
}
```

### Cleanup (Critical!)
```bash
# Delete injected rules (position 1, or search by match criteria)
iptables -t filter -D INPUT 1
iptables -t filter -D FORWARD 1
iptables -t filter -D OUTPUT 1
# ... for each hook

# Use -D with full rule spec if position uncertain:
iptables -t filter -D INPUT -p tcp --dport 80 -s 1.2.3.4 -j NFLOG --nflog-group 100
```

---

## 2. nft trace Details

### Kernel Support Check
```bash
# Check if nf_tables available
cat /proc/sys/net/netfilter/nf_tables_trace  # Should exist and be writable

# Check kernel version
uname -r  # Should be 4.13+ (5.0+ recommended)

# Check nft command
nft --version
```

### Enable/Disable Tracing
```bash
# Enable (requires root)
echo 1 > /proc/sys/net/netfilter/nf_tables_trace

# Disable
echo 0 > /proc/sys/net/netfilter/nf_tables_trace

# Verify
cat /proc/sys/net/netfilter/nf_tables_trace
```

### Monitoring via `nft monitor trace`
```bash
# Real-time trace output (can run in subprocess)
nft monitor trace

# Example output:
# trace id 3f8e3da5 inet filter input packet: iif "eth0" ... tcp dport 80
#   [ payload load 4b @ network header + 12 => reg 1 ]
#   [ cmp eq reg 1 0x04030201 ]
#   [ immediate reg 0 set 0x00000000 ] -- rule 1: ip saddr 1.2.3.4 ... drop
#   [ verdict reg 0 set drop ]
```

### Direct Netlink Binding (Advanced)
```go
import (
    "github.com/mdlayher/netfilter"
)

// Bind to nftables subsystem
// Parse trace events directly from netlink NFNL_SUBSYS_NFTABLES
// (More complex; text parsing via subprocess is simpler)
```

### Text Output Parsing Pattern
```
trace id {TRACE_ID} {FAMILY} {TABLE} {CHAIN} packet: {PACKET_INFO}
  [ ... expression evaluation ... ]
  [ ... matching verdict ... ] -- rule {RULE_NUM}: {RULE_DESCRIPTION} {ACTION}
```

---

## 3. Error Scenarios & Recovery

### Missing xt_LOG Module
```
Error: "failed to load xt_LOG"
Recovery: 
  apt-get install iptables-mod-xt-LOG  # Debian/Ubuntu
  yum install iptables-utils            # RHEL/CentOS
```

### Missing nftables Kernel Support
```
Error: "nftables trace unavailable: nf_tables module not loaded"
Recovery:
  - Fallback to xt_TRACE
  - Or recompile kernel with CONFIG_NF_TABLES=y
```

### Dual Backend Conflict (iptables-legacy + iptables-nft)
```
Detection:
  iptables -L 2>/dev/null         # iptables-legacy
  iptables-legacy -L 2>/dev/null  # explicit check
  nft list tables 2>/dev/null     # nftables
  
If both present:
  - Warn user which backend is active
  - Use only active backend (check: update-alternatives --display iptables)
```

---

## 4. Go Implementation Checklist

### xt_TRACE Backend
- [ ] Module preload (modprobe xt_LOG, nf_log, nf_log_ipv4)
- [ ] Rule backup (optional, for safety)
- [ ] Rule injection (iptables -t filter -I {hook} 1 ...)
- [ ] Netlink socket binding (AF_NETLINK, group 100)
- [ ] TLV attribute parsing
- [ ] Packet payload decoding (IP header + TCP/UDP)
- [ ] Rule cleanup on exit (defer)
- [ ] Error recovery (crashed tool → leftover rules?)

### nft trace Backend
- [ ] Kernel version check (>= 4.13)
- [ ] nftables module presence check
- [ ] Sysctl write (net.netfilter.nf_tables_trace = 1)
- [ ] nft subprocess spawn OR netlink binding
- [ ] Output parsing (text or netlink)
- [ ] Cleanup on exit (sysctl = 0)

### Shared
- [ ] Root privilege check
- [ ] Backend detection (iptables-legacy vs iptables-nft)
- [ ] Backend selection logic
- [ ] Fallback strategy
- [ ] Error messages with actionable suggestions

---

## 5. Testing Approach

### Unit Tests
- TLV parsing (mock NFLOG bytes)
- nft output parsing (mock subprocess output)
- Rule injection/deletion logic (safe mocks)

### Integration Tests (Requires Root + Testbed)
```bash
# Test setup:
# 1. Create dummy interface or use loopback
# 2. Add simple iptables rule
# 3. Send test packet (e.g., nc -l + nc)
# 4. Verify trace output matches rule
# 5. Verify rules cleaned up after tool exit
```

### Compatibility Matrix
```
┌─────────────────┬────────────────────┬───────────┬────────────────┐
│ OS              │ Backend            │ Kernel    │ Method         │
├─────────────────┼────────────────────┼───────────┼────────────────┤
│ RHEL 7          │ iptables-legacy    │ 3.10      │ xt_TRACE       │
│ RHEL 8          │ iptables-nft       │ 4.18      │ xt_TRACE       │
│ RHEL 9          │ iptables-nft       │ 5.14      │ nft trace      │
│ Ubuntu 20.04    │ iptables-nft       │ 5.4       │ nft trace      │
│ Ubuntu 22.04    │ iptables-nft       │ 5.15      │ nft trace      │
│ Debian 11       │ iptables-nft       │ 5.10      │ nft trace      │
│ Alpine (edge)   │ iptables-nft       │ 6.0+      │ nft trace      │
└─────────────────┴────────────────────┴───────────┴────────────────┘
```

---

## 6. References

- **NFLOG Protocol**: `include/uapi/netfilter/nfnetlink_log.h` (kernel source)
- **xt_LOG Implementation**: `net/netfilter/xt_LOG.c`
- **nftables Trace**: `net/netfilter/nf_tables_trace.c`
- **Pure Go Netlink**: https://github.com/mdlayher/netlink
- **netfilter Go Binding**: https://github.com/mdlayher/netfilter
- **Netfilter Docs**: https://www.netfilter.org/documentation.html

---

## 7. Performance Characteristics

### xt_TRACE + NFLOG
- **Latency**: Message available in kernel ring buffer <1ms after rule match
- **Throughput**: ~1000s of packets/sec before NFLOG buffer overflow (tunable)
- **CPU**: <1% overhead per backend when tracing <100 pps
- **Memory**: ~100KB per active connection trace

### nft trace
- **Latency**: Event available in netlink buffer <1ms after rule evaluation
- **Throughput**: Similar to xt_TRACE; kernel-limited
- **CPU**: <1% overhead when tracing <100 pps
- **Memory**: ~50KB per active trace

### Offline Simulation (P1)
- **Latency**: <100ms for 1000-rule set (single packet)
- **CPU**: Negligible
- **Memory**: Proportional to rule set size (~1MB per 10k rules)

---

## 8. Production Deployment Notes

1. **xt_TRACE Rules Leak**: If tool crashes, NFLOG rules may persist
   - Mitigation: Systemd ExecStop script to clean up
   - Or: Periodic cleanup service that removes stale NFLOG rules

2. **High-Traffic Filtering**: Both mechanisms can be overwhelmed by high pps
   - Mitigation: Pre-filter rules (match only source IP) instead of tracing all packets
   - Mitigation: Enable sampling (if supported)

3. **iptables-legacy Sunset**: Plan migration path to nftables
   - iptables-legacy deprecated in Linux 5.10+
   - Consider warning users to adopt iptables-nft for future compatibility

4. **Kernel Module Availability**: Some hardened kernels disable modules
   - Test on target environments before deployment
   - Provide compile-from-source option for unsupported systems

---

## 9. Example: User Workflow

```bash
# User: "I need to trace why 1.2.3.4:random -> 10.0.0.1:80 is being blocked"

# Step 1: Run iptrace with filter
$ sudo iptrace trace --filter "src 1.2.3.4 dport 80"
Detecting backend... iptables-nft
Checking trace mechanism availability...
  ✓ nftables kernel support found (kernel 5.10)
  ✓ nft command available
Using: nft monitor trace (non-intrusive)

Enabling kernel tracing...
Listening for packets matching: src 1.2.3.4 dport 80

---

# Step 2: User triggers traffic from 1.2.3.4 to 10.0.0.1:80
# (e.g., ping from source, or curl to destination)

# Step 3: iptrace outputs in real-time:
[2026-03-25T14:23:45.123Z] Packet arrived: 1.2.3.4:56789 -> 10.0.0.1:80 TCP
  PREROUTING raw      : No match
  PREROUTING mangle   : No match
  INPUT filter        : Rule 1 (input rate limit) - No match
  INPUT filter        : Rule 2 (-s 1.2.3.4 -j DROP) - MATCHED ✗
Final decision: DROP (Rule INPUT:2)

---

# Step 4: User sees rule number, can check with:
$ sudo iptables -t filter -L INPUT -n -v
Chain INPUT (policy ACCEPT 123 packets, 45K bytes)
    pkts      bytes target     prot opt in   out   source          destination
       0        0 DROP        tcp  --  *    *    1.2.3.4          0.0.0.0/0
       ...

# Rule is confirmed; user can update as needed
```

