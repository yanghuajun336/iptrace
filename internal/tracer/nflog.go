package tracer

// nflog.go implements a NETLINK_NETFILTER socket listener that subscribes to
// NFLOG group 0.  When xt_TRACE is active, the kernel delivers one NFLOG
// message per rule-hit; each message carries a NFULA_PREFIX attribute of the
// form "TRACE: <table>:<chain>:<type>:<rulenum>", which DecodeNFLOGPrefix
// converts into a model.TraceStep.
//
// Protocol overview
// -----------------
//  1. socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER)
//  2. bind  (addr.Groups = 0 — we poll, not multicast)
//  3. send  NFULNL_MSG_CONFIG / NFULNL_CFG_CMD_PF_BIND  (AF_INET, group 0)
//  4. send  NFULNL_MSG_CONFIG / NFULNL_CFG_CMD_BIND     (AF_INET, group 0)
//  5. send  NFULNL_MSG_CONFIG / NFULA_CFG_MODE = COPY_META  (metadata only)
//  6. loop: Recvfrom → ParseNetlinkMessage → DecodeNFLOGPacket → TraceStep

import (
	"context"
	"encoding/binary"
	"fmt"
	"syscall"

	"golang.org/x/sys/unix"
	"iptrace/pkg/model"
)

// NFLOG subsystem / message-type constants (linux/netfilter/nfnetlink_log.h)
const (
	nfnlSubsysUlog  = 4 // NFNL_SUBSYS_ULOG
	nfulnlMsgPacket = 0 // NFULNL_MSG_PACKET  kernel → userspace
	nfulnlMsgConfig = 1 // NFULNL_MSG_CONFIG  userspace → kernel

	nfulnlCfgCmdNone    = 0
	nfulnlCfgCmdBind    = 1 // bind to a specific group
	nfulnlCfgCmdUnbind  = 2
	nfulnlCfgCmdPfBind  = 3 // bind to all packets of a protocol family
	nfulnlCfgCmdPfUnbind = 4

	nfulaCfgCmd  = 1  // NFULA_CFG_CMD  attribute type
	nfulaCfgMode = 2  // NFULA_CFG_MODE attribute type
	nfulaPrefix  = 10 // NFULA_PREFIX   attribute type

	nfulnlCopyNone   = 0
	nfulnlCopyMeta   = 1 // copy only metadata (sufficient for xt_TRACE)
	nfulnlCopyPacket = 2

	nflogGroup   = 0              // xt_TRACE uses NFLOG group 0 by default
	nlmsgHdrLen  = 16             // sizeof(struct nlmsghdr)
	recvTimeout  = 200_000        // µs  — SO_RCVTIMEO polling interval
)

// nflogListener manages a NETLINK_NETFILTER socket for reading NFLOG events.
type nflogListener struct {
	fd int
}

// openNFLOGSocket creates and configures the NFLOG socket.
// Returns an error if the kernel is missing NETLINK_NETFILTER support or if
// the caller lacks CAP_NET_ADMIN.
func openNFLOGSocket() (*nflogListener, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_NETFILTER)
	if err != nil {
		return nil, fmt.Errorf("create NETLINK_NETFILTER socket: %w", err)
	}

	addr := &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: 0}
	if err := unix.Bind(fd, addr); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("bind netlink socket: %w", err)
	}

	nl := &nflogListener{fd: fd}

	// Step 3: PF_BIND — tell kernel we want NFLOG packets for AF_INET
	if err := nl.sendCfgCmd(unix.AF_INET, nflogGroup, nfulnlCfgCmdPfBind); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("NFLOG PF_BIND AF_INET: %w", err)
	}

	// Step 4: BIND — subscribe to the specific group
	if err := nl.sendCfgCmd(unix.AF_INET, nflogGroup, nfulnlCfgCmdBind); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("NFLOG bind group %d: %w", nflogGroup, err)
	}

	// Step 5: set copy mode to META (we only need the prefix, not the full packet)
	if err := nl.sendCopyMode(unix.AF_INET, nflogGroup, nfulnlCopyMeta); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("NFLOG set copy mode: %w", err)
	}

	return nl, nil
}

// Close releases the netlink socket.
func (n *nflogListener) Close() error {
	return unix.Close(n.fd)
}

// ReadEvents reads NFLOG packets in a loop, sending decoded TraceStep values to
// out.  It returns when ctx is cancelled or a fatal socket error occurs.
// The caller is responsible for closing out.
func (n *nflogListener) ReadEvents(ctx context.Context, out chan<- model.TraceStep) {
	// Set a receive timeout so we can check ctx periodically.
	tv := unix.Timeval{Sec: 0, Usec: recvTimeout}
	_ = unix.SetsockoptTimeval(n.fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)

	buf := make([]byte, 65536)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		nr, _, err := unix.Recvfrom(n.fd, buf, 0)
		if err != nil {
			if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
				continue // timeout — loop back and check ctx
			}
			return // fatal socket error
		}

		msgs, err := syscall.ParseNetlinkMessage(buf[:nr])
		if err != nil {
			continue
		}

		for _, msg := range msgs {
			// Only process NFULNL_MSG_PACKET from the ULOG subsystem
			if msg.Header.Type != uint16(nfnlSubsysUlog<<8|nfulnlMsgPacket) {
				continue
			}
			step, err := DecodeNFLOGPacket(msg.Data)
			if err != nil {
				continue
			}
			select {
			case out <- step:
			case <-ctx.Done():
				return
			}
		}
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Low-level netlink message builders
// ──────────────────────────────────────────────────────────────────────────────

// sendCfgCmd sends an NFULNL_MSG_CONFIG message with a NFULA_CFG_CMD attribute.
func (n *nflogListener) sendCfgCmd(family uint8, group uint16, cmd uint8) error {
	// nfgenmsg (4 bytes): family | version=0 | res_id (group, big-endian)
	nfgen := nfgenMsg(family, group)

	// NFULA_CFG_CMD attribute: nla_len=8, nla_type=1, cmd(1B)+pad(3B)
	attr := make([]byte, 8)
	binary.LittleEndian.PutUint16(attr[0:2], 8)            // nla_len
	binary.LittleEndian.PutUint16(attr[2:4], nfulaCfgCmd)  // nla_type
	attr[4] = cmd                                          // cmd byte
	// attr[5:8] = 0 (pad)

	return n.sendNLMsg(
		uint16(nfnlSubsysUlog<<8|nfulnlMsgConfig),
		unix.NLM_F_REQUEST|unix.NLM_F_ACK,
		append(nfgen, attr...),
	)
}

// sendCopyMode sends an NFULNL_MSG_CONFIG message with a NFULA_CFG_MODE attribute.
func (n *nflogListener) sendCopyMode(family uint8, group uint16, mode uint8) error {
	nfgen := nfgenMsg(family, group)

	// NFULA_CFG_MODE attribute: nla_len=12, nla_type=2, mode(1B)+pad(3B)+copy_range(4B)
	attr := make([]byte, 12)
	binary.LittleEndian.PutUint16(attr[0:2], 12)             // nla_len
	binary.LittleEndian.PutUint16(attr[2:4], nfulaCfgMode)   // nla_type
	attr[4] = mode                                           // copy_mode
	// attr[5:8] = 0 (pad); attr[8:12] = 0 (copy_range = unlimited)

	return n.sendNLMsg(
		uint16(nfnlSubsysUlog<<8|nfulnlMsgConfig),
		unix.NLM_F_REQUEST,
		append(nfgen, attr...),
	)
}

// nfgenMsg returns a 4-byte nfgenmsg header: [family, version=0, res_id_hi, res_id_lo].
// res_id is the NFLOG group number and must be in network byte order.
func nfgenMsg(family uint8, group uint16) []byte {
	b := make([]byte, 4)
	b[0] = family
	b[1] = 0 // NFNETLINK_V0
	b[2] = byte(group >> 8)
	b[3] = byte(group)
	return b
}

// sendNLMsg wraps payload in a nlmsghdr and sends it to the kernel.
func (n *nflogListener) sendNLMsg(msgType, flags uint16, payload []byte) error {
	totalLen := nlmsgHdrLen + len(payload)
	alignedLen := (totalLen + 3) &^ 3

	buf := make([]byte, alignedLen)
	binary.LittleEndian.PutUint32(buf[0:4], uint32(totalLen))
	binary.LittleEndian.PutUint16(buf[4:6], msgType)
	binary.LittleEndian.PutUint16(buf[6:8], flags)
	// seq = 0, pid = 0
	copy(buf[nlmsgHdrLen:], payload)

	dst := &unix.SockaddrNetlink{Family: unix.AF_NETLINK}
	return unix.Sendto(n.fd, buf, 0, dst)
}
