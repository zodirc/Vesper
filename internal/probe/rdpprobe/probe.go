// Package rdpprobe 发送一条不申请 TLS 或 CredSSP 的 RDP 连接请求，确认 X.224 连接确认后立即关闭。
// Package rdpprobe sends one RDP connection request that does not request TLS or CredSSP, and closes as soon as the X.224 connection confirm is recognized.
package rdpprobe

import (
	"context"
	"encoding/binary"
	"net/netip"
	"time"

	"github.com/zodirc/Vesper/pkg/probesdk"
)

const (
	// Name 是探针名称。它表示 RDP 线协议，不表示远程桌面产品。
	// Name is the probe name. It names the RDP wire protocol, not a remote-desktop product.
	Name = "rdp"
	// HintPort 是选择该探针的端口提示。应答不匹配时仍不记录 RDP。
	// HintPort is the port hint that selects this probe. A non-matching response is still not recorded as RDP.
	HintPort = 3389
	// MaxReplyBytes 是连接确认的读取上限。确认本身短于这个长度；更长的报文只保留这个长度。
	// MaxReplyBytes is the read limit for a connection confirm. The confirm itself is shorter; a longer message keeps only this many bytes.
	MaxReplyBytes = 64

	x224ConnectionConfirm = 0xd0
	negotiationResponse   = 0x02
	negotiationFailure    = 0x03
)

// connectionRequest 是一条 TPKT 和 X.224 连接请求，附带 requestedProtocols 为 0 的 RDP 协商请求。
// connectionRequest is one TPKT and X.224 connection request with an RDP negotiation request whose requestedProtocols value is 0.
//
// 0 表示标准 RDP 安全，不申请 TLS，也不申请 CredSSP 或 NLA。MS-RDPBCGR 的连接请求由这 19 字节组成。
// Zero selects standard RDP security and requests neither TLS nor CredSSP or NLA. An MS-RDPBCGR connection request consists of these 19 bytes.
var connectionRequest = []byte{
	0x03, 0x00, 0x00, 0x13,
	0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x01, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
}

// Request 返回探针发送的唯一请求。调用方不能把它改成 TLS 或 CredSSP 协商。
// Request returns the only request the probe sends. Callers cannot turn it into a TLS or CredSSP negotiation.
func Request() []byte {
	return append([]byte(nil), connectionRequest...)
}

// Result 是一次 RDP 连接确认观察。
// Result is one RDP connection-confirm observation.
type Result struct {
	Negotiation      string
	SelectedProtocol int
	FailureCode      int
	Raw              []byte
	IsRDP            bool
	State            string
	Message          string
}

// ProbeForPort 按端口提示选择探针。只有 3389 选择 RDP，其他端口没有该探针。
// ProbeForPort selects a probe from the port hint. Only port 3389 selects RDP. Every other port has no RDP probe.
func ProbeForPort(port int) string {
	if port == HintPort {
		return Name
	}
	return ""
}

// Probe 发送一条 requestedProtocols 为 0 的连接请求，并最多读取 64 字节。它不开始 TLS，也不发送 CredSSP 或登录信息。
// Probe sends one connection request with requestedProtocols 0 and reads at most 64 bytes. It starts no TLS handshake and sends no CredSSP or logon data.
//
// TPKT 版本必须是 3，X.224 代码必须是连接确认 0xD0。协商应答 0x02 和协商失败 0x03 都记为 RDP。服务器选出的协议即使包含 TLS，探针也立即关闭。
// The TPKT version must be 3 and the X.224 code must be connection confirm 0xD0. Both negotiation response 0x02 and negotiation failure 0x03 are RDP. The probe closes immediately even when the protocol selected by the server includes TLS.
func Probe(ctx context.Context, dial probesdk.Dialer, budget interface {
	AcquireRequest(context.Context, time.Time) error
}, ip netip.Addr, port int, now func() time.Time) (Result, error) {
	if err := budget.AcquireRequest(ctx, now()); err != nil {
		return Result{State: "not_scanned", Message: err.Error()}, err
	}
	conn, err := dial.DialTCP(ctx, ip, port, "protocol_probe")
	if err != nil {
		return Result{State: probesdk.Classify(err), Message: err.Error()}, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(dial.Timeout))
	if _, err := conn.Write(connectionRequest); err != nil {
		return Result{State: "error", Message: err.Error()}, err
	}
	raw, err := readReply(conn)
	if len(raw) == 0 && err != nil {
		return Result{State: "error", Message: err.Error()}, err
	}
	result, ok := confirm(raw)
	result.Raw = append([]byte(nil), raw...)
	result.IsRDP = ok
	result.State = "open"
	return result, nil
}

func readReply(conn interface {
	Read([]byte) (int, error)
}) ([]byte, error) {
	buf := make([]byte, MaxReplyBytes)
	total := 0
	var err error
	for total < MaxReplyBytes {
		var n int
		n, err = conn.Read(buf[total:])
		total += n
		if total >= 11 && buf[0] == 0x03 {
			size := int(binary.BigEndian.Uint16(buf[2:4]))
			if size >= 11 && size <= MaxReplyBytes && total >= size {
				return buf[:size], nil
			}
			if size > MaxReplyBytes && total >= 11 {
				return buf[:total], nil
			}
		}
		if n == 0 || err != nil {
			return buf[:total], err
		}
	}
	return buf[:total], nil
}

func confirm(raw []byte) (Result, bool) {
	if len(raw) < 11 || raw[0] != 0x03 || raw[1] != 0x00 || raw[5] != x224ConnectionConfirm {
		return Result{}, false
	}
	size := int(binary.BigEndian.Uint16(raw[2:4]))
	if size < 11 || size > 4096 {
		return Result{}, false
	}
	if len(raw) < 19 {
		return Result{}, true
	}
	switch raw[11] {
	case negotiationResponse:
		if len(raw) < 19 {
			return Result{Negotiation: "response"}, true
		}
		return Result{Negotiation: "response", SelectedProtocol: int(binary.LittleEndian.Uint32(raw[15:19]))}, true
	case negotiationFailure:
		if len(raw) < 19 {
			return Result{Negotiation: "failure"}, true
		}
		return Result{Negotiation: "failure", FailureCode: int(binary.LittleEndian.Uint32(raw[15:19]))}, true
	default:
		return Result{}, true
	}
}
