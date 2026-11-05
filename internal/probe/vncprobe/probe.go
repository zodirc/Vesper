// Package vncprobe 读取 RFB 协议版本，不发送客户端版本，也不用端口号推断 VNC 服务。
// Package vncprobe reads the RFB protocol version. It sends no client version and does not infer a VNC service from the port number.
package vncprobe

import (
	"bytes"
	"context"
	"net/netip"
	"time"

	"github.com/zodirc/Vesper/pkg/probesdk"
)

const (
	// Name 是探针名称。服务类型 vnc 表示 RFC 6143 的 RFB 线协议，不表示发行方。
	// Name is the probe name. The vnc service type names the RFC 6143 RFB wire protocol, not a vendor.
	Name = "vnc"
	// HintPort 是选择该探针的端口提示。应答不匹配时仍不记录 VNC。
	// HintPort is the port hint that selects this probe. A non-matching response is still not recorded as VNC.
	HintPort = 5900
	// VersionBytes 是服务器协议版本的固定长度。RFC 6143 规定为 "RFB xxx.xxx\n"。
	// VersionBytes is the fixed length of the server protocol version. RFC 6143 specifies "RFB xxx.xxx\n".
	VersionBytes = 12
)

// Result 是一次 RFB 版本观察。
// Result is one RFB version observation.
type Result struct {
	ProtocolVersion string
	Raw             []byte
	IsVNC           bool
	State           string
	Message         string
}

// ProbeForPort 按端口提示选择探针。只有 5900 选择 VNC，其他端口没有该探针。
// ProbeForPort selects a probe from the port hint. Only port 5900 selects VNC. Every other port has no VNC probe.
func ProbeForPort(port int) string {
	if port == HintPort {
		return Name
	}
	return ""
}

// Probe 在连接成功后读取 12 字节。它不发送客户端协议版本，也不进入安全协商。
// Probe reads 12 bytes after the connection succeeds. It sends no client protocol version and does not enter security negotiation.
//
// 这 12 字节必须是 RFB、空格、三位数字、点、三位数字和换行。其他文本不记为 VNC。版本标记原样保存，不据此判断发行方。
// Those 12 bytes are VNC only when they are RFB, a space, three digits, a dot, three digits, and a newline. Any other text is not VNC. The version token is stored verbatim and is not used to infer a vendor.
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
	raw, err := readN(conn, VersionBytes)
	if len(raw) == 0 && err != nil {
		return Result{State: "error", Message: err.Error()}, err
	}
	version, ok := protocolVersion(raw)
	return Result{ProtocolVersion: version, Raw: append([]byte(nil), raw...), IsVNC: ok, State: "open"}, nil
}

func readN(conn interface {
	Read([]byte) (int, error)
}, n int) ([]byte, error) {
	buf := make([]byte, n)
	total := 0
	var err error
	for total < n {
		var read int
		read, err = conn.Read(buf[total:])
		total += read
		if read == 0 || err != nil {
			return buf[:total], err
		}
	}
	return buf[:total], nil
}

func protocolVersion(raw []byte) (string, bool) {
	if len(raw) != VersionBytes || !bytes.HasPrefix(raw, []byte("RFB ")) || raw[11] != '\n' || raw[7] != '.' {
		return "", false
	}
	for _, index := range []int{4, 5, 6, 8, 9, 10} {
		if raw[index] < '0' || raw[index] > '9' {
			return "", false
		}
	}
	return string(raw[4:11]), true
}
