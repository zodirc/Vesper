// Package cqlprobe 用一条 CQL STARTUP 识别原生协议，不发送认证响应或查询，也不用端口号推断数据库服务。
// Package cqlprobe identifies the CQL native protocol with one STARTUP. It sends no authentication response or query and does not infer a database service from the port number.
package cqlprobe

import (
	"context"
	"encoding/binary"
	"net/netip"
	"time"

	"github.com/zodirc/Vesper/pkg/probesdk"
)

const (
	// Name 是探针名称。它表示 CQL 原生协议，不表示发行方。
	// Name is the probe name. It names the CQL native protocol, not a vendor.
	Name = "cql"
	// HintPort 是选择该探针的端口提示。应答不匹配时仍不记录 CQL。
	// HintPort is the port hint that selects this probe. A non-matching response is still not recorded as CQL.
	HintPort = 9042
	// MaxFrameBytes 是一帧的读取上限，含 9 字节帧头。
	// MaxFrameBytes is the read limit for one frame, including its 9-byte header.
	MaxFrameBytes = 512
	// ReplyReady 表示服务器接受了 STARTUP，并且没有要求认证。
	// ReplyReady means the server accepted STARTUP and did not require authentication.
	ReplyReady = "READY"
	// ReplyAuthenticate 表示服务器要求认证。探针就此停止，不发送认证响应。
	// ReplyAuthenticate means the server requires authentication. The probe stops there and sends no authentication response.
	ReplyAuthenticate = "AUTHENTICATE"
)

// startupMessage 是一条协议版本 4 的 STARTUP。选项只有 CQL_VERSION=3.0.0，没有压缩、驱动名或凭据。
// startupMessage is one protocol version 4 STARTUP. Its only option is CQL_VERSION=3.0.0, with no compression, driver name, or credential.
var startupMessage = []byte{
	0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x16,
	0x00, 0x01,
	0x00, 0x0b, 'C', 'Q', 'L', '_', 'V', 'E', 'R', 'S', 'I', 'O', 'N',
	0x00, 0x05, '3', '.', '0', '.', '0',
}

// Result 是一次 CQL STARTUP 应答观察。
// Result is one CQL STARTUP response observation.
type Result struct {
	ProtocolVersion int
	Reply           string
	Raw             []byte
	IsCQL           bool
	State           string
	Message         string
}

// ProbeForPort 按端口提示选择探针。只有 9042 选择 CQL，其他端口没有该探针。
// ProbeForPort selects a probe from the port hint. Only port 9042 selects CQL. Every other port has no CQL probe.
func ProbeForPort(port int) string {
	if port == HintPort {
		return Name
	}
	return ""
}

// Probe 发送一条 STARTUP，并最多读取 512 字节的第一帧。它不发送认证响应、查询或后续帧，也不协商压缩。
// Probe sends one STARTUP and reads at most 512 bytes of the first frame. It sends no authentication response, query, or follow-up frame, and it does not negotiate compression.
//
// 应答的方向位必须置位，协议版本必须是 3、4 或 5，标志和流号必须是 0，长度字段必须与实际字节数一致。READY 的正文必须为空。AUTHENTICATE 的正文必须是一条非空字符串。压缩、跟踪和 ERROR 帧不记为 CQL。
// A response is CQL only when its direction bit is set, its protocol version is 3, 4, or 5, its flags and stream are 0, and its length field matches the bytes received. READY must have an empty body. AUTHENTICATE must have one non-empty string body. Compressed, traced, and ERROR frames are not CQL.
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
	if _, err := conn.Write(startupMessage); err != nil {
		return Result{State: "error", Message: err.Error()}, err
	}
	raw, err := readFrame(conn)
	if len(raw) == 0 && err != nil {
		return Result{State: "error", Message: err.Error()}, err
	}
	version, reply, ok := response(raw)
	return Result{ProtocolVersion: version, Reply: reply, Raw: append([]byte(nil), raw...), IsCQL: ok, State: "open"}, nil
}

func readFrame(conn interface {
	Read([]byte) (int, error)
}) ([]byte, error) {
	buf := make([]byte, MaxFrameBytes)
	total := 0
	var err error
	for total < 9 {
		var n int
		n, err = conn.Read(buf[total:])
		total += n
		if n == 0 || err != nil {
			break
		}
	}
	if total < 9 {
		return buf[:total], err
	}
	bodyLen := int(binary.BigEndian.Uint32(buf[5:9]))
	need := 9 + bodyLen
	if bodyLen < 0 || need > MaxFrameBytes {
		return buf[:total], nil
	}
	for total < need {
		var n int
		n, err = conn.Read(buf[total:])
		total += n
		if n == 0 || err != nil {
			return buf[:total], err
		}
	}
	return buf[:need], nil
}

func response(raw []byte) (int, string, bool) {
	if len(raw) < 9 || len(raw) > MaxFrameBytes || raw[0]&0x80 == 0 || raw[1] != 0 {
		return 0, "", false
	}
	version := int(raw[0] & 0x7f)
	bodyLen := int(binary.BigEndian.Uint32(raw[5:9]))
	if version < 3 || version > 5 || binary.BigEndian.Uint16(raw[2:4]) != 0 || 9+bodyLen != len(raw) {
		return 0, "", false
	}
	switch raw[4] {
	case 0x02:
		if bodyLen != 0 {
			return 0, "", false
		}
		return version, ReplyReady, true
	case 0x03:
		if !authenticator(raw[9:]) {
			return 0, "", false
		}
		return version, ReplyAuthenticate, true
	default:
		return 0, "", false
	}
}

func authenticator(body []byte) bool {
	if len(body) < 3 {
		return false
	}
	n := int(binary.BigEndian.Uint16(body[:2]))
	return n > 0 && 2+n == len(body)
}
