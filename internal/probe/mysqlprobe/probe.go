// Package mysqlprobe 读取 MySQL 协议 10 的握手包，不发送认证，也不用端口号推断数据库服务。
// Package mysqlprobe reads a MySQL protocol 10 handshake and does not authenticate or infer a database service from the port number.
package mysqlprobe

import (
	"context"
	"net/netip"
	"time"

	"github.com/zodirc/Vesper/pkg/probesdk"
)

const (
	// Name 是探针名称。它表示 MySQL 线协议，不表示发行方。
	// Name is the probe name. It names the MySQL wire protocol, not a vendor.
	Name = "mysql"
	// HintPort 是选择该探针的端口提示。握手不匹配时仍不记录 MySQL。
	// HintPort is the port hint that selects this probe. A non-matching handshake is still not recorded as MySQL.
	HintPort = 3306
	// MaxHandshakeBytes 是一个握手包的读取上限，含 4 字节包头。
	// MaxHandshakeBytes is the read limit for one handshake packet, including its 4-byte header.
	MaxHandshakeBytes = 256
)

// Result 是一次 MySQL 握手观察。
// Result is one MySQL handshake observation.
type Result struct {
	ServerVersion   string
	ProtocolVersion int
	Raw             []byte
	IsMySQL         bool
	State           string
	Message         string
}

// ProbeForPort 按端口提示选择探针。只有 3306 选择 MySQL，其他端口没有该探针。
// ProbeForPort selects a probe from the port hint. Only port 3306 selects MySQL. Every other port has no MySQL probe.
func ProbeForPort(port int) string {
	if port == HintPort {
		return Name
	}
	return ""
}

// Probe 在连接成功后最多读取 256 字节。它不向服务器发送任何字节。
// Probe reads at most 256 bytes after the connection succeeds. It sends no bytes to the server.
//
// 完整包的序列号必须是 0，协议字节必须是 10，并且协议字节后有一段非空、以 NUL 结束的服务器版本。版本文本原样保留，不据此判断发行方。
// A complete packet is MySQL only when its sequence is 0, its protocol byte is 10, and a non-empty NUL-terminated server version follows that byte. The version text is kept as read and is not used to decide a vendor.
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
	raw, err := readPacket(conn)
	if len(raw) == 0 && err != nil {
		return Result{State: "error", Message: err.Error()}, err
	}
	version, ok := handshake(raw)
	return Result{ServerVersion: version, ProtocolVersion: protocolVersion(ok), Raw: append([]byte(nil), raw...), IsMySQL: ok, State: "open"}, nil
}

func protocolVersion(ok bool) int {
	if !ok {
		return 0
	}
	return 10
}

func readPacket(conn interface {
	Read([]byte) (int, error)
}) ([]byte, error) {
	buf := make([]byte, MaxHandshakeBytes)
	total := 0
	var err error
	for total < 4 {
		var n int
		n, err = conn.Read(buf[total:])
		total += n
		if n == 0 || err != nil {
			break
		}
	}
	if total < 4 {
		return buf[:total], err
	}
	payloadLen := int(buf[0]) | int(buf[1])<<8 | int(buf[2])<<16
	need := 4 + payloadLen
	if payloadLen < 1 || need > MaxHandshakeBytes {
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

func handshake(raw []byte) (string, bool) {
	if len(raw) < 5 || raw[3] != 0 {
		return "", false
	}
	payloadLen := int(raw[0]) | int(raw[1])<<8 | int(raw[2])<<16
	if payloadLen < 1 || len(raw) != 4+payloadLen || raw[4] != 10 {
		return "", false
	}
	payload := raw[5 : 4+payloadLen]
	end := -1
	for i, item := range payload {
		if item == 0 {
			end = i
			break
		}
	}
	if end <= 0 {
		return "", false
	}
	return string(payload[:end]), true
}
