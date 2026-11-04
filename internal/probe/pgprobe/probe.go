// Package pgprobe 用一条 PostgreSQL 启动消息识别线协议，不发送口令或查询，也不用端口号推断数据库服务。
// Package pgprobe identifies the PostgreSQL wire protocol with one startup message. It sends no password or query and does not infer a database service from the port number.
package pgprobe

import (
	"context"
	"encoding/binary"
	"net/netip"
	"time"

	"github.com/zodirc/Vesper/pkg/probesdk"
)

const (
	// Name 是探针名称。它表示 PostgreSQL 线协议，不表示发行方。
	// Name is the probe name. It names the PostgreSQL wire protocol, not a vendor.
	Name = "postgresql"
	// HintPort 是选择该探针的端口提示。应答不匹配时仍不记录 PostgreSQL。
	// HintPort is the port hint that selects this probe. A non-matching response is still not recorded as PostgreSQL.
	HintPort = 5432
	// MaxMessageBytes 是一条后端消息的读取上限，含类型字节和长度字段。
	// MaxMessageBytes is the read limit for one backend message, including the type byte and length field.
	MaxMessageBytes = 1024
)

// startupMessage 是协议版本 3.0 的一条启动消息。参数只有 user=vesper，没有口令。
// startupMessage is one protocol 3.0 startup message. Its only parameter is user=vesper, and it contains no password.
var startupMessage = []byte{
	0, 0, 0, 21,
	0, 3, 0, 0,
	'u', 's', 'e', 'r', 0,
	'v', 'e', 's', 'p', 'e', 'r', 0,
	0,
}

// Result 是一次 PostgreSQL 启动应答观察。
// Result is one PostgreSQL startup-response observation.
type Result struct {
	MessageType  string
	AuthMethod   int
	Raw          []byte
	IsPostgreSQL bool
	State        string
	Message      string
}

// ProbeForPort 按端口提示选择探针。只有 5432 选择 PostgreSQL，其他端口没有该探针。
// ProbeForPort selects a probe from the port hint. Only port 5432 selects PostgreSQL. Every other port has no PostgreSQL probe.
func ProbeForPort(port int) string {
	if port == HintPort {
		return Name
	}
	return ""
}

// Probe 发送一条启动消息，并最多读取 1024 字节的第一条后端消息。它不发送口令、查询或后续消息。
// Probe sends one startup message and reads at most 1024 bytes of the first backend message. It sends no password, query, or follow-up message.
//
// 第一条消息的类型必须是 R 或 E，长度字段必须与实际字节数一致，并且不超过读取上限。R 表示认证请求，E 表示错误应答。认证方法为 0 时也立即停止，不使用已经建立的会话。
// The first message is PostgreSQL only when its type is R or E, its length field matches the bytes received, and it stays within the read limit. R is an authentication request and E is an error response. The probe also stops immediately when the authentication method is 0 and does not use a session that was already established.
func Probe(ctx context.Context, dial probesdk.Dialer, budget interface {
	AcquireRequest(context.Context, time.Time) error
}, ip netip.Addr, port int, now func() time.Time) (Result, error) {
	if err := budget.AcquireRequest(ctx, now()); err != nil {
		return Result{AuthMethod: -1, State: "not_scanned", Message: err.Error()}, err
	}
	conn, err := dial.DialTCP(ctx, ip, port, "protocol_probe")
	if err != nil {
		return Result{AuthMethod: -1, State: probesdk.Classify(err), Message: err.Error()}, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(dial.Timeout))
	if _, err := conn.Write(startupMessage); err != nil {
		return Result{AuthMethod: -1, State: "error", Message: err.Error()}, err
	}
	raw, err := readMessage(conn)
	if len(raw) == 0 && err != nil {
		return Result{AuthMethod: -1, State: "error", Message: err.Error()}, err
	}
	kind, method, ok := backendMessage(raw)
	return Result{MessageType: kind, AuthMethod: method, Raw: append([]byte(nil), raw...), IsPostgreSQL: ok, State: "open"}, nil
}

func readMessage(conn interface {
	Read([]byte) (int, error)
}) ([]byte, error) {
	buf := make([]byte, MaxMessageBytes)
	total := 0
	var err error
	for total < 5 {
		var n int
		n, err = conn.Read(buf[total:])
		total += n
		if n == 0 || err != nil {
			break
		}
	}
	if total < 5 {
		return buf[:total], err
	}
	length := int(binary.BigEndian.Uint32(buf[1:5]))
	need := 1 + length
	if length < 4 || need > MaxMessageBytes {
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

func backendMessage(raw []byte) (string, int, bool) {
	if len(raw) < 5 {
		return "", -1, false
	}
	kind := raw[0]
	if kind != 'R' && kind != 'E' {
		return "", -1, false
	}
	length := int(binary.BigEndian.Uint32(raw[1:5]))
	if length < 4 || len(raw) != 1+length {
		return "", -1, false
	}
	if kind == 'E' {
		return "E", -1, true
	}
	if length < 8 {
		return "", -1, false
	}
	return "R", int(binary.BigEndian.Uint32(raw[5:9])), true
}
