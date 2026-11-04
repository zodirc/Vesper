// Package clickhouseprobe 用一条原生 Hello 识别 ClickHouse 线协议，不发送查询，也不用端口号推断数据库服务。
// Package clickhouseprobe identifies the ClickHouse native protocol with one Hello. It sends no query and does not infer a database service from the port number.
package clickhouseprobe

import (
	"context"
	"encoding/binary"
	"fmt"
	"net/netip"
	"time"

	"github.com/zodirc/Vesper/pkg/probesdk"
)

const (
	// Name 是探针名称。它表示 ClickHouse 原生协议，不表示发行方。
	// Name is the probe name. It names the ClickHouse native protocol, not a vendor.
	Name = "clickhouse"
	// HintPort 是选择该探针的端口提示。应答不匹配时仍不记录 ClickHouse。
	// HintPort is the port hint that selects this probe. A non-matching response is still not recorded as ClickHouse.
	HintPort = 9000
	// MaxResponseBytes 是第一条应答的读取上限。
	// MaxResponseBytes is the read limit for the first response.
	MaxResponseBytes = 1024
	// ReplyHello 表示服务器返回了 Hello。
	// ReplyHello means the server returned Hello.
	ReplyHello = "HELLO"
	// ReplyException 表示服务器返回了 Exception。探针就此停止。
	// ReplyException means the server returned Exception. The probe stops at that response.
	ReplyException = "EXCEPTION"
)

// helloMessage 是一条客户端修订号为 0 的 Hello。客户端名和用户名都是 vesper，数据库和口令都为空。
// 修订号 0 低于服务器开始附加时区、显示名和 addendum 的阈值，因此应答停在协议修订号，服务器也不会等待 addendum。
// helloMessage is one Hello whose client revision is 0. The client name and user are both vesper, and the database and password are empty.
// Revision 0 is below the thresholds where a server appends a timezone, display name, and addendum, so the response ends at the protocol revision and the server does not wait for an addendum.
var helloMessage = []byte{
	0x00,
	0x06, 'v', 'e', 's', 'p', 'e', 'r',
	0x00, 0x00, 0x00,
	0x00,
	0x06, 'v', 'e', 's', 'p', 'e', 'r',
	0x00,
}

// Result 是一次 ClickHouse Hello 应答观察。
// Result is one ClickHouse Hello response observation.
type Result struct {
	Reply            string
	ServerVersion    string
	ProtocolRevision int
	ExceptionCode    int
	ExceptionName    string
	Raw              []byte
	IsClickHouse     bool
	State            string
	Message          string
}

// ProbeForPort 按端口提示选择探针。只有 9000 选择 ClickHouse，其他端口没有该探针。
// ProbeForPort selects a probe from the port hint. Only port 9000 selects ClickHouse. Every other port has no ClickHouse probe.
func ProbeForPort(port int) string {
	if port == HintPort {
		return Name
	}
	return ""
}

// Probe 发送一条 Hello，并最多读取 1024 字节的第一条应答。它不发送查询、Ping 或 addendum，也不协商 TLS。
// Probe sends one Hello and reads at most 1024 bytes of the first response. It sends no query, Ping, or addendum, and it does not negotiate TLS.
//
// 口令字段为空，且不改用其他用户重试。即使服务器接受了这条 Hello，探针也立即关闭连接，不使用已经建立的会话。
// 包类型 0 是 Hello：服务器名必须是非空可打印 ASCII，主版本至少是 1，次版本和协议修订号必须完整。包类型 2 是 Exception：小端 int32 错误码、由大写字母数字和下划线组成的错误名、非空消息、堆栈和值为 0 的 nested 标志必须完整。其他包类型不记为 ClickHouse。服务器名和异常消息不作为产品。
// The password field is empty, and the probe does not retry with another user. Even when the server accepts this Hello, the probe closes the connection immediately and does not use the established session.
// Packet type 0 is Hello: the server name must be non-empty printable ASCII, the major version must be at least 1, and the minor version and protocol revision must be complete. Packet type 2 is Exception: a little-endian int32 code, an error name of uppercase letters, digits, and underscores, a non-empty message, a stack string, and a nested flag of 0 must all be complete. Every other packet type is not ClickHouse. The server name and exception message are not a product.
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
	if _, err := conn.Write(helloMessage); err != nil {
		return Result{State: "error", Message: err.Error()}, err
	}
	stream := &stream{conn: conn}
	result, ok := response(stream)
	raw := stream.buf
	if ok {
		raw = stream.buf[:stream.off]
	}
	if len(raw) == 0 && stream.err != nil {
		return Result{State: "error", Message: stream.err.Error()}, stream.err
	}
	result.Raw = append([]byte(nil), raw...)
	result.IsClickHouse = ok
	result.State = "open"
	return result, nil
}

type stream struct {
	conn interface {
		Read([]byte) (int, error)
	}
	buf []byte
	off int
	err error
}

func (s *stream) byte() (byte, bool) {
	if s.off < len(s.buf) {
		b := s.buf[s.off]
		s.off++
		return b, true
	}
	if len(s.buf) >= MaxResponseBytes || s.err != nil {
		return 0, false
	}
	tmp := make([]byte, MaxResponseBytes-len(s.buf))
	n, err := s.conn.Read(tmp)
	if n > 0 {
		s.buf = append(s.buf, tmp[:n]...)
	}
	if err != nil {
		s.err = err
	}
	if s.off >= len(s.buf) {
		return 0, false
	}
	b := s.buf[s.off]
	s.off++
	return b, true
}

func (s *stream) varuint() (uint64, bool) {
	var value uint64
	for i := 0; i < 10; i++ {
		b, ok := s.byte()
		if !ok {
			return 0, false
		}
		if b < 0x80 {
			if i == 9 && b > 1 || i > 0 && b == 0 {
				return 0, false
			}
			return value | uint64(b)<<uint(7*i), true
		}
		value |= uint64(b&0x7f) << uint(7*i)
	}
	return 0, false
}

func (s *stream) text(limit int) (string, bool) {
	n, ok := s.varuint()
	if !ok || n > uint64(limit) || s.off > MaxResponseBytes-int(n) {
		return "", false
	}
	raw := make([]byte, int(n))
	for i := range raw {
		b, ok := s.byte()
		if !ok {
			return "", false
		}
		raw[i] = b
	}
	return string(raw), true
}

func (s *stream) fixed(n int) ([]byte, bool) {
	raw := make([]byte, n)
	for i := range raw {
		b, ok := s.byte()
		if !ok {
			return nil, false
		}
		raw[i] = b
	}
	return raw, true
}

func response(s *stream) (Result, bool) {
	kind, ok := s.varuint()
	if !ok {
		return Result{}, false
	}
	switch kind {
	case 0:
		return hello(s)
	case 2:
		return exception(s)
	default:
		return Result{}, false
	}
}

func hello(s *stream) (Result, bool) {
	name, ok := s.text(128)
	if !ok || !printable(name) {
		return Result{}, false
	}
	major, ok := s.varuint()
	if !ok || major < 1 || major > 65535 {
		return Result{}, false
	}
	minor, ok := s.varuint()
	if !ok || minor > 65535 {
		return Result{}, false
	}
	revision, ok := s.varuint()
	if !ok || revision < 1 || revision > 10000000 {
		return Result{}, false
	}
	return Result{Reply: ReplyHello, ServerVersion: fmt.Sprintf("%d.%d", major, minor), ProtocolRevision: int(revision)}, true
}

func exception(s *stream) (Result, bool) {
	raw, ok := s.fixed(4)
	if !ok {
		return Result{}, false
	}
	name, ok := s.text(64)
	if !ok || !errorName(name) {
		return Result{}, false
	}
	message, ok := s.text(768)
	if !ok || message == "" {
		return Result{}, false
	}
	if _, ok = s.text(256); !ok {
		return Result{}, false
	}
	nested, ok := s.byte()
	if !ok || nested != 0 {
		return Result{}, false
	}
	return Result{Reply: ReplyException, ExceptionCode: int(int32(binary.LittleEndian.Uint32(raw))), ExceptionName: name}, true
}

func printable(value string) bool {
	if value == "" {
		return false
	}
	for i := 0; i < len(value); i++ {
		if value[i] < 0x20 || value[i] > 0x7e {
			return false
		}
	}
	return true
}

func errorName(value string) bool {
	if value == "" {
		return false
	}
	for i := 0; i < len(value); i++ {
		b := value[i]
		if b != '_' && (b < 'A' || b > 'Z') && (b < '0' || b > '9') {
			return false
		}
	}
	return true
}
