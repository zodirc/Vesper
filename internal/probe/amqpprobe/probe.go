// Package amqpprobe 发送 AMQP 0-9-1 协议头，确认对端协议头或 connection.start 后立即关闭。
// Package amqpprobe sends the AMQP 0-9-1 protocol header and closes as soon as the peer header or connection.start is recognized.
package amqpprobe

import (
	"bytes"
	"context"
	"encoding/binary"
	"net/netip"
	"time"

	"github.com/zodirc/Vesper/pkg/probesdk"
)

const (
	// Name 是探针名称。它表示 AMQP 线协议，不表示消息中间件产品。
	// Name is the probe name. It names the AMQP wire protocol, not a messaging product.
	Name = "amqp"
	// HintPort 是选择该探针的端口提示。应答不匹配时仍不记录 AMQP。
	// HintPort is the port hint that selects this probe. A non-matching response is still not recorded as AMQP.
	HintPort = 5672
	// MaxReplyBytes 是第一段应答的读取上限。connection.start 的参数可以更长，识别只需要方法头。
	// MaxReplyBytes is the read limit for the first reply. connection.start arguments can be longer; identification needs only the method header.
	MaxReplyBytes = 512
)

// protocolHeader 是 AMQP 0-9-1 的 8 字节协议头。探针只发送这一段，不发送 connection.start-ok。
// protocolHeader is the 8-byte AMQP 0-9-1 protocol header. The probe sends only this header and no connection.start-ok.
var protocolHeader = []byte{'A', 'M', 'Q', 'P', 0x00, 0x00, 0x09, 0x01}

// Request 返回探针发送的协议头副本。
// Request returns a copy of the protocol header sent by the probe.
func Request() []byte {
	return append([]byte(nil), protocolHeader...)
}

// Result 是一次 AMQP 初始观察。
// Result is one initial AMQP observation.
type Result struct {
	Reply   string
	Raw     []byte
	IsAMQP  bool
	State   string
	Message string
}

// ProbeForPort 按端口提示选择探针。只有 5672 选择 AMQP，其他端口没有该探针。
// ProbeForPort selects a probe from the port hint. Only port 5672 selects AMQP. Every other port has no AMQP probe.
func ProbeForPort(port int) string {
	if port == HintPort {
		return Name
	}
	return ""
}

// Probe 发送 8 字节协议头，并最多读取 512 字节。它不发送 connection.start-ok、信道打开或认证。
// Probe sends the 8-byte protocol header and reads at most 512 bytes. It sends no connection.start-ok, channel open, or authentication.
//
// 应答以前 8 字节的 AMQP 协议头开始，或是信道 0 上的 connection.start 方法帧时，才记为 AMQP。服务器属性留在原始证据中，不提取产品。
// The reply is AMQP when it begins with an 8-byte AMQP protocol header, or when it is a connection.start method frame on channel 0. Server properties stay in the raw evidence and no product is extracted.
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
	if _, err := conn.Write(protocolHeader); err != nil {
		return Result{State: "error", Message: err.Error()}, err
	}
	raw, err := readReply(conn)
	if len(raw) == 0 && err != nil {
		return Result{State: "error", Message: err.Error()}, err
	}
	reply, ok := match(raw)
	return Result{Reply: reply, Raw: append([]byte(nil), raw...), IsAMQP: ok, State: "open"}, nil
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
		if header(buf[:total]) || methodStart(buf[:total]) {
			return buf[:total], nil
		}
		if n == 0 || err != nil {
			return buf[:total], err
		}
	}
	return buf[:total], nil
}

func match(raw []byte) (string, bool) {
	if header(raw) {
		return protocolID(raw[4:8]), true
	}
	if methodStart(raw) {
		return "connection.start", true
	}
	return "", false
}

func header(raw []byte) bool {
	return len(raw) >= 8 && bytes.Equal(raw[:4], []byte("AMQP"))
}

func protocolID(raw []byte) string {
	if bytes.Equal(raw, []byte{0, 0, 9, 1}) {
		return "0-9-1"
	}
	if bytes.Equal(raw, []byte{0, 1, 0, 0}) {
		return "1.0"
	}
	return "header"
}

func methodStart(raw []byte) bool {
	if len(raw) < 11 || raw[0] != 1 || raw[1] != 0 || raw[2] != 0 {
		return false
	}
	size := binary.BigEndian.Uint32(raw[3:7])
	if size < 4 || size > 4096 {
		return false
	}
	if raw[7] != 0 || raw[8] != 10 || raw[9] != 0 || raw[10] != 10 {
		return false
	}
	end := 7 + int(size)
	if len(raw) > end && raw[end] != 0xce {
		return false
	}
	return true
}
