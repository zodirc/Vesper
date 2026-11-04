// Package redisprobe 用一条 RESP PING 识别 Redis 线协议，不发送 AUTH、INFO 或其他命令，也不用端口号推断数据库服务。
// Package redisprobe identifies the Redis wire protocol with one RESP PING. It sends no AUTH, INFO, or other command and does not infer a database service from the port number.
package redisprobe

import (
	"bytes"
	"context"
	"net/netip"
	"time"

	"github.com/zodirc/Vesper/pkg/probesdk"
)

const (
	// Name 是探针名称。它表示 Redis 线协议，不表示发行方。
	// Name is the probe name. It names the Redis wire protocol, not a vendor.
	Name = "redis"
	// HintPort 是选择该探针的端口提示。应答不匹配时仍不记录 Redis。
	// HintPort is the port hint that selects this probe. A non-matching response is still not recorded as Redis.
	HintPort = 6379
	// MaxReplyBytes 是一条应答的读取上限，含结尾的 CRLF。
	// MaxReplyBytes is the read limit for one reply, including its terminating CRLF.
	MaxReplyBytes = 2048
	// ReplyPONG 表示服务器返回了简单字符串 PONG。
	// ReplyPONG means the server returned the simple string PONG.
	ReplyPONG = "PONG"
	// ReplyNOAUTH 表示服务器要求认证，探针就此停止。
	// ReplyNOAUTH means the server requires authentication. The probe stops at that reply.
	ReplyNOAUTH = "NOAUTH"
	// ReplyDENIED 表示服务器以 protected mode 拒绝了这条 PING。
	// ReplyDENIED means the server rejected this PING because protected mode is enabled.
	ReplyDENIED = "DENIED"
)

// pingCommand 是一条 RESP 数组，只包含 PING，没有参数。
// pingCommand is one RESP array containing only PING, with no argument.
var pingCommand = []byte("*1\r\n$4\r\nPING\r\n")

var (
	pongLine     = []byte("+PONG\r\n")
	noauthLine   = []byte("-NOAUTH Authentication required.\r\n")
	deniedPrefix = []byte("-DENIED Redis is running in protected mode")
)

// Result 是一次 Redis PING 应答观察。
// Result is one Redis PING reply observation.
type Result struct {
	Reply   string
	Raw     []byte
	IsRedis bool
	State   string
	Message string
}

// ProbeForPort 按端口提示选择探针。只有 6379 选择 Redis，其他端口没有该探针。
// ProbeForPort selects a probe from the port hint. Only port 6379 selects Redis. Every other port has no Redis probe.
func ProbeForPort(port int) string {
	if port == HintPort {
		return Name
	}
	return ""
}

// Probe 发送一条 PING，并最多读取 2048 字节的第一条应答。它不发送 AUTH、INFO 或后续命令。
// Probe sends one PING and reads at most 2048 bytes of the first reply. It sends no AUTH, INFO, or follow-up command.
//
// 应答必须是一条以 CRLF 结束的 RESP 行。只有整行等于 +PONG、整行等于 -NOAUTH Authentication required.，或以 -DENIED Redis is running in protected mode 开头时才记为 Redis。其他错误和批量字符串都不记为 Redis。
// The reply is Redis only when it is one RESP line ending in CRLF. The whole line must equal +PONG, equal -NOAUTH Authentication required., or begin with -DENIED Redis is running in protected mode. Other errors and bulk strings are not Redis.
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
	if _, err := conn.Write(pingCommand); err != nil {
		return Result{State: "error", Message: err.Error()}, err
	}
	raw, err := readLine(conn)
	if len(raw) == 0 && err != nil {
		return Result{State: "error", Message: err.Error()}, err
	}
	kind, ok := reply(raw)
	return Result{Reply: kind, Raw: append([]byte(nil), raw...), IsRedis: ok, State: "open"}, nil
}

func readLine(conn interface {
	Read([]byte) (int, error)
}) ([]byte, error) {
	buf := make([]byte, MaxReplyBytes)
	total := 0
	var err error
	for total < MaxReplyBytes {
		var n int
		n, err = conn.Read(buf[total:])
		total += n
		if end := bytes.Index(buf[:total], []byte("\r\n")); end >= 0 {
			return buf[:end+2], nil
		}
		if n == 0 || err != nil {
			return buf[:total], err
		}
	}
	return buf[:total], nil
}

func reply(raw []byte) (string, bool) {
	if len(raw) < 3 || !bytes.HasSuffix(raw, []byte("\r\n")) || bytes.Contains(raw[:len(raw)-2], []byte("\r\n")) {
		return "", false
	}
	switch {
	case bytes.Equal(raw, pongLine):
		return ReplyPONG, true
	case bytes.Equal(raw, noauthLine):
		return ReplyNOAUTH, true
	case bytes.HasPrefix(raw, deniedPrefix) && printable(raw[:len(raw)-2]):
		return ReplyDENIED, true
	default:
		return "", false
	}
}

func printable(line []byte) bool {
	for _, item := range line {
		if item < 0x20 || item > 0x7e {
			return false
		}
	}
	return true
}
