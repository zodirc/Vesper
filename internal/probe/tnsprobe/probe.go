// Package tnsprobe 用一条 TNS CONNECT 识别监听器线协议。命令只有 ping，不发送口令，不跟随重定向，也不用端口号推断数据库服务。
// Package tnsprobe identifies the TNS listener wire protocol with one CONNECT. The command is only ping. It sends no password, does not follow a redirect, and does not infer a database service from the port number.
package tnsprobe

import (
	"bytes"
	"context"
	"net/netip"
	"strconv"
	"time"

	"github.com/zodirc/Vesper/pkg/probesdk"
)

const (
	// Name 是探针名称。它表示 TNS 线协议，不表示发行方。
	// Name is the probe name. It names the TNS wire protocol, not a vendor.
	Name = "tns"
	// HintPort 是选择该探针的端口提示。应答不匹配时仍不记录 TNS。
	// HintPort is the port hint that selects this probe. A non-matching response is still not recorded as TNS.
	HintPort = 1521
	// MaxPacketBytes 是一个 TNS 包的读取上限，含包头。
	// MaxPacketBytes is the read limit for one TNS packet, including its header.
	MaxPacketBytes = 1024
)

// pingMessage 是一条 CONNECT。连接数据只有 (CONNECT_DATA=(COMMAND=ping))，没有口令、服务名或地址。
// pingMessage is one CONNECT. Its connect data is only (CONNECT_DATA=(COMMAND=ping)), with no password, service name, or address.
var pingMessage = []byte{
	0x00, 0x57, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
	0x01, 0x36, 0x01, 0x2c, 0x00, 0x00, 0x08, 0x00,
	0x7f, 0xff, 0x7f, 0x08, 0x00, 0x00, 0x00, 0x01,
	0x00, 0x1d, 0x00, 0x3a, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x34, 0xe6, 0x00, 0x00,
	0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00,
	'(', 'C', 'O', 'N', 'N', 'E', 'C', 'T', '_', 'D', 'A', 'T', 'A', '=', '(', 'C', 'O', 'M', 'M', 'A', 'N', 'D', '=', 'p', 'i', 'n', 'g', ')', ')',
}

// Result 是一次 TNS 监听器应答观察。
// Result is one TNS listener response observation.
type Result struct {
	ServerVersion string
	ErrorCode     int
	Raw           []byte
	IsTNS         bool
	State         string
	Message       string
}

// ProbeForPort 按端口提示选择探针。只有 1521 选择 TNS，其他端口没有该探针。
// ProbeForPort selects a probe from the port hint. Only port 1521 selects TNS. Every other port has no TNS probe.
func ProbeForPort(port int) string {
	if port == HintPort {
		return Name
	}
	return ""
}

// Probe 发送一条 CONNECT，并最多读取 1024 字节的第一个 TNS 包。它不重发，不跟随重定向，也不开始 TLS。
// Probe sends one CONNECT and reads at most 1024 bytes of the first TNS packet. It does not resend, does not follow a redirect, and does not start TLS.
//
// 包类型必须是 ACCEPT、REFUSE、REDIRECT 或 DATA，长度字段必须与实际字节数一致，并且包内包含 (DESCRIPTION=。VSNNUM 按它的五个字段写成点分文本。没有 VSNNUM 或 ERR 时仍然可以确认线协议。版本文本不用于判断发行方。
// A packet is TNS only when its type is ACCEPT, REFUSE, REDIRECT, or DATA, its length field matches the bytes received, and it contains (DESCRIPTION=. VSNNUM is rendered as its five dotted fields. The wire protocol can still be confirmed when VSNNUM or ERR is absent. The version text is not used to decide a vendor.
func Probe(ctx context.Context, dial probesdk.Dialer, budget interface {
	AcquireRequest(context.Context, time.Time) error
}, ip netip.Addr, port int, now func() time.Time) (Result, error) {
	if err := budget.AcquireRequest(ctx, now()); err != nil {
		return Result{ErrorCode: -1, State: "not_scanned", Message: err.Error()}, err
	}
	conn, err := dial.DialTCP(ctx, ip, port, "protocol_probe")
	if err != nil {
		return Result{ErrorCode: -1, State: probesdk.Classify(err), Message: err.Error()}, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(dial.Timeout))
	if _, err := conn.Write(pingMessage); err != nil {
		return Result{ErrorCode: -1, State: "error", Message: err.Error()}, err
	}
	raw, err := readPacket(conn)
	if len(raw) == 0 && err != nil {
		return Result{ErrorCode: -1, State: "error", Message: err.Error()}, err
	}
	version, code, ok := listener(raw)
	return Result{ServerVersion: version, ErrorCode: code, Raw: append([]byte(nil), raw...), IsTNS: ok, State: "open"}, nil
}

func readPacket(conn interface {
	Read([]byte) (int, error)
}) ([]byte, error) {
	buf := make([]byte, MaxPacketBytes)
	total := 0
	var err error
	for total < 8 {
		var n int
		n, err = conn.Read(buf[total:])
		total += n
		if n == 0 || err != nil {
			break
		}
	}
	if total < 8 {
		return buf[:total], err
	}
	length := int(buf[0])<<8 | int(buf[1])
	if length < 8 || length > MaxPacketBytes {
		return buf[:total], nil
	}
	for total < length {
		var n int
		n, err = conn.Read(buf[total:])
		total += n
		if n == 0 || err != nil {
			return buf[:total], err
		}
	}
	return buf[:length], nil
}

func listener(raw []byte) (string, int, bool) {
	if len(raw) < 8 || len(raw) > MaxPacketBytes {
		return "", -1, false
	}
	length := int(raw[0])<<8 | int(raw[1])
	if length != len(raw) || !serverType(raw[4]) || !bytes.Contains(raw[8:], []byte("(DESCRIPTION=")) {
		return "", -1, false
	}
	version := ""
	if text, ok := parameter(raw[8:], "VSNNUM"); ok {
		if decoded, ok := vsnnum(text); ok {
			version = decoded
		}
	}
	code := -1
	if text, ok := parameter(raw[8:], "ERR"); ok {
		if parsed, err := strconv.ParseUint(text, 10, 16); err == nil {
			code = int(parsed)
		}
	}
	return version, code, true
}

func serverType(kind byte) bool {
	switch kind {
	case 2, 4, 5, 6:
		return true
	default:
		return false
	}
}

func parameter(raw []byte, name string) (string, bool) {
	key := append(append([]byte("("), name...), '=')
	start := bytes.Index(raw, key)
	if start < 0 {
		return "", false
	}
	value := raw[start+len(key):]
	end := bytes.IndexByte(value, ')')
	if end <= 0 {
		return "", false
	}
	return string(value[:end]), true
}

func vsnnum(text string) (string, bool) {
	number, err := strconv.ParseUint(text, 10, 32)
	if err != nil {
		return "", false
	}
	value := uint32(number)
	return strconv.FormatUint(uint64(value>>24), 10) + "." +
		strconv.FormatUint(uint64(value>>20&0xf), 10) + "." +
		strconv.FormatUint(uint64(value>>12&0xff), 10) + "." +
		strconv.FormatUint(uint64(value>>8&0xf), 10) + "." +
		strconv.FormatUint(uint64(value&0xff), 10), true
}
