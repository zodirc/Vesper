// Package pop3probe 读取 POP3 问候行，不发送命令，也不用端口号推断 POP3 服务。
// Package pop3probe reads the POP3 greeting. It sends no command and does not infer a POP3 service from the port number.
package pop3probe

import (
	"bytes"
	"context"
	"net/netip"
	"time"

	"github.com/zodirc/Vesper/pkg/probesdk"
)

const (
	// Name 是探针名称。它表示 POP3 线协议，不表示邮件产品。
	// Name is the probe name. It names the POP3 wire protocol, not a mail product.
	Name = "pop3"
	// HintPort 是选择该探针的端口提示。应答不匹配时仍不记录 POP3。
	// HintPort is the port hint that selects this probe. A non-matching response is still not recorded as POP3.
	HintPort = 110
	// MaxBannerBytes 是一条问候行的读取上限。RFC 1939 把响应限制在 512 字节以内。
	// MaxBannerBytes is the read limit for one greeting. RFC 1939 limits a response to 512 bytes.
	MaxBannerBytes = 512
)

// Result 是一次 POP3 问候观察。
// Result is one POP3 greeting observation.
type Result struct {
	Reply     string
	ReplyCode string
	Raw       []byte
	IsPOP3    bool
	State     string
	Message   string
}

// ProbeForPort 按端口提示选择探针。只有 110 选择 POP3，其他端口没有该探针。
// ProbeForPort selects a probe from the port hint. Only port 110 selects POP3. Every other port has no POP3 probe.
func ProbeForPort(port int) string {
	if port == HintPort {
		return Name
	}
	return ""
}

// Probe 在连接成功后最多读取 512 字节的第一行。它不发送 CAPA、STLS、USER 或 PASS。
// Probe reads at most 512 bytes of the first line after the connection succeeds. It sends no CAPA, STLS, USER, or PASS.
//
// 第一行必须以 CRLF 结束，并且整行是 +OK 或 -ERR，后面是结尾或空格。其他文本不记为 POP3。
// The first line is POP3 only when it ends in CRLF and the whole line is +OK or -ERR followed by the end or a space. Any other text is not POP3.
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
	raw, err := readLine(conn, MaxBannerBytes)
	if len(raw) == 0 && err != nil {
		return Result{State: "error", Message: err.Error()}, err
	}
	reply, code, ok := greeting(raw)
	return Result{Reply: reply, ReplyCode: code, Raw: append([]byte(nil), raw...), IsPOP3: ok, State: "open"}, nil
}

func readLine(conn interface {
	Read([]byte) (int, error)
}, limit int) ([]byte, error) {
	buf := make([]byte, limit)
	total := 0
	var err error
	for total < limit {
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

func greeting(raw []byte) (string, string, bool) {
	if !bytes.HasSuffix(raw, []byte("\r\n")) || bytes.Contains(raw[:len(raw)-2], []byte("\n")) {
		return "", "", false
	}
	line := raw[:len(raw)-2]
	code, rest, ok := cutStatus(line)
	if !ok {
		return "", "", false
	}
	return string(line), code, rest
}

func cutStatus(line []byte) (string, bool, bool) {
	for _, code := range []string{"+OK", "-ERR"} {
		token := []byte(code)
		if bytes.Equal(line, token) {
			return code, true, true
		}
		if bytes.HasPrefix(line, append(token, ' ')) {
			return code, true, true
		}
	}
	return "", false, false
}
