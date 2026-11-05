// Package imapprobe 读取 IMAP 问候行，不发送命令，也不用端口号推断 IMAP 服务。
// Package imapprobe reads the IMAP greeting. It sends no command and does not infer an IMAP service from the port number.
package imapprobe

import (
	"bytes"
	"context"
	"net/netip"
	"time"

	"github.com/zodirc/Vesper/pkg/probesdk"
)

const (
	// Name 是探针名称。它表示 IMAP 线协议，不表示邮件产品。
	// Name is the probe name. It names the IMAP wire protocol, not a mail product.
	Name = "imap"
	// HintPort 是选择该探针的端口提示。应答不匹配时仍不记录 IMAP。
	// HintPort is the port hint that selects this probe. A non-matching response is still not recorded as IMAP.
	HintPort = 143
	// MaxBannerBytes 是一条问候行的读取上限。RFC 3501 把一行限制在 512 字节以内，字面量除外；问候行不包含字面量。
	// MaxBannerBytes is the read limit for one greeting. RFC 3501 limits a line to 512 bytes except for literals; a greeting contains no literal.
	MaxBannerBytes = 512
)

// Result 是一次 IMAP 问候观察。
// Result is one IMAP greeting observation.
type Result struct {
	Reply   string
	Status  string
	Raw     []byte
	IsIMAP  bool
	State   string
	Message string
}

// ProbeForPort 按端口提示选择探针。只有 143 选择 IMAP，其他端口没有该探针。
// ProbeForPort selects a probe from the port hint. Only port 143 selects IMAP. Every other port has no IMAP probe.
func ProbeForPort(port int) string {
	if port == HintPort {
		return Name
	}
	return ""
}

// Probe 在连接成功后最多读取 512 字节的第一行。它不发送 CAPABILITY、STARTTLS 或 LOGIN。
// Probe reads at most 512 bytes of the first line after the connection succeeds. It sends no CAPABILITY, STARTTLS, or LOGIN.
//
// 第一行必须以 CRLF 结束，并且是 * OK、* PREAUTH 或 * BYE，后面是结尾或空格。其他文本不记为 IMAP。
// The first line is IMAP only when it ends in CRLF and is * OK, * PREAUTH, or * BYE followed by the end or a space. Any other text is not IMAP.
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
	raw, err := readLine(conn)
	if len(raw) == 0 && err != nil {
		return Result{State: "error", Message: err.Error()}, err
	}
	reply, status, ok := greeting(raw)
	return Result{Reply: reply, Status: status, Raw: append([]byte(nil), raw...), IsIMAP: ok, State: "open"}, nil
}

func readLine(conn interface {
	Read([]byte) (int, error)
}) ([]byte, error) {
	buf := make([]byte, MaxBannerBytes)
	total := 0
	var err error
	for total < MaxBannerBytes {
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
	for _, status := range []string{"* OK", "* PREAUTH", "* BYE"} {
		token := []byte(status)
		if bytes.Equal(line, token) || bytes.HasPrefix(line, append(append([]byte(nil), token...), ' ')) {
			return string(line), status, true
		}
	}
	return "", "", false
}
