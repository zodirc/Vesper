// Package telnetprobe 读取 Telnet 初始字节，不发送协商，也不用端口号推断 Telnet 服务。
// Package telnetprobe reads the initial Telnet bytes. It sends no negotiation and does not infer a Telnet service from the port number.
package telnetprobe

import (
	"bytes"
	"context"
	"net/netip"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/zodirc/Vesper/pkg/probesdk"
)

const (
	// Name 是探针名称。它表示 Telnet 线协议，不表示终端产品。
	// Name is the probe name. It names the Telnet wire protocol, not a terminal product.
	Name = "telnet"
	// HintPort 是选择该探针的端口提示。应答不匹配时仍不记录 Telnet。
	// HintPort is the port hint that selects this probe. A non-matching response is still not recorded as Telnet.
	HintPort = 23
	// MaxBannerBytes 是读取上限。RFC 854 的协商和一条登录提示都落在这个长度内。
	// MaxBannerBytes is the read limit. An RFC 854 negotiation and one login prompt both fit in this length.
	MaxBannerBytes = 512

	iac = 0xff
)

// Result 是一次 Telnet 初始观察。
// Result is one initial Telnet observation.
type Result struct {
	Banner   string
	Raw      []byte
	IsTelnet bool
	State    string
	Message  string
}

// ProbeForPort 按端口提示选择探针。只有 23 选择 Telnet，其他端口没有该探针。
// ProbeForPort selects a probe from the port hint. Only port 23 selects Telnet. Every other port has no Telnet probe.
func ProbeForPort(port int) string {
	if port == HintPort {
		return Name
	}
	return ""
}

// Probe 在连接成功后最多读取 512 字节。它不发送 IAC、用户名或口令。
// Probe reads at most 512 bytes after the connection succeeds. It sends no IAC, username, or password.
//
// 出现 IAC 命令，或一条以 CRLF 结束且包含 login: 的可打印行时，才记为 Telnet。单独的可打印横幅不记为 Telnet。
// The response is Telnet only when it contains an IAC command, or one printable line ending in CRLF that contains login:. A printable banner by itself is not Telnet.
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
	raw, err := readBanner(conn)
	if len(raw) == 0 && err != nil {
		return Result{State: "error", Message: err.Error()}, err
	}
	banner, ok := match(raw)
	return Result{Banner: banner, Raw: append([]byte(nil), raw...), IsTelnet: ok, State: "open"}, nil
}

func readBanner(conn interface {
	Read([]byte) (int, error)
}) ([]byte, error) {
	buf := make([]byte, MaxBannerBytes)
	total := 0
	var err error
	for total < MaxBannerBytes {
		var n int
		n, err = conn.Read(buf[total:])
		total += n
		if hasIAC(buf[:total]) || bytes.Contains(buf[:total], []byte("\n")) {
			return buf[:total], nil
		}
		if n == 0 || err != nil {
			return buf[:total], err
		}
	}
	return buf[:total], nil
}

func match(raw []byte) (string, bool) {
	if hasIAC(raw) {
		return "", true
	}
	if bytes.Contains(raw, []byte("HTTP/")) || !bytes.Contains(raw, []byte("\r\n")) {
		return "", false
	}
	for _, line := range bytes.Split(raw, []byte("\n")) {
		if !bytes.HasSuffix(line, []byte("\r")) {
			continue
		}
		line = line[:len(line)-1]
		if bytes.Contains(bytes.ToLower(line), []byte("login:")) && printable(line) {
			return string(line), true
		}
	}
	return "", false
}

func hasIAC(raw []byte) bool {
	for i := 0; i+1 < len(raw); i++ {
		if raw[i] != iac {
			continue
		}
		cmd := raw[i+1]
		if cmd == iac {
			i++
			continue
		}
		if cmd >= 240 && cmd <= 254 {
			return true
		}
	}
	return false
}

func printable(raw []byte) bool {
	if len(raw) == 0 || !utf8.Valid(raw) {
		return false
	}
	for _, r := range string(raw) {
		if r != '\t' && !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}
