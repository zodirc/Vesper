// Package smtpprobe 读取 SMTP 问候应答，不发送命令，也不用端口号推断 SMTP 服务。
// Package smtpprobe reads the SMTP greeting and does not send a command or infer an SMTP service from the port number.
package smtpprobe

import (
	"bufio"
	"context"
	"crypto/tls"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/zodirc/Vesper/pkg/probesdk"
)

const (
	// Name 是探针名称。
	// Name is the probe name.
	Name = "smtp"
	// TransportPlain 表示直接读取明文问候。端口 25 和 587 使用这种传输。
	// TransportPlain reads the greeting in plaintext. Ports 25 and 587 use this transport.
	TransportPlain = "plain"
	// TransportTLS 表示先完成 TLS 握手再读取问候。端口 465 使用这种传输。
	// TransportTLS completes a TLS handshake before reading the greeting. Port 465 uses this transport.
	TransportTLS = "tls"
	// MaxBannerBytes 是一条问候行的读取上限。RFC 5321 把文本行限制在 1000 字节以内，含 CRLF。
	// MaxBannerBytes is the read limit for one greeting line. RFC 5321 limits a text line, including CRLF, to 1000 bytes.
	MaxBannerBytes = 1000
)

// Result 是一次 SMTP 问候观察。
// Result is one SMTP greeting observation.
type Result struct {
	Banner    string
	ReplyCode string
	Raw       []byte
	IsSMTP    bool
	State     string
	Message   string
}

// ProbeForPort 按端口提示选择传输方式。25 和 587 是明文，465 是 TLS。其他端口不选择 SMTP。
// ProbeForPort selects the transport from the port hint. Ports 25 and 587 are plaintext, and port 465 is TLS. Every other port does not select SMTP.
func ProbeForPort(port int) (string, bool) {
	switch port {
	case 25, 587:
		return TransportPlain, true
	case 465:
		return TransportTLS, true
	default:
		return "", false
	}
}

// Probe 连接成功后最多读取 1000 字节，并在第一个换行处结束。它不发送 EHLO、HELO 或 STARTTLS。
// Probe reads at most 1000 bytes after the connection succeeds and stops at the first newline. It does not send EHLO, HELO, or STARTTLS.
//
// transport 为 tls 时先完成握手，证书校验关闭，因为这里采集问候而不是建立可信邮件会话。hostname 只用作 SNI。
// When transport is tls, it completes the handshake first. Certificate verification is disabled because the probe collects the greeting rather than establishing a trusted mail session. hostname is used only as SNI.
//
// 第一行的应答码必须是 220 或 554，后接空格或连字符，并且文本包含 smtp。FTP 的 220 文本因此不会被记为 SMTP。
// The first line is SMTP only when its reply code is 220 or 554, the next character is a space or hyphen, and the text contains smtp. An FTP 220 greeting is therefore not recorded as SMTP.
func Probe(ctx context.Context, dial probesdk.Dialer, budget interface {
	AcquireRequest(context.Context, time.Time) error
}, ip netip.Addr, port int, hostname, transport string, now func() time.Time) (Result, error) {
	if err := budget.AcquireRequest(ctx, now()); err != nil {
		return Result{State: "not_scanned", Message: err.Error()}, err
	}
	conn, err := dial.DialTCP(ctx, ip, port, "protocol_probe")
	if err != nil {
		return Result{State: probesdk.Classify(err), Message: err.Error()}, err
	}
	defer conn.Close()
	deadline := time.Now().Add(dial.Timeout)
	_ = conn.SetDeadline(deadline)
	readerConn := net.Conn(conn)
	if transport == TransportTLS {
		tlsConn := tls.Client(conn, &tls.Config{ServerName: hostname, InsecureSkipVerify: true, MinVersion: tls.VersionTLS10})
		_ = tlsConn.SetDeadline(deadline)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return Result{State: "error", Message: err.Error()}, err
		}
		readerConn = tlsConn
	}
	reader := bufio.NewReaderSize(readerConn, MaxBannerBytes)
	line, err := reader.ReadSlice('\n')
	if len(line) > MaxBannerBytes {
		line = line[:MaxBannerBytes]
	}
	raw := append([]byte(nil), line...)
	banner := trimLine(raw)
	if len(raw) == 0 && err != nil {
		return Result{State: "error", Message: err.Error()}, err
	}
	code, ok := greeting(banner)
	return Result{Banner: banner, ReplyCode: code, Raw: raw, IsSMTP: ok, State: "open"}, nil
}

func trimLine(raw []byte) string {
	end := len(raw)
	for end > 0 && (raw[end-1] == '\n' || raw[end-1] == '\r' || raw[end-1] == ' ' || raw[end-1] == '\t') {
		end--
	}
	return string(raw[:end])
}

func greeting(line string) (string, bool) {
	if len(line) < 4 {
		return "", false
	}
	code := line[:3]
	if code != "220" && code != "554" {
		return "", false
	}
	if line[3] != ' ' && line[3] != '-' {
		return "", false
	}
	if !strings.Contains(strings.ToLower(line), "smtp") {
		return "", false
	}
	return code, true
}
