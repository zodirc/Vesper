// Package ftpprobe 读取 FTP 问候应答，不发送命令，也不用端口号推断 FTP 服务。
// Package ftpprobe reads the FTP greeting and does not send a command or infer an FTP service from the port number.
package ftpprobe

import (
	"bufio"
	"context"
	"net/netip"
	"time"
	"unicode"

	"github.com/zodirc/Vesper/pkg/probesdk"
)

const (
	// Name 是探针名称。
	// Name is the probe name.
	Name = "ftp"
	// HintPort 是选择该探针的端口提示。应答不匹配时仍不记录 FTP。
	// HintPort is the port hint that selects this probe. A non-matching response is still not recorded as FTP.
	HintPort = 21
	// MaxBannerBytes 是问候应答的读取上限。RFC 959 把一条应答行限制在 512 字节以内。
	// MaxBannerBytes is the greeting read limit. RFC 959 limits one reply line to 512 bytes.
	MaxBannerBytes = 512
)

// Result 是一次 FTP 问候观察。
// Result is one FTP greeting observation.
type Result struct {
	Banner    string
	ReplyCode string
	Raw       []byte
	IsFTP     bool
	State     string
	Message   string
}

// ProbeForPort 按端口提示选择探针。只有 21 选择 FTP，其他端口没有该探针。
// ProbeForPort selects a probe from the port hint. Only port 21 selects FTP. Every other port has no FTP probe.
func ProbeForPort(port int) string {
	if port == HintPort {
		return Name
	}
	return ""
}

// Probe 在连接成功后最多读取 512 字节，并在第一个换行处结束。它不向服务器发送任何字节。
// Probe reads at most 512 bytes after the connection succeeds and stops at the first newline. It sends no bytes to the server.
//
// 第一行以 100–599 的三位应答码开始，并且后面是空格或连字符时，才记为 FTP。其他文本保持已连接，但不记为 FTP。
// The first line is FTP only when it begins with a three-digit reply code from 100 through 599 followed by a space or hyphen. Any other text stays connected and is not recorded as FTP.
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
	reader := bufio.NewReaderSize(conn, MaxBannerBytes)
	line, err := reader.ReadSlice('\n')
	if len(line) > MaxBannerBytes {
		line = line[:MaxBannerBytes]
	}
	raw := append([]byte(nil), line...)
	banner := trimLine(raw)
	if len(raw) == 0 && err != nil {
		return Result{State: "error", Message: err.Error()}, err
	}
	code, ok := replyCode(banner)
	return Result{Banner: banner, ReplyCode: code, Raw: raw, IsFTP: ok, State: "open"}, nil
}

func trimLine(raw []byte) string {
	end := len(raw)
	for end > 0 && (raw[end-1] == '\n' || raw[end-1] == '\r' || raw[end-1] == ' ' || raw[end-1] == '\t') {
		end--
	}
	return string(raw[:end])
}

func replyCode(line string) (string, bool) {
	if len(line) < 4 {
		return "", false
	}
	for i := 0; i < 3; i++ {
		if !unicode.IsDigit(rune(line[i])) {
			return "", false
		}
	}
	if line[0] < '1' || line[0] > '5' {
		return "", false
	}
	if line[3] != ' ' && line[3] != '-' {
		return "", false
	}
	return line[:3], true
}
