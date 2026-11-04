// Package memcachedprobe 用一条文本 version 命令识别 Memcached 线协议，不发送 stats、get 或 set，也不用端口号推断数据库服务。
// Package memcachedprobe identifies the Memcached wire protocol with one text version command. It sends no stats, get, or set and does not infer a database service from the port number.
package memcachedprobe

import (
	"bytes"
	"context"
	"net/netip"
	"time"

	"github.com/zodirc/Vesper/pkg/probesdk"
)

const (
	// Name 是探针名称。它表示 Memcached 线协议，不表示发行方。
	// Name is the probe name. It names the Memcached wire protocol, not a vendor.
	Name = "memcached"
	// HintPort 是选择该探针的端口提示。应答不匹配时仍不记录 Memcached。
	// HintPort is the port hint that selects this probe. A non-matching response is still not recorded as Memcached.
	HintPort = 11211
	// MaxReplyBytes 是一条应答的读取上限，含结尾的 CRLF。
	// MaxReplyBytes is the read limit for one reply, including its terminating CRLF.
	MaxReplyBytes = 128
)

// versionCommand 是一条没有参数的文本 version 命令。
// versionCommand is one text version command with no argument.
var versionCommand = []byte("version\r\n")

// Result 是一次 Memcached version 应答观察。
// Result is one Memcached version reply observation.
type Result struct {
	ServerVersion string
	Raw           []byte
	IsMemcached   bool
	State         string
	Message       string
}

// ProbeForPort 按端口提示选择探针。只有 11211 选择 Memcached，其他端口没有该探针。
// ProbeForPort selects a probe from the port hint. Only port 11211 selects Memcached. Every other port has no Memcached probe.
func ProbeForPort(port int) string {
	if port == HintPort {
		return Name
	}
	return ""
}

// Probe 发送一条 version，并最多读取 128 字节的第一条应答。它不发送 stats、get、set 或后续命令，也不协商 TLS 或 SASL。
// Probe sends one version command and reads at most 128 bytes of the first reply. It sends no stats, get, set, or follow-up command, and it negotiates neither TLS nor SASL.
//
// 应答必须是一条以 CRLF 结束的行。整行必须是 VERSION 后接一个空格和一个非空、不含空格的可打印 ASCII 版本标记。ERROR 和其他命令应答不记为 Memcached。版本标记原样保存，不据此判断发行方。
// The reply is Memcached only when it is one line ending in CRLF. The whole line must be VERSION, one space, and one non-empty printable ASCII version token with no space. ERROR and other command replies are not Memcached. The version token is stored verbatim and is not used to infer a vendor.
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
	if _, err := conn.Write(versionCommand); err != nil {
		return Result{State: "error", Message: err.Error()}, err
	}
	raw, err := readLine(conn)
	if len(raw) == 0 && err != nil {
		return Result{State: "error", Message: err.Error()}, err
	}
	version, ok := reply(raw)
	return Result{ServerVersion: version, Raw: append([]byte(nil), raw...), IsMemcached: ok, State: "open"}, nil
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
	if len(raw) < len("VERSION x\r\n") || !bytes.HasSuffix(raw, []byte("\r\n")) || bytes.Contains(raw[:len(raw)-2], []byte("\n")) {
		return "", false
	}
	body := raw[:len(raw)-2]
	token, ok := bytes.CutPrefix(body, []byte("VERSION "))
	if !ok || len(token) == 0 || bytes.Contains(token, []byte(" ")) {
		return "", false
	}
	for _, b := range token {
		if b < 0x21 || b > 0x7e {
			return "", false
		}
	}
	return string(token), true
}
