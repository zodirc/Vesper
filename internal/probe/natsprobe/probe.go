// Package natsprobe 读取 NATS 的 INFO 行，不发送 CONNECT，也不用端口号推断 NATS 服务。
// Package natsprobe reads the NATS INFO line. It sends no CONNECT and does not infer a NATS service from the port number.
package natsprobe

import (
	"bytes"
	"context"
	"encoding/json"
	"net/netip"
	"time"

	"github.com/zodirc/Vesper/pkg/probesdk"
)

const (
	// Name 是探针名称。它表示 NATS 线协议，不表示发行方。
	// Name is the probe name. It names the NATS wire protocol, not a vendor.
	Name = "nats"
	// HintPort 是选择该探针的端口提示。应答不匹配时仍不记录 NATS。
	// HintPort is the port hint that selects this probe. A non-matching response is still not recorded as NATS.
	HintPort = 4222
	// MaxInfoBytes 是一条 INFO 行的读取上限，含结尾的 CRLF。
	// MaxInfoBytes is the read limit for one INFO line, including its terminating CRLF.
	MaxInfoBytes = 4096
)

// Result 是一次 NATS INFO 观察。
// Result is one NATS INFO observation.
type Result struct {
	ServerVersion string
	Raw           []byte
	IsNATS        bool
	State         string
	Message       string
}

// ProbeForPort 按端口提示选择探针。只有 4222 选择 NATS，其他端口没有该探针。
// ProbeForPort selects a probe from the port hint. Only port 4222 selects NATS. Every other port has no NATS probe.
func ProbeForPort(port int) string {
	if port == HintPort {
		return Name
	}
	return ""
}

// Probe 在连接成功后最多读取 4096 字节的第一行。它不发送 CONNECT、PING、SUB 或 PUB。
// Probe reads at most 4096 bytes of the first line after the connection succeeds. It sends no CONNECT, PING, SUB, or PUB.
//
// 第一行必须是 INFO、空格、一个 JSON 对象和 CRLF。version 字符串原样保存。对象里的其他字段留在原始证据中，不写入观察值，也不据此判断发行方。
// The first line is NATS only when it is INFO, a space, one JSON object, and CRLF. A version string is stored verbatim. Other object fields stay in the raw evidence and are not written into the observation or used to infer a vendor.
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
	version, ok := infoVersion(raw)
	return Result{ServerVersion: version, Raw: append([]byte(nil), raw...), IsNATS: ok, State: "open"}, nil
}

func readLine(conn interface {
	Read([]byte) (int, error)
}) ([]byte, error) {
	buf := make([]byte, MaxInfoBytes)
	total := 0
	var err error
	for total < MaxInfoBytes {
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

func infoVersion(raw []byte) (string, bool) {
	if len(raw) < len("INFO {}\r\n") || !bytes.HasSuffix(raw, []byte("\r\n")) || bytes.Contains(raw[:len(raw)-2], []byte("\n")) {
		return "", false
	}
	payload, ok := bytes.CutPrefix(raw[:len(raw)-2], []byte("INFO "))
	if !ok || len(payload) < 2 || payload[0] != '{' || payload[len(payload)-1] != '}' {
		return "", false
	}
	var info struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(payload, &info); err != nil {
		return "", false
	}
	return info.Version, true
}
