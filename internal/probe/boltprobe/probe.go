// Package boltprobe 用一次 Bolt 版本协商识别线协议，不发送 HELLO 或认证，也不用端口号推断数据库服务。
// Package boltprobe identifies the Bolt wire protocol with one version negotiation. It sends no HELLO or authentication and does not infer a database service from the port number.
package boltprobe

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"github.com/zodirc/Vesper/pkg/probesdk"
)

const (
	// Name 是探针名称。它表示 Bolt 线协议，不表示发行方。
	// Name is the probe name. It names the Bolt wire protocol, not a vendor.
	Name = "bolt"
	// HintPort 是选择该探针的端口提示。应答不匹配时仍不记录 Bolt。
	// HintPort is the port hint that selects this probe. A non-matching response is still not recorded as Bolt.
	HintPort = 7687
	// MaxResponseBytes 是版本应答的读取上限。协商结果是一个 4 字节整数。
	// MaxResponseBytes is the read limit for the version response. The negotiation result is one 4-byte integer.
	MaxResponseBytes = 4
)

// handshake 是固定的 20 字节协商。前 4 字节是标识 60 60 B0 17。随后四个大端版本槽依次是 5.8 向下 8 个次版本、4.4 向下 4 个次版本、4.1 和 3.0。
// 槽的字节顺序是保留字节、range、次版本、主版本。这里不发送 manifest 槽，因此服务器仍按一个 4 字节版本应答。
// handshake is the fixed 20-byte negotiation. Its first 4 bytes are the marker 60 60 B0 17. The next four big-endian version slots are 5.8 with eight earlier minor versions, 4.4 with four earlier minor versions, 4.1, and 3.0.
// A slot is ordered as the reserved byte, range, minor version, and major version. No manifest slot is sent, so the server still answers with one 4-byte version.
var handshake = []byte{
	0x60, 0x60, 0xb0, 0x17,
	0x00, 0x08, 0x08, 0x05,
	0x00, 0x04, 0x04, 0x04,
	0x00, 0x00, 0x01, 0x04,
	0x00, 0x00, 0x00, 0x03,
}

// Result 是一次 Bolt 版本协商观察。
// Result is one Bolt version-negotiation observation.
type Result struct {
	ProtocolVersion string
	Raw             []byte
	IsBolt          bool
	State           string
	Message         string
}

// ProbeForPort 按端口提示选择探针。只有 7687 选择 Bolt，其他端口没有该探针。
// ProbeForPort selects a probe from the port hint. Only port 7687 selects Bolt. Every other port has no Bolt probe.
func ProbeForPort(port int) string {
	if port == HintPort {
		return Name
	}
	return ""
}

// Probe 发送一次版本协商，并最多读取 4 字节的应答。它不发送 HELLO、认证或后续报文，也不协商 TLS，也不进入 manifest 交换。
// Probe sends one version negotiation and reads at most 4 bytes of the response. It sends no HELLO, authentication, or follow-up message, and it negotiates neither TLS nor a manifest exchange.
//
// 应答必须是 4 字节。保留字节和 range 必须是 0，主次版本必须落在请求提议的范围内。全 0 表示没有可接受的版本，不记为 Bolt。
// The response must be 4 bytes. Its reserved byte and range must be 0, and its major and minor versions must fall within the offered ranges. All zeros mean no acceptable version and are not Bolt.
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
	if _, err := conn.Write(handshake); err != nil {
		return Result{State: "error", Message: err.Error()}, err
	}
	raw, err := readVersion(conn)
	if len(raw) == 0 && err != nil {
		return Result{State: "error", Message: err.Error()}, err
	}
	version, ok := response(raw)
	return Result{ProtocolVersion: version, Raw: append([]byte(nil), raw...), IsBolt: ok, State: "open"}, nil
}

func readVersion(conn interface {
	Read([]byte) (int, error)
}) ([]byte, error) {
	buf := make([]byte, MaxResponseBytes)
	total := 0
	var err error
	for total < MaxResponseBytes {
		var n int
		n, err = conn.Read(buf[total:])
		total += n
		if n == 0 || err != nil {
			break
		}
	}
	return buf[:total], err
}

func response(raw []byte) (string, bool) {
	if len(raw) != MaxResponseBytes || raw[0] != 0 || raw[1] != 0 || !offered(int(raw[3]), int(raw[2])) {
		return "", false
	}
	return fmt.Sprintf("%d.%d", raw[3], raw[2]), true
}

func offered(major, minor int) bool {
	switch major {
	case 5:
		return minor <= 8
	case 4:
		return minor <= 4
	case 3:
		return minor == 0
	default:
		return false
	}
}
