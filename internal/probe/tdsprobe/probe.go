// Package tdsprobe 用一条 TDS PRELOGIN 识别线协议，不发送 LOGIN7，也不协商 TLS，不用端口号推断数据库服务。
// Package tdsprobe identifies the TDS wire protocol with one PRELOGIN. It sends no LOGIN7, does not negotiate TLS, and does not infer a database service from the port number.
package tdsprobe

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"github.com/zodirc/Vesper/pkg/probesdk"
)

const (
	// Name 是探针名称。它表示 TDS 线协议，不表示发行方。
	// Name is the probe name. It names the TDS wire protocol, not a vendor.
	Name = "tds"
	// HintPort 是选择该探针的端口提示。应答不匹配时仍不记录 TDS。
	// HintPort is the port hint that selects this probe. A non-matching response is still not recorded as TDS.
	HintPort = 1433
	// MaxPacketBytes 是一个 TDS 包的读取上限，含 8 字节包头。
	// MaxPacketBytes is the read limit for one TDS packet, including its 8-byte header.
	MaxPacketBytes = 512
	typePrelogin   = 0x12
	typeResponse   = 0x04
	statusEOM      = 0x01
)

// preloginMessage 是一条客户端 PRELOGIN。加密能力声明为不支持，实例名为空，不包含登录凭据。
// preloginMessage is one client PRELOGIN. It declares that encryption is not supported, the instance name is empty, and it contains no login credential.
var preloginMessage = []byte{
	0x12, 0x01, 0x00, 0x2f, 0x00, 0x00, 0x01, 0x00,
	0x00, 0x00, 0x1a, 0x00, 0x06,
	0x01, 0x00, 0x20, 0x00, 0x01,
	0x02, 0x00, 0x21, 0x00, 0x01,
	0x03, 0x00, 0x22, 0x00, 0x04,
	0x04, 0x00, 0x26, 0x00, 0x01,
	0xff,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x02,
	0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00,
}

// Result 是一次 TDS PRELOGIN 应答观察。
// Result is one TDS PRELOGIN response observation.
type Result struct {
	ServerVersion string
	Encryption    int
	Raw           []byte
	IsTDS         bool
	State         string
	Message       string
}

// ProbeForPort 按端口提示选择探针。只有 1433 选择 TDS，其他端口没有该探针。
// ProbeForPort selects a probe from the port hint. Only port 1433 selects TDS. Every other port has no TDS probe.
func ProbeForPort(port int) string {
	if port == HintPort {
		return Name
	}
	return ""
}

// Probe 发送一条 PRELOGIN，并最多读取 512 字节的第一个 TDS 包。它不发送 LOGIN7，也不开始 TLS。
// Probe sends one PRELOGIN and reads at most 512 bytes of the first TDS packet. It sends no LOGIN7 and does not start TLS.
//
// 包类型必须是 0x04 或 0x12，状态必须带 EOM，长度字段必须与实际字节数一致。选项区必须以 0xFF 结束，并且同时包含长度为 6 的 VERSION 和长度为 1 的 ENCRYPTION。ENCRYPTION 为 0x03 时也立即停止。版本号按字段原样写成点分文本，不据此判断发行方。
// A packet is TDS only when its type is 0x04 or 0x12, its status has EOM set, and its length field matches the bytes received. The option list must end in 0xFF and contain both a 6-byte VERSION and a 1-byte ENCRYPTION. The probe also stops immediately when ENCRYPTION is 0x03. The version is rendered from those fields as dotted text and is not used to decide a vendor.
func Probe(ctx context.Context, dial probesdk.Dialer, budget interface {
	AcquireRequest(context.Context, time.Time) error
}, ip netip.Addr, port int, now func() time.Time) (Result, error) {
	if err := budget.AcquireRequest(ctx, now()); err != nil {
		return Result{Encryption: -1, State: "not_scanned", Message: err.Error()}, err
	}
	conn, err := dial.DialTCP(ctx, ip, port, "protocol_probe")
	if err != nil {
		return Result{Encryption: -1, State: probesdk.Classify(err), Message: err.Error()}, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(dial.Timeout))
	if _, err := conn.Write(preloginMessage); err != nil {
		return Result{Encryption: -1, State: "error", Message: err.Error()}, err
	}
	raw, err := readPacket(conn)
	if len(raw) == 0 && err != nil {
		return Result{Encryption: -1, State: "error", Message: err.Error()}, err
	}
	version, encryption, ok := prelogin(raw)
	return Result{ServerVersion: version, Encryption: encryption, Raw: append([]byte(nil), raw...), IsTDS: ok, State: "open"}, nil
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
	length := int(buf[2])<<8 | int(buf[3])
	if length < 26 || length > MaxPacketBytes {
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

func prelogin(raw []byte) (string, int, bool) {
	if len(raw) < 26 || len(raw) > MaxPacketBytes || (raw[0] != typeResponse && raw[0] != typePrelogin) || raw[1]&statusEOM == 0 {
		return "", -1, false
	}
	length := int(raw[2])<<8 | int(raw[3])
	if length != len(raw) {
		return "", -1, false
	}
	options, tableEnd, ok := optionTable(raw)
	if !ok {
		return "", -1, false
	}
	var version []byte
	encryption := -1
	used := make([]bool, len(raw))
	for _, item := range options {
		start := 8 + item.offset
		if item.length == 0 || item.offset < tableEnd-8 || start+item.length > len(raw) {
			return "", -1, false
		}
		for i := start; i < start+item.length; i++ {
			if used[i] {
				return "", -1, false
			}
			used[i] = true
		}
		data := raw[start : start+item.length]
		switch item.token {
		case 0x00:
			if item.length != 6 || version != nil {
				return "", -1, false
			}
			version = data
		case 0x01:
			if item.length != 1 || encryption >= 0 || data[0] > 3 {
				return "", -1, false
			}
			encryption = int(data[0])
		}
	}
	if version == nil || encryption < 0 {
		return "", -1, false
	}
	build := int(version[2])<<8 | int(version[3])
	subbuild := int(version[4])<<8 | int(version[5])
	return fmt.Sprintf("%d.%d.%d.%d", version[0], version[1], build, subbuild), encryption, true
}

type option struct {
	token  byte
	offset int
	length int
}

func optionTable(raw []byte) ([]option, int, bool) {
	var options []option
	seen := map[byte]bool{}
	i := 8
	for i < len(raw) {
		token := raw[i]
		i++
		if token == 0xff {
			if len(options) == 0 {
				return nil, 0, false
			}
			return options, i, true
		}
		if token > 0x07 || seen[token] || i+4 > len(raw) {
			return nil, 0, false
		}
		seen[token] = true
		options = append(options, option{
			token:  token,
			offset: int(raw[i])<<8 | int(raw[i+1]),
			length: int(raw[i+2])<<8 | int(raw[i+3]),
		})
		i += 4
	}
	return nil, 0, false
}
