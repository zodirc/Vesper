// Package mqttprobe 发送一条 MQTT 3.1.1 CONNECT，确认 CONNACK 后立即关闭。
// Package mqttprobe sends one MQTT 3.1.1 CONNECT and closes as soon as the CONNACK is recognized.
package mqttprobe

import (
	"context"
	"net/netip"
	"time"

	"github.com/zodirc/Vesper/pkg/probesdk"
)

const (
	// Name 是探针名称。它表示 MQTT 线协议，不表示代理产品。
	// Name is the probe name. It names the MQTT wire protocol, not a broker product.
	Name = "mqtt"
	// HintPort 是选择该探针的端口提示。应答不匹配时仍不记录 MQTT。
	// HintPort is the port hint that selects this probe. A non-matching response is still not recorded as MQTT.
	HintPort = 1883
	// AckBytes 是 MQTT 3.1.1 CONNACK 的固定长度。
	// AckBytes is the fixed length of an MQTT 3.1.1 CONNACK.
	AckBytes = 4
)

// connectPacket 是一条 MQTT 3.1.1 CONNECT。协议级别是 4，标志只有 clean session，keepalive 是 30 秒，客户端标识是 vesper。
// connectPacket is one MQTT 3.1.1 CONNECT. The protocol level is 4, the only flag is clean session, the keepalive is 30 seconds, and the client identifier is vesper.
//
// 这条报文没有用户名、口令、遗嘱或订阅。探针不发送 SUBSCRIBE 或 PUBLISH。
// This packet has no username, password, will, or subscription. The probe sends no SUBSCRIBE or PUBLISH.
var connectPacket = []byte{
	0x10, 0x12,
	0x00, 0x04, 'M', 'Q', 'T', 'T',
	0x04, 0x02, 0x00, 0x1e,
	0x00, 0x06, 'v', 'e', 's', 'p', 'e', 'r',
}

// Request 返回探针发送的 CONNECT 副本。
// Request returns a copy of the CONNECT packet sent by the probe.
func Request() []byte {
	return append([]byte(nil), connectPacket...)
}

// Result 是一次 MQTT CONNACK 观察。
// Result is one MQTT CONNACK observation.
type Result struct {
	AckCode int
	Raw     []byte
	IsMQTT  bool
	State   string
	Message string
}

// ProbeForPort 按端口提示选择探针。只有 1883 选择 MQTT，其他端口没有该探针。
// ProbeForPort selects a probe from the port hint. Only port 1883 selects MQTT. Every other port has no MQTT probe.
func ProbeForPort(port int) string {
	if port == HintPort {
		return Name
	}
	return ""
}

// Probe 发送一条 CONNECT，并读取 4 字节 CONNACK。它不发送认证、订阅或发布。
// Probe sends one CONNECT and reads a 4-byte CONNACK. It sends no authentication, subscription, or publication.
//
// 固定头必须是 0x20，剩余长度必须是 2。确认标志只能有 session present 位。返回码 0 到 5 都记为 MQTT，包括未授权。其他报文不记为 MQTT。
// The fixed header must be 0x20 and the remaining length must be 2. The acknowledge flags may contain only the session present bit. Return codes 0 through 5 are MQTT, including not authorized. Any other packet is not MQTT.
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
	if _, err := conn.Write(connectPacket); err != nil {
		return Result{State: "error", Message: err.Error()}, err
	}
	raw, err := readN(conn, AckBytes)
	if len(raw) == 0 && err != nil {
		return Result{State: "error", Message: err.Error()}, err
	}
	code, ok := connack(raw)
	return Result{AckCode: code, Raw: append([]byte(nil), raw...), IsMQTT: ok, State: "open"}, nil
}

func readN(conn interface {
	Read([]byte) (int, error)
}, n int) ([]byte, error) {
	buf := make([]byte, n)
	total := 0
	var err error
	for total < n {
		var read int
		read, err = conn.Read(buf[total:])
		total += read
		if read == 0 || err != nil {
			return buf[:total], err
		}
	}
	return buf[:total], nil
}

func connack(raw []byte) (int, bool) {
	if len(raw) != AckBytes || raw[0] != 0x20 || raw[1] != 0x02 || raw[2]&0xfe != 0 || raw[3] > 5 {
		return 0, false
	}
	return int(raw[3]), true
}
