// Package kafkaprobe 发送一条 Kafka ApiVersions 请求，确认关联标识匹配的响应帧后立即关闭。
// Package kafkaprobe sends one Kafka ApiVersions request and closes as soon as a response frame with the matching correlation identifier is recognized.
package kafkaprobe

import (
	"context"
	"encoding/binary"
	"net/netip"
	"time"

	"github.com/zodirc/Vesper/pkg/probesdk"
)

const (
	// Name 是探针名称。它表示 Kafka 线协议，不表示发行方。
	// Name is the probe name. It names the Kafka wire protocol, not a vendor.
	Name = "kafka"
	// HintPort 是选择该探针的端口提示。应答不匹配时仍不记录 Kafka。
	// HintPort is the port hint that selects this probe. A non-matching response is still not recorded as Kafka.
	HintPort = 9092
	// MaxReplyBytes 是响应帧的读取上限，含 4 字节长度。
	// MaxReplyBytes is the read limit for a response frame, including the 4-byte length.
	MaxReplyBytes = 4100

	apiVersionsKey     = 18
	apiVersionsVersion = 0
	correlationID      = 1
)

// apiVersionsRequest 是一条 ApiVersions 版本 0 请求。请求头使用非灵活编码，正文为空。
// apiVersionsRequest is one ApiVersions version 0 request. The request header uses the non-flexible encoding and the body is empty.
//
// 关联标识固定为 1，客户端标识是 vesper。探针不发送 Produce、Fetch 或加入组请求。
// The correlation identifier is fixed at 1 and the client identifier is vesper. The probe sends no Produce, Fetch, or join-group request.
var apiVersionsRequest = func() []byte {
	body := make([]byte, 16)
	binary.BigEndian.PutUint16(body[0:2], apiVersionsKey)
	binary.BigEndian.PutUint16(body[2:4], apiVersionsVersion)
	binary.BigEndian.PutUint32(body[4:8], correlationID)
	binary.BigEndian.PutUint16(body[8:10], 6)
	copy(body[10:], []byte("vesper"))
	frame := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(frame[:4], uint32(len(body)))
	copy(frame[4:], body)
	return frame
}()

// Request 返回探针发送的 ApiVersions 请求副本。
// Request returns a copy of the ApiVersions request sent by the probe.
func Request() []byte {
	return append([]byte(nil), apiVersionsRequest...)
}

// Result 是一次 Kafka ApiVersions 响应观察。
// Result is one Kafka ApiVersions response observation.
type Result struct {
	ErrorCode int
	Raw       []byte
	IsKafka   bool
	State     string
	Message   string
}

// ProbeForPort 按端口提示选择探针。只有 9092 选择 Kafka，其他端口没有该探针。
// ProbeForPort selects a probe from the port hint. Only port 9092 selects Kafka. Every other port has no Kafka probe.
func ProbeForPort(port int) string {
	if port == HintPort {
		return Name
	}
	return ""
}

// Probe 发送一条 ApiVersions 版本 0，并最多读取 4100 字节的一个长度帧。它不发送写入、读取或组管理请求。
// Probe sends one ApiVersions version 0 request and reads at most 4100 bytes of one length-prefixed frame. It sends no produce, fetch, or group-management request.
//
// 长度字段必须与帧内字节数一致，并且不超过 4096。关联标识必须等于 1。错误码可以是任何 int16，包括不受支持的版本；数组长度必须能被已收到的字节装下。其他帧不记为 Kafka。
// The length field must equal the number of bytes inside the frame and must not exceed 4096. The correlation identifier must equal 1. The error code may be any int16, including unsupported version; the array length must fit in the bytes received. Any other frame is not Kafka.
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
	if _, err := conn.Write(apiVersionsRequest); err != nil {
		return Result{State: "error", Message: err.Error()}, err
	}
	raw, err := readFrame(conn)
	if len(raw) == 0 && err != nil {
		return Result{State: "error", Message: err.Error()}, err
	}
	code, ok := response(raw)
	return Result{ErrorCode: code, Raw: append([]byte(nil), raw...), IsKafka: ok, State: "open"}, nil
}

func readFrame(conn interface {
	Read([]byte) (int, error)
}) ([]byte, error) {
	buf := make([]byte, MaxReplyBytes)
	total := 0
	var err error
	for total < 4 {
		var n int
		n, err = conn.Read(buf[total:])
		total += n
		if n == 0 || err != nil {
			return buf[:total], err
		}
	}
	size := int(binary.BigEndian.Uint32(buf[:4]))
	if size < 6 || size > MaxReplyBytes-4 {
		return buf[:total], nil
	}
	need := 4 + size
	for total < need {
		var n int
		n, err = conn.Read(buf[total:need])
		total += n
		if n == 0 || err != nil {
			return buf[:total], err
		}
	}
	return buf[:need], nil
}

func response(raw []byte) (int, bool) {
	if len(raw) < 10 {
		return 0, false
	}
	size := int(binary.BigEndian.Uint32(raw[:4]))
	if size < 6 || size > 4096 || len(raw) != 4+size {
		return 0, false
	}
	body := raw[4:]
	if binary.BigEndian.Uint32(body[:4]) != correlationID {
		return 0, false
	}
	code := int(int16(binary.BigEndian.Uint16(body[4:6])))
	if size == 6 {
		return code, true
	}
	if size < 10 {
		return 0, false
	}
	count := int(int32(binary.BigEndian.Uint32(body[6:10])))
	if count < 0 || count > 128 || size != 10+count*6 {
		return 0, false
	}
	return code, true
}
