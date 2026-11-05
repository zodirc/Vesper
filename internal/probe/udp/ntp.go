package udp

import (
	"context"
)

const (
	// NTPName 是 NTP 探针的名称。端口号只用来选择这个探针，不写入服务身份。
	// NTPName is the NTP probe name. A port number only selects this probe and is not written as a service identity.
	NTPName = "ntp"
	// NTPVersion 是 NTP 探针版本。
	// NTPVersion is the NTP probe version.
	NTPVersion = "ntp-1"
	// NTPPort 是选择 NTP 探针的端口提示。
	// NTPPort is the port hint that selects the NTP probe.
	NTPPort = 123
	// NTPPacketBytes 是 RFC 5905 客户端报文的长度。扩展字段不在请求里。
	// NTPPacketBytes is the length of an RFC 5905 client packet. Extension fields are not part of the request.
	NTPPacketBytes = 48
	// NTPAttempts 是超时后的总发送次数，包含第一次。ICMP 端口不可达和不匹配的响应不重试。
	// NTPAttempts is the total number of sends when the exchange times out, including the first send. ICMP port unreachable and a non-matching response are not retried.
	NTPAttempts = 2
)

// clientPacket 是一条 LI 为 0、版本为 4、模式为 3 的客户端报文，其余字段为 0。
// clientPacket is a client packet with LI 0, version 4, and mode 3. Every other field is zero.
//
// 模式 3 是客户端。探针不发送模式 6 或模式 7，因此不请求控制查询或 monlist。
// Mode 3 is the client. The probe sends neither mode 6 nor mode 7, so it requests neither a control query nor monlist.
var clientPacket = func() []byte {
	packet := make([]byte, NTPPacketBytes)
	packet[0] = 0x23
	return packet
}()

// NTPRequest 返回探针发送的客户端报文副本。
// NTPRequest returns a copy of the client packet sent by the probe.
func NTPRequest() []byte {
	return append([]byte(nil), clientPacket...)
}

// ProbeNTP 发送一条有界 NTP 客户端报文并按规格给出结论。
// ProbeNTP sends one bounded NTP client packet and returns the conclusion allowed by the spec.
//
// 响应至少 48 字节，版本是 3 或 4，并且低 3 位模式是 4，才记为匹配。模式 6 和模式 7 不匹配。
// ICMP 端口不可达记为 closed 且不重试。超时再发一次，两次都超时记为 no_response。
// A response matches only when it has at least 48 bytes, its version is 3 or 4, and its low 3 mode bits are 4. Mode 6 and mode 7 do not match.
// ICMP port unreachable is closed and is not retried. A timeout is sent once more, and two timeouts are no_response.
func ProbeNTP(ctx context.Context, exchange func(context.Context, []byte) ([]byte, error)) (Result, error) {
	spec := Spec{
		Name: NTPName, Version: NTPVersion, Request: NTPRequest(), MaxRequestBytes: NTPPacketBytes, MaxResponseBytes: NTPPacketBytes,
		Attempts: NTPAttempts, ResponseMatches: ntpMatches,
		ICMPUnreachableMeans: "closed", TimeoutConclusion: "no_response",
	}
	return Run(ctx, spec, exchange)
}

func ntpMatches(response []byte) bool {
	if len(response) < NTPPacketBytes {
		return false
	}
	version := (response[0] >> 3) & 0x7
	mode := response[0] & 0x7
	return mode == 4 && (version == 3 || version == 4)
}
