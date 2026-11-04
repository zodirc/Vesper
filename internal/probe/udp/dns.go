package udp

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"strings"
)

const (
	// DNSName 是 DNS 探针的名称。端口号只用来选择这个探针，不写入服务身份。
	// DNSName is the DNS probe name. A port number only selects this probe and is not written as a service identity.
	DNSName = "dns"
	// DNSVersion 是 DNS 探针版本。
	// DNSVersion is the DNS probe version.
	DNSVersion = "dns-1"
	// DNSPort 是选择 DNS 探针的端口提示。
	// DNSPort is the port hint that selects the DNS probe.
	DNSPort = 53
	// DNSMaxRequestBytes 是一条 DNS 查询的最大长度。
	// DNSMaxRequestBytes is the maximum length of one DNS query.
	DNSMaxRequestBytes = 512
	// DNSMaxResponseBytes 是一次读取的响应上限。更长的报文只保留这个长度。
	// DNSMaxResponseBytes is the read limit for one response. A longer datagram keeps only this many bytes.
	DNSMaxResponseBytes = 512
	// DNSAttempts 是超时后的总发送次数，包含第一次。ICMP 端口不可达和不匹配的响应不重试。
	// DNSAttempts is the total number of sends when the exchange times out, including the first send. ICMP port unreachable and a non-matching response are not retried.
	DNSAttempts = 2

	dnsQTypeA  = 1
	dnsQTypeNS = 2
	dnsClassIN = 1
)

// Result 是一次 UDP 探测的结论和实际收到的字节。QName 和 QType 只在 DNS 探针中有值。
// Result is the conclusion of one UDP probe and the bytes actually received. QName and QType are set only for the DNS probe.
type Result struct {
	Probe    string
	Version  string
	Outcome  Outcome
	Response []byte
	Rounds   int
	Query    []byte
	QName    string
	QType    uint16
}

// ProbeForPort 按端口提示选择探针。只有 53 选择 DNS，其他端口没有探针。
// ProbeForPort selects a probe from the port hint. Only port 53 selects DNS. Every other port has no probe.
func ProbeForPort(port int) string {
	if port == DNSPort {
		return DNSName
	}
	return ""
}

// Query 构造一条标准 DNS 查询。name 为空或为 "." 时查询根。qtype 为记录类型。
// Query builds one standard DNS query. An empty name or "." queries the root. qtype is the record type.
//
// 名称只接受字母、数字、连字符和点。编码后的请求超过 512 字节时返回错误，不生成截断请求。
// The name accepts only letters, digits, hyphens, and dots. A request longer than 512 bytes after encoding returns an error and does not produce a truncated request.
func Query(id uint16, name string, qtype uint16) ([]byte, error) {
	encoded, err := encodeName(name)
	if err != nil {
		return nil, err
	}
	if 12+len(encoded)+4 > DNSMaxRequestBytes {
		return nil, fmt.Errorf("dns request exceeds %d bytes", DNSMaxRequestBytes)
	}
	buf := make([]byte, 12+len(encoded)+4)
	binary.BigEndian.PutUint16(buf[0:2], id)
	binary.BigEndian.PutUint16(buf[2:4], 0x0100)
	binary.BigEndian.PutUint16(buf[4:6], 1)
	copy(buf[12:], encoded)
	off := 12 + len(encoded)
	binary.BigEndian.PutUint16(buf[off:], qtype)
	binary.BigEndian.PutUint16(buf[off+2:], dnsClassIN)
	return buf, nil
}

// ResponseMatches 判断响应是否属于这次查询。事务 ID 必须相同，QR 必须为 1，opcode 必须为 0。
// ResponseMatches reports whether a response belongs to this query. The transaction ID must match, QR must be 1, and the opcode must be 0.
func ResponseMatches(id uint16, response []byte) bool {
	if len(response) < 12 {
		return false
	}
	if binary.BigEndian.Uint16(response[:2]) != id {
		return false
	}
	if response[2]&0x80 == 0 || response[2]&0x78 != 0 {
		return false
	}
	return true
}

// ProbeDNS 发送有界 DNS 查询并按规格给出结论。
// ProbeDNS sends a bounded DNS query and returns the conclusion allowed by the spec.
//
// qname 非空时查询该名称的 A 记录。qname 为空时查询根的 NS 记录。
// exchange 负责授权、预算和一次收发。超时会继续下一次，直到 DNSAttempts。
// 授权失败、预算耗尽和取消返回 not_scanned，Rounds 保持 0。其余尝试在通过授权和预算后计入 Rounds。
// A non-empty qname queries A records for that name. An empty qname queries NS records at the root.
// exchange performs authorization, budget accounting, and one exchange. A timeout continues until DNSAttempts.
// Authorization failure, budget exhaustion, and cancellation return not_scanned and leave Rounds at 0. Every other attempt counts in Rounds after authorization and budget checks pass.
func ProbeDNS(ctx context.Context, exchange func(context.Context, []byte) ([]byte, error), qname string) (Result, error) {
	if exchange == nil {
		return Result{}, fmt.Errorf("dns probe: exchange is required")
	}
	name := "."
	qtype := uint16(dnsQTypeNS)
	if qname != "" {
		name = qname
		qtype = dnsQTypeA
	}
	var rawID [2]byte
	if _, err := rand.Read(rawID[:]); err != nil {
		return Result{}, fmt.Errorf("dns probe: %w", err)
	}
	id := binary.BigEndian.Uint16(rawID[:])
	query, err := Query(id, name, qtype)
	if err != nil {
		return Result{}, err
	}
	spec := Spec{
		Name: DNSName, Version: DNSVersion, Request: query, MaxRequestBytes: DNSMaxRequestBytes, MaxResponseBytes: DNSMaxResponseBytes,
		Attempts: DNSAttempts, ResponseMatches: func(response []byte) bool { return ResponseMatches(id, response) },
		ICMPUnreachableMeans: "closed", TimeoutConclusion: "no_response",
	}
	result, err := Run(ctx, spec, exchange)
	result.Query = query
	result.QName = name
	result.QType = qtype
	return result, err
}

func encodeName(name string) ([]byte, error) {
	if name == "" || name == "." {
		return []byte{0}, nil
	}
	if len(name) > 253 {
		return nil, fmt.Errorf("dns name %q is too long", name)
	}
	var out []byte
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 {
			return nil, fmt.Errorf("dns label in %q is invalid", name)
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '-' {
				return nil, fmt.Errorf("dns label in %q is invalid", name)
			}
		}
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	out = append(out, 0)
	return out, nil
}
