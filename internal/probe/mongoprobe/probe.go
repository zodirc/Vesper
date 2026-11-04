// Package mongoprobe 用一条 OP_MSG ping 识别 MongoDB 线协议，不发送凭据或查询，也不用端口号推断数据库服务。
// Package mongoprobe identifies the MongoDB wire protocol with one OP_MSG ping. It sends no credential or query and does not infer a database service from the port number.
package mongoprobe

import (
	"bytes"
	"context"
	"encoding/binary"
	"hash/crc32"
	"math"
	"net/netip"
	"time"

	"github.com/zodirc/Vesper/pkg/probesdk"
)

const (
	// Name 是探针名称。它表示 MongoDB 线协议，不表示发行方。
	// Name is the probe name. It names the MongoDB wire protocol, not a vendor.
	Name = "mongodb"
	// HintPort 是选择该探针的端口提示。应答不匹配时仍不记录 MongoDB。
	// HintPort is the port hint that selects this probe. A non-matching response is still not recorded as MongoDB.
	HintPort = 27017
	// MaxMessageBytes 是一条 OP_MSG 的读取上限，含报文头。
	// MaxMessageBytes is the read limit for one OP_MSG, including its header.
	MaxMessageBytes = 1024
	// ReplyOK 表示命令文档里的 ok 为 1。
	// ReplyOK means the command document has ok equal to 1.
	ReplyOK = "ok"
	// ReplyError 表示命令文档里的 ok 为 0。探针就此停止，不发送凭据。
	// ReplyError means the command document has ok equal to 0. The probe stops there and sends no credential.
	ReplyError         = "error"
	requestID          = 1
	opMsg              = 2013
	flagChecksum       = 1
	flagMoreToCome     = 1 << 1
	flagExhaustAllowed = 1 << 16
)

// pingMessage 是一条 OP_MSG。正文只有 ping 和 $db，没有客户端元数据，也没有凭据。
// pingMessage is one OP_MSG. Its body contains only ping and $db, with no client metadata and no credential.
var pingMessage = []byte{
	0x33, 0x00, 0x00, 0x00,
	0x01, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0xdd, 0x07, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00,
	0x1e, 0x00, 0x00, 0x00,
	0x10, 'p', 'i', 'n', 'g', 0x00, 0x01, 0x00, 0x00, 0x00,
	0x02, '$', 'd', 'b', 0x00, 0x06, 0x00, 0x00, 0x00, 'a', 'd', 'm', 'i', 'n', 0x00,
	0x00,
}

var checksumTable = crc32.MakeTable(crc32.Castagnoli)

// Result 是一次 MongoDB ping 应答观察。
// Result is one MongoDB ping reply observation.
type Result struct {
	Reply     string
	Raw       []byte
	IsMongoDB bool
	State     string
	Message   string
}

// ProbeForPort 按端口提示选择探针。只有 27017 选择 MongoDB，其他端口没有该探针。
// ProbeForPort selects a probe from the port hint. Only port 27017 selects MongoDB. Every other port has no MongoDB probe.
func ProbeForPort(port int) string {
	if port == HintPort {
		return Name
	}
	return ""
}

// Probe 发送一条 OP_MSG ping，并最多读取 1024 字节的第一条应答。它不发送凭据、查询、压缩协商或后续消息，也不探测 TLS。
// Probe sends one OP_MSG ping and reads at most 1024 bytes of the first reply. It sends no credential, query, compression negotiation, or follow-up message, and it does not probe TLS.
//
// 应答的长度字段必须与实际字节数一致。responseTo 必须等于请求 ID，opcode 必须是 2013。正文必须有且只有一个 kind 0 文档，并且该文档的 ok 为 0 或 1。压缩报文和 OP_QUERY 不记为 MongoDB。moreToCome 置位时也不再读取后续报文。
// A reply is MongoDB only when its length field matches the bytes received, responseTo equals the request ID, and the opcode is 2013. The body must contain exactly one kind-0 document, and that document's ok must be 0 or 1. Compressed messages and OP_QUERY are not MongoDB. When moreToCome is set, the probe still does not read another message.
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
	if _, err := conn.Write(pingMessage); err != nil {
		return Result{State: "error", Message: err.Error()}, err
	}
	raw, err := readMessage(conn)
	if len(raw) == 0 && err != nil {
		return Result{State: "error", Message: err.Error()}, err
	}
	kind, ok := commandReply(raw)
	return Result{Reply: kind, Raw: append([]byte(nil), raw...), IsMongoDB: ok, State: "open"}, nil
}

func readMessage(conn interface {
	Read([]byte) (int, error)
}) ([]byte, error) {
	buf := make([]byte, MaxMessageBytes)
	total := 0
	var err error
	for total < 4 {
		var n int
		n, err = conn.Read(buf[total:])
		total += n
		if n == 0 || err != nil {
			break
		}
	}
	if total < 4 {
		return buf[:total], err
	}
	length := int(binary.LittleEndian.Uint32(buf[:4]))
	if length < 26 || length > MaxMessageBytes {
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

func commandReply(raw []byte) (string, bool) {
	if len(raw) < 26 || len(raw) > MaxMessageBytes {
		return "", false
	}
	length := int(binary.LittleEndian.Uint32(raw[:4]))
	if length != len(raw) || binary.LittleEndian.Uint32(raw[8:12]) != requestID || binary.LittleEndian.Uint32(raw[12:16]) != opMsg {
		return "", false
	}
	flags := binary.LittleEndian.Uint32(raw[16:20])
	if flags&^(flagChecksum|flagMoreToCome|flagExhaustAllowed) != 0 {
		return "", false
	}
	payload := raw[20:]
	if flags&flagChecksum != 0 {
		if len(payload) < 4 || crc32.Checksum(raw[:len(raw)-4], checksumTable) != binary.LittleEndian.Uint32(payload[len(payload)-4:]) {
			return "", false
		}
		payload = payload[:len(payload)-4]
	}
	doc, ok := bodySection(payload)
	if !ok {
		return "", false
	}
	return documentReply(doc)
}

func bodySection(payload []byte) ([]byte, bool) {
	var doc []byte
	i := 0
	for i < len(payload) {
		kind := payload[i]
		i++
		if i+4 > len(payload) {
			return nil, false
		}
		size := int(binary.LittleEndian.Uint32(payload[i:]))
		switch kind {
		case 0:
			if doc != nil || size < 5 || i+size > len(payload) {
				return nil, false
			}
			doc = payload[i : i+size]
			i += size
		case 1:
			if size < 4 || i+size > len(payload) {
				return nil, false
			}
			i += size
		default:
			return nil, false
		}
	}
	if doc == nil || i != len(payload) {
		return nil, false
	}
	return doc, true
}

func documentReply(doc []byte) (string, bool) {
	if len(doc) < 5 {
		return "", false
	}
	size := int(binary.LittleEndian.Uint32(doc[:4]))
	if size != len(doc) || doc[size-1] != 0 {
		return "", false
	}
	var reply string
	seen := false
	i := 4
	for i < size-1 {
		typ := doc[i]
		i++
		name, next, ok := cstring(doc[:size-1], i)
		if !ok {
			return "", false
		}
		i = next
		var valid bool
		if bytes.Equal(name, []byte("ok")) {
			var status string
			i, status, valid = readOK(typ, doc, i)
			if !valid || seen || i > size-1 {
				return "", false
			}
			seen = true
			reply = status
			continue
		}
		i, valid = skipValue(typ, doc, i)
		if !valid || i > size-1 {
			return "", false
		}
	}
	if i != size-1 || !seen {
		return "", false
	}
	return reply, true
}

func readOK(typ byte, doc []byte, i int) (int, string, bool) {
	switch typ {
	case 0x01:
		if i+8 > len(doc) {
			return 0, "", false
		}
		value := math.Float64frombits(binary.LittleEndian.Uint64(doc[i : i+8]))
		status, ok := okReply(value == 0, value == 1)
		return i + 8, status, ok
	case 0x10:
		if i+4 > len(doc) {
			return 0, "", false
		}
		value := int32(binary.LittleEndian.Uint32(doc[i : i+4]))
		status, ok := okReply(value == 0, value == 1)
		return i + 4, status, ok
	case 0x12:
		if i+8 > len(doc) {
			return 0, "", false
		}
		value := int64(binary.LittleEndian.Uint64(doc[i : i+8]))
		status, ok := okReply(value == 0, value == 1)
		return i + 8, status, ok
	default:
		return 0, "", false
	}
}

func okReply(zero, one bool) (string, bool) {
	if one {
		return ReplyOK, true
	}
	if zero {
		return ReplyError, true
	}
	return "", false
}

func skipValue(typ byte, doc []byte, i int) (int, bool) {
	switch typ {
	case 0x01, 0x09, 0x11, 0x12:
		if i+8 > len(doc) {
			return 0, false
		}
		return i + 8, true
	case 0x10:
		if i+4 > len(doc) {
			return 0, false
		}
		return i + 4, true
	case 0x07:
		if i+12 > len(doc) {
			return 0, false
		}
		return i + 12, true
	case 0x08:
		if i+1 > len(doc) || doc[i] > 1 {
			return 0, false
		}
		return i + 1, true
	case 0x0A:
		return i, true
	case 0x13:
		if i+16 > len(doc) {
			return 0, false
		}
		return i + 16, true
	case 0x02:
		if i+4 > len(doc) {
			return 0, false
		}
		n := int(binary.LittleEndian.Uint32(doc[i:]))
		if n < 1 || i+4+n > len(doc) {
			return 0, false
		}
		return i + 4 + n, true
	case 0x03, 0x04:
		if i+4 > len(doc) {
			return 0, false
		}
		n := int(binary.LittleEndian.Uint32(doc[i:]))
		if n < 5 || i+n > len(doc) {
			return 0, false
		}
		return i + n, true
	case 0x05:
		if i+5 > len(doc) {
			return 0, false
		}
		n := int(binary.LittleEndian.Uint32(doc[i:]))
		if n < 0 || i+5+n > len(doc) {
			return 0, false
		}
		return i + 5 + n, true
	default:
		return 0, false
	}
}

func cstring(doc []byte, i int) ([]byte, int, bool) {
	if i >= len(doc) {
		return nil, 0, false
	}
	end := bytes.IndexByte(doc[i:], 0)
	if end < 0 {
		return nil, 0, false
	}
	return doc[i : i+end], i + end + 1, true
}
