package mongoprobe

import (
	"context"
	"encoding/binary"
	"hash/crc32"
	"math"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/zodirc/Vesper/internal/scope"
	"github.com/zodirc/Vesper/pkg/probesdk"
)

func TestProbeSendsOnePingAndStops(t *testing.T) {
	got, sent := serveMongo(t, replyMessage(requestID, richOK()))
	if !got.IsMongoDB || got.Reply != ReplyOK || got.State != "open" || string(sent) != string(pingMessage) || len(got.Raw) != len(replyMessage(requestID, richOK())) {
		t.Fatalf("ok = %+v sent = %x", got, sent)
	}
	failed, sent := serveMongo(t, replyMessage(requestID, doc(elemDouble("ok", 0), elemString("errmsg", "unauthorized"))))
	if !failed.IsMongoDB || failed.Reply != ReplyError || string(sent) != string(pingMessage) {
		t.Fatalf("error = %+v sent = %q", failed, sent)
	}
	checked := withChecksum(replyMessage(requestID, doc(elemDouble("ok", 1))))
	if sum, _ := serveMongo(t, checked); !sum.IsMongoDB || sum.Reply != ReplyOK || len(sum.Raw) != len(checked) {
		t.Fatalf("checksum = %+v", sum)
	}
}

func TestProbeRejectsANonMongoDBReply(t *testing.T) {
	got, _ := serveMongo(t, []byte("HTTP/1.0 200 OK\r\n\r\n"))
	if got.IsMongoDB || got.Reply != "" || got.State != "open" {
		t.Fatalf("http = %+v", got)
	}
	if other, _ := serveMongo(t, replyMessage(2, doc(elemDouble("ok", 1)))); other.IsMongoDB {
		t.Fatalf("responseTo = %+v", other)
	}
	query := append([]byte(nil), replyMessage(requestID, doc(elemDouble("ok", 1)))...)
	binary.LittleEndian.PutUint32(query[12:16], 1)
	if legacy, _ := serveMongo(t, query); legacy.IsMongoDB {
		t.Fatalf("op_query = %+v", legacy)
	}
	bad := withChecksum(replyMessage(requestID, doc(elemDouble("ok", 1))))
	bad[len(bad)-1] ^= 0xff
	if mismatch, _ := serveMongo(t, bad); mismatch.IsMongoDB {
		t.Fatalf("checksum = %+v", mismatch)
	}
	oversize := []byte{0x01, 0x04, 0x00, 0x00}
	if huge, _ := serveMongo(t, oversize); huge.IsMongoDB || len(huge.Raw) > MaxMessageBytes {
		t.Fatalf("oversize = %+v len = %d", huge, len(huge.Raw))
	}
}

func TestProbeForPortSelectsOnly27017(t *testing.T) {
	if ProbeForPort(27017) != Name || ProbeForPort(27018) != "" || ProbeForPort(6379) != "" {
		t.Fatalf("27017 = %s 27018 = %s 6379 = %s", ProbeForPort(27017), ProbeForPort(27018), ProbeForPort(6379))
	}
}

func richOK() []byte {
	signature := doc(elemBinary("hash", []byte("0123456789abcdef0123")), elemInt64("keyId", 7))
	cluster := doc(elemTimestamp("clusterTime"), elemDoc("signature", signature))
	return doc(elemDouble("ok", 1), elemTimestamp("operationTime"), elemDoc("$clusterTime", cluster))
}

func replyMessage(responseTo uint32, document []byte) []byte {
	raw := make([]byte, 21+len(document))
	binary.LittleEndian.PutUint32(raw[0:], uint32(len(raw)))
	binary.LittleEndian.PutUint32(raw[8:], responseTo)
	binary.LittleEndian.PutUint32(raw[12:], opMsg)
	copy(raw[21:], document)
	return raw
}

func withChecksum(raw []byte) []byte {
	out := append([]byte(nil), raw...)
	flags := binary.LittleEndian.Uint32(out[16:20]) | flagChecksum
	binary.LittleEndian.PutUint32(out[16:20], flags)
	binary.LittleEndian.PutUint32(out[0:4], uint32(len(out)+4))
	var tail [4]byte
	binary.LittleEndian.PutUint32(tail[:], crc32.Checksum(out, checksumTable))
	return append(out, tail[:]...)
}

func doc(elements ...[]byte) []byte {
	n := 5
	for _, element := range elements {
		n += len(element)
	}
	raw := make([]byte, n)
	binary.LittleEndian.PutUint32(raw, uint32(n))
	i := 4
	for _, element := range elements {
		copy(raw[i:], element)
		i += len(element)
	}
	return raw
}

func elemDouble(name string, value float64) []byte {
	raw := append([]byte{0x01}, append([]byte(name), 0)...)
	var bits [8]byte
	binary.LittleEndian.PutUint64(bits[:], math.Float64bits(value))
	return append(raw, bits[:]...)
}

func elemString(name, value string) []byte {
	raw := append([]byte{0x02}, append([]byte(name), 0)...)
	var size [4]byte
	binary.LittleEndian.PutUint32(size[:], uint32(len(value)+1))
	raw = append(raw, size[:]...)
	return append(append(raw, value...), 0)
}

func elemDoc(name string, document []byte) []byte {
	return append(append([]byte{0x03}, append([]byte(name), 0)...), document...)
}

func elemBinary(name string, value []byte) []byte {
	raw := append([]byte{0x05}, append([]byte(name), 0)...)
	var size [4]byte
	binary.LittleEndian.PutUint32(size[:], uint32(len(value)))
	raw = append(raw, size[:]...)
	raw = append(raw, 0)
	return append(raw, value...)
}

func elemInt64(name string, value int64) []byte {
	raw := append([]byte{0x12}, append([]byte(name), 0)...)
	var bits [8]byte
	binary.LittleEndian.PutUint64(bits[:], uint64(value))
	return append(raw, bits[:]...)
}

func elemTimestamp(name string) []byte {
	raw := append([]byte{0x11}, append([]byte(name), 0)...)
	return append(raw, make([]byte, 8)...)
}

func serveMongo(t *testing.T, response []byte) (Result, []byte) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	sent := make(chan []byte, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			sent <- nil
			return
		}
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		buf := make([]byte, 64)
		n, _ := conn.Read(buf)
		_, _ = conn.Write(response)
		_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		extra := make([]byte, 32)
		m, _ := conn.Read(extra)
		sent <- append(append([]byte(nil), buf[:n]...), extra[:m]...)
	}()
	account := scope.NewAccount(scope.Budget{
		MaxTargets: 1, MaxAddresses: 1, MaxConnections: 2, MaxRequests: 2, MaxConcurrency: 1,
		MaxRatePerSecond: 1000, MaxRuntime: time.Minute, MaxEvidenceBytes: 10000,
	}, time.Now())
	dial := probesdk.Dialer{Auth: allow{}, Budget: account, Timeout: time.Second, Now: time.Now}
	result, err := Probe(context.Background(), dial, account, netip.MustParseAddr("127.0.0.1"), listener.Addr().(*net.TCPAddr).Port, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	return result, <-sent
}

type allow struct{}

func (allow) Authorize(context.Context, netip.Addr, int, string, string) error { return nil }
