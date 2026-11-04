package clickhouseprobe

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/zodirc/Vesper/internal/scope"
	"github.com/zodirc/Vesper/pkg/probesdk"
)

func TestProbeSendsOneHelloAndStops(t *testing.T) {
	if string(helloMessage) != "\x00\x06vesper\x00\x00\x00\x00\x06vesper\x00" {
		t.Fatalf("request = %x", helloMessage)
	}
	hello := []byte{0x00, 0x04, 'N', 'o', 'd', 'e', 0x18, 0x03, 0xdf, 0xa9, 0x03}
	got, sent := serveClickHouse(t, hello)
	if !got.IsClickHouse || got.Reply != ReplyHello || got.ServerVersion != "24.3" || got.ProtocolRevision != 54495 || got.ExceptionName != "" || got.State != "open" || string(sent) != string(helloMessage) || string(got.Raw) != string(hello) {
		t.Fatalf("hello = %+v sent = %x", got, sent)
	}
	exception := append([]byte{0x02, 0x04, 0x02, 0x00, 0x00, 0x15}, []byte("AUTHENTICATION_FAILED")...)
	exception = append(exception, 0x08)
	exception = append(exception, []byte("rejected")...)
	exception = append(exception, 0x00, 0x00)
	failed, sent := serveClickHouse(t, exception)
	if !failed.IsClickHouse || failed.Reply != ReplyException || failed.ExceptionCode != 516 || failed.ExceptionName != "AUTHENTICATION_FAILED" || failed.ServerVersion != "" || string(sent) != string(helloMessage) {
		t.Fatalf("exception = %+v sent = %x", failed, sent)
	}
}

func TestProbeRejectsANonClickHouseResponse(t *testing.T) {
	got, _ := serveClickHouse(t, []byte("HTTP/1.0 200 OK\r\n\r\n"))
	if got.IsClickHouse || got.Reply != "" || got.State != "open" {
		t.Fatalf("http = %+v", got)
	}
	if echoed, _ := serveClickHouse(t, append([]byte(nil), helloMessage...)); echoed.IsClickHouse {
		t.Fatalf("echo = %+v", echoed)
	}
	if data, _ := serveClickHouse(t, []byte{0x01, 0x00}); data.IsClickHouse {
		t.Fatalf("data = %+v", data)
	}
	nested := append([]byte{0x02, 0x04, 0x02, 0x00, 0x00, 0x15}, []byte("AUTHENTICATION_FAILED")...)
	nested = append(nested, 0x08)
	nested = append(nested, []byte("rejected")...)
	nested = append(nested, 0x00, 0x01)
	if badNested, _ := serveClickHouse(t, nested); badNested.IsClickHouse {
		t.Fatalf("nested = %+v", badNested)
	}
	if unnamed, _ := serveClickHouse(t, []byte{0x00, 0x00, 0x01, 0x00, 0x01}); unnamed.IsClickHouse {
		t.Fatalf("empty name = %+v", unnamed)
	}
	oversize := []byte{0x00, 0x80, 0x80, 0x10}
	if huge, _ := serveClickHouse(t, oversize); huge.IsClickHouse || len(huge.Raw) > MaxResponseBytes {
		t.Fatalf("oversize = %+v len = %d", huge, len(huge.Raw))
	}
}

func TestProbeForPortSelectsOnly9000(t *testing.T) {
	if ProbeForPort(9000) != Name || ProbeForPort(8123) != "" || ProbeForPort(9004) != "" || ProbeForPort(9440) != "" {
		t.Fatalf("9000 = %s 8123 = %s 9004 = %s 9440 = %s", ProbeForPort(9000), ProbeForPort(8123), ProbeForPort(9004), ProbeForPort(9440))
	}
}

func serveClickHouse(t *testing.T, response []byte) (Result, []byte) {
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
