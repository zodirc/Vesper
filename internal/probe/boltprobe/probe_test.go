package boltprobe

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/zodirc/Vesper/internal/scope"
	"github.com/zodirc/Vesper/pkg/probesdk"
)

func TestProbeSendsOneHandshakeAndStops(t *testing.T) {
	if len(handshake) != 20 || handshake[0] != 0x60 || handshake[3] != 0x17 || handshake[4] != 0x00 || handshake[7] != 0x05 {
		t.Fatalf("request = %x", handshake)
	}
	for _, version := range []struct {
		major, minor byte
		text         string
	}{
		{5, 4, "5.4"},
		{4, 1, "4.1"},
		{3, 0, "3.0"},
	} {
		got, sent := serveBolt(t, []byte{0x00, 0x00, version.minor, version.major})
		if !got.IsBolt || got.ProtocolVersion != version.text || got.State != "open" || string(sent) != string(handshake) || len(got.Raw) != MaxResponseBytes {
			t.Fatalf("version %s = %+v sent = %x", version.text, got, sent)
		}
	}
}

func TestProbeRejectsANonBoltResponse(t *testing.T) {
	got, _ := serveBolt(t, []byte("HTTP/1.0 200 OK\r\n\r\n"))
	if got.IsBolt || got.ProtocolVersion != "" || got.State != "open" {
		t.Fatalf("http = %+v", got)
	}
	if echoed, _ := serveBolt(t, append([]byte(nil), handshake...)); echoed.IsBolt {
		t.Fatalf("echo = %+v", echoed)
	}
	if none, _ := serveBolt(t, []byte{0x00, 0x00, 0x00, 0x00}); none.IsBolt {
		t.Fatalf("no version = %+v", none)
	}
	if ranged, _ := serveBolt(t, []byte{0x00, 0x08, 0x08, 0x05}); ranged.IsBolt {
		t.Fatalf("range = %+v", ranged)
	}
	if bolt2, _ := serveBolt(t, []byte{0x00, 0x00, 0x00, 0x02}); bolt2.IsBolt {
		t.Fatalf("bolt 2 = %+v", bolt2)
	}
	if future, _ := serveBolt(t, []byte{0x00, 0x00, 0x09, 0x05}); future.IsBolt {
		t.Fatalf("5.9 = %+v", future)
	}
	if short, _ := serveBolt(t, []byte{0x00, 0x00, 0x04}); short.IsBolt || len(short.Raw) > MaxResponseBytes {
		t.Fatalf("short = %+v", short)
	}
}

func TestProbeForPortSelectsOnly7687(t *testing.T) {
	if ProbeForPort(7687) != Name || ProbeForPort(7474) != "" || ProbeForPort(7688) != "" {
		t.Fatalf("7687 = %s 7474 = %s 7688 = %s", ProbeForPort(7687), ProbeForPort(7474), ProbeForPort(7688))
	}
}

func serveBolt(t *testing.T, response []byte) (Result, []byte) {
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
