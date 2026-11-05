package natsprobe

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/zodirc/Vesper/internal/scope"
	"github.com/zodirc/Vesper/pkg/probesdk"
)

func TestProbeReadsInfoAndSendsNothing(t *testing.T) {
	raw := []byte("INFO {\"server_id\":\"abc\",\"version\":\"2.10.18\",\"auth_required\":true}\r\n")
	got, sent := serveNATS(t, raw)
	if !got.IsNATS || got.ServerVersion != "2.10.18" || len(sent) != 0 || !bytes.Equal(got.Raw, raw) {
		t.Fatalf("info = %+v sent = %q", got, sent)
	}
	empty, _ := serveNATS(t, []byte("INFO {}\r\n"))
	if !empty.IsNATS || empty.ServerVersion != "" {
		t.Fatalf("empty = %+v", empty)
	}
}

func TestProbeRejectsANonInfoLine(t *testing.T) {
	for _, payload := range []string{"INFO not-json\r\n", "CONNECT {}\r\n", "INFO {}\n", "PING\r\n"} {
		got, _ := serveNATS(t, []byte(payload))
		if got.IsNATS {
			t.Fatalf("%q = %+v", payload, got)
		}
	}
}

func TestProbeForPortSelectsOnly4222(t *testing.T) {
	if ProbeForPort(4222) != Name || ProbeForPort(4223) != "" || ProbeForPort(6222) != "" {
		t.Fatalf("4222 = %s", ProbeForPort(4222))
	}
}

func TestBudgetStopsBeforeDial(t *testing.T) {
	result, err := Probe(context.Background(), dialer(), deny{}, netip.MustParseAddr("127.0.0.1"), 1, time.Now)
	if err == nil || result.State != "not_scanned" {
		t.Fatalf("result = %+v err = %v", result, err)
	}
}

func serveNATS(t *testing.T, response []byte) (Result, []byte) {
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
		_, _ = conn.Write(response)
		_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		buf := make([]byte, 32)
		n, _ := conn.Read(buf)
		sent <- append([]byte(nil), buf[:n]...)
	}()
	result, err := Probe(context.Background(), dialer(), account(), netip.MustParseAddr("127.0.0.1"), listener.Addr().(*net.TCPAddr).Port, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	return result, <-sent
}

func account() *scope.Account {
	return scope.NewAccount(scope.Budget{
		MaxTargets: 1, MaxAddresses: 1, MaxConnections: 4, MaxRequests: 4, MaxConcurrency: 1,
		MaxRatePerSecond: 1000, MaxRuntime: time.Minute, MaxEvidenceBytes: 10000,
	}, time.Now())
}

func dialer() probesdk.Dialer {
	return probesdk.Dialer{Auth: allow{}, Budget: account(), Timeout: time.Second, Now: time.Now}
}

type allow struct{}

func (allow) Authorize(context.Context, netip.Addr, int, string, string) error { return nil }

type deny struct{}

func (deny) AcquireRequest(context.Context, time.Time) error { return fmt.Errorf("budget") }
