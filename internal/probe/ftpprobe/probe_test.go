package ftpprobe

import (
	"context"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/zodirc/Vesper/internal/scope"
	"github.com/zodirc/Vesper/pkg/probesdk"
)

func TestProbeReadsTheGreetingAndSendsNothing(t *testing.T) {
	got, sent := serveFTP(t, "220 (vsFTPd 3.0.5)\r\n")
	if !got.IsFTP || got.ReplyCode != "220" || got.Banner != "220 (vsFTPd 3.0.5)" || got.State != "open" || len(sent) != 0 {
		t.Fatalf("result = %+v sent = %q", got, sent)
	}
	multiline, _ := serveFTP(t, "220-Welcome\r\n220 ready\r\n")
	if !multiline.IsFTP || multiline.ReplyCode != "220" || multiline.Banner != "220-Welcome" {
		t.Fatalf("multiline = %+v", multiline)
	}
	early, _ := serveFTP(t, "120 Service ready in 2 minutes\r\n")
	if !early.IsFTP || early.ReplyCode != "120" {
		t.Fatalf("early = %+v", early)
	}
	closing, _ := serveFTP(t, "421 Service not available\r\n")
	if !closing.IsFTP || closing.ReplyCode != "421" {
		t.Fatalf("closing = %+v", closing)
	}
}

func TestProbeRejectsANonFTPBanner(t *testing.T) {
	got, _ := serveFTP(t, "HTTP/1.0 200 OK\r\n\r\n")
	if got.IsFTP || got.ReplyCode != "" || got.State != "open" || !strings.HasPrefix(got.Banner, "HTTP/1.0") {
		t.Fatalf("result = %+v", got)
	}
	short, _ := serveFTP(t, "220\r\n")
	if short.IsFTP {
		t.Fatalf("short = %+v", short)
	}
}

func TestProbeStopsAtTheReadLimit(t *testing.T) {
	got, _ := serveFTP(t, strings.Repeat("A", MaxBannerBytes+40))
	if got.IsFTP || len(got.Raw) != MaxBannerBytes {
		t.Fatalf("len = %d ftp = %v", len(got.Raw), got.IsFTP)
	}
}

func TestProbeForPortSelectsOnly21(t *testing.T) {
	if ProbeForPort(21) != Name || ProbeForPort(80) != "" || ProbeForPort(2121) != "" {
		t.Fatalf("21 = %s 80 = %s 2121 = %s", ProbeForPort(21), ProbeForPort(80), ProbeForPort(2121))
	}
}

func serveFTP(t *testing.T, greeting string) (Result, []byte) {
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
		_, _ = io.WriteString(conn, greeting)
		_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		buf := make([]byte, 64)
		n, _ := conn.Read(buf)
		sent <- append([]byte(nil), buf[:n]...)
	}()
	port := listener.Addr().(*net.TCPAddr).Port
	account := scope.NewAccount(scope.Budget{
		MaxTargets: 1, MaxAddresses: 1, MaxConnections: 2, MaxRequests: 2, MaxConcurrency: 1,
		MaxRatePerSecond: 1000, MaxRuntime: time.Minute, MaxEvidenceBytes: 10000,
	}, time.Now())
	dial := probesdk.Dialer{Auth: allow{}, Budget: account, Timeout: time.Second, Now: time.Now}
	result, err := Probe(context.Background(), dial, account, netip.MustParseAddr("127.0.0.1"), port, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	return result, <-sent
}

type allow struct{}

func (allow) Authorize(context.Context, netip.Addr, int, string, string) error { return nil }
