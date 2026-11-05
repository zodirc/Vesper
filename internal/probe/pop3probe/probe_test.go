package pop3probe

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/zodirc/Vesper/internal/scope"
	"github.com/zodirc/Vesper/pkg/probesdk"
)

func TestProbeReadsTheGreetingAndSendsNothing(t *testing.T) {
	got, sent := servePOP3(t, []byte("+OK ready\r\n"))
	if !got.IsPOP3 || got.ReplyCode != "+OK" || got.Reply != "+OK ready" || len(sent) != 0 {
		t.Fatalf("ok = %+v sent = %q", got, sent)
	}
	errLine, _ := servePOP3(t, []byte("-ERR closed\r\n"))
	if !errLine.IsPOP3 || errLine.ReplyCode != "-ERR" {
		t.Fatalf("err = %+v", errLine)
	}
	bare, _ := servePOP3(t, []byte("+OK\r\n"))
	if !bare.IsPOP3 || bare.Reply != "+OK" {
		t.Fatalf("bare = %+v", bare)
	}
}

func TestProbeRejectsANonPOP3Line(t *testing.T) {
	for _, payload := range []string{"+OKAY\r\n", "OK ready\r\n", "+OK ready\n", "HTTP/1.0 200 OK\r\n"} {
		got, _ := servePOP3(t, []byte(payload))
		if got.IsPOP3 {
			t.Fatalf("%q = %+v", payload, got)
		}
	}
}

func TestProbeForPortSelectsOnly110(t *testing.T) {
	if ProbeForPort(110) != Name || ProbeForPort(995) != "" || ProbeForPort(111) != "" {
		t.Fatalf("110 = %s", ProbeForPort(110))
	}
}

func TestBudgetStopsBeforeDial(t *testing.T) {
	result, err := Probe(context.Background(), dialer(), deny{}, netip.MustParseAddr("127.0.0.1"), 1, time.Now)
	if err == nil || result.State != "not_scanned" {
		t.Fatalf("result = %+v err = %v", result, err)
	}
}

func servePOP3(t *testing.T, response []byte) (Result, []byte) {
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
