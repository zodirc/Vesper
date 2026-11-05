package amqpprobe

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

func TestProbeAcceptsAPeerHeaderOrConnectionStart(t *testing.T) {
	header := []byte{'A', 'M', 'Q', 'P', 0, 1, 0, 0}
	got, sent := serveAMQP(t, header)
	if !got.IsAMQP || got.Reply != "1.0" || !bytes.Equal(sent, Request()) {
		t.Fatalf("header = %+v sent = %x", got, sent)
	}
	start := []byte{1, 0, 0, 0, 0, 0, 4, 0, 10, 0, 10, 0xce}
	method, sent := serveAMQP(t, start)
	if !method.IsAMQP || method.Reply != "connection.start" || !bytes.Equal(sent, Request()) {
		t.Fatalf("start = %+v sent = %x", method, sent)
	}
	own := Request()
	same, _ := serveAMQP(t, own)
	if !same.IsAMQP || same.Reply != "0-9-1" {
		t.Fatalf("0-9-1 = %+v", same)
	}
}

func TestProbeRejectsAForeignBanner(t *testing.T) {
	got, sent := serveAMQP(t, []byte("HTTP/1.0 200 OK\r\n\r\n"))
	if got.IsAMQP || !bytes.Equal(sent, Request()) {
		t.Fatalf("http = %+v sent = %x", got, sent)
	}
}

func TestProbeForPortSelectsOnly5672(t *testing.T) {
	if ProbeForPort(5672) != Name || ProbeForPort(5671) != "" || ProbeForPort(5673) != "" {
		t.Fatalf("5672 = %s", ProbeForPort(5672))
	}
}

func TestBudgetStopsBeforeDial(t *testing.T) {
	result, err := Probe(context.Background(), dialer(), deny{}, netip.MustParseAddr("127.0.0.1"), 1, time.Now)
	if err == nil || result.State != "not_scanned" {
		t.Fatalf("result = %+v err = %v", result, err)
	}
}

func serveAMQP(t *testing.T, response []byte) (Result, []byte) {
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
		_ = conn.SetDeadline(time.Now().Add(time.Second))
		buf := make([]byte, 64)
		n, _ := conn.Read(buf)
		_, _ = conn.Write(response)
		_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		extra := make([]byte, 32)
		m, _ := conn.Read(extra)
		sent <- append(append([]byte(nil), buf[:n]...), extra[:m]...)
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
