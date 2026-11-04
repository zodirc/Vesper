package redisprobe

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/zodirc/Vesper/internal/scope"
	"github.com/zodirc/Vesper/pkg/probesdk"
)

func TestProbeSendsOnePingAndStops(t *testing.T) {
	got, sent := serveRedis(t, []byte("+PONG\r\n"))
	if !got.IsRedis || got.Reply != ReplyPONG || got.State != "open" || string(sent) != string(pingCommand) {
		t.Fatalf("pong = %+v sent = %q", got, sent)
	}
	auth, sent := serveRedis(t, []byte("-NOAUTH Authentication required.\r\n"))
	if !auth.IsRedis || auth.Reply != ReplyNOAUTH || string(sent) != string(pingCommand) {
		t.Fatalf("noauth = %+v sent = %q", auth, sent)
	}
	denied, sent := serveRedis(t, []byte("-DENIED Redis is running in protected mode because protected mode is enabled.\r\n"))
	if !denied.IsRedis || denied.Reply != ReplyDENIED || string(sent) != string(pingCommand) {
		t.Fatalf("denied = %+v sent = %q", denied, sent)
	}
}

func TestProbeRejectsANonRedisReply(t *testing.T) {
	got, _ := serveRedis(t, []byte("HTTP/1.0 200 OK\r\n\r\n"))
	if got.IsRedis || got.Reply != "" || got.State != "open" {
		t.Fatalf("http = %+v", got)
	}
	if partial, _ := serveRedis(t, []byte("+PONG")); partial.IsRedis {
		t.Fatalf("partial = %+v", partial)
	}
	if other, _ := serveRedis(t, []byte("-ERR unknown command\r\n")); other.IsRedis {
		t.Fatalf("error = %+v", other)
	}
	if bulk, _ := serveRedis(t, []byte("$4\r\nPONG\r\n")); bulk.IsRedis {
		t.Fatalf("bulk = %+v", bulk)
	}
	oversize := []byte(strings.Repeat("+", MaxReplyBytes))
	if huge, _ := serveRedis(t, oversize); huge.IsRedis || len(huge.Raw) > MaxReplyBytes {
		t.Fatalf("oversize = %+v len = %d", huge, len(huge.Raw))
	}
}

func TestProbeForPortSelectsOnly6379(t *testing.T) {
	if ProbeForPort(6379) != Name || ProbeForPort(6380) != "" || ProbeForPort(3306) != "" {
		t.Fatalf("6379 = %s 6380 = %s 3306 = %s", ProbeForPort(6379), ProbeForPort(6380), ProbeForPort(3306))
	}
}

func serveRedis(t *testing.T, response []byte) (Result, []byte) {
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
