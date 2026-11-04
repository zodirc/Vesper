package memcachedprobe

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/zodirc/Vesper/internal/scope"
	"github.com/zodirc/Vesper/pkg/probesdk"
)

func TestProbeSendsOneVersionAndStops(t *testing.T) {
	if string(versionCommand) != "version\r\n" {
		t.Fatalf("request = %q", versionCommand)
	}
	got, sent := serveMemcached(t, []byte("VERSION 1.6.22\r\n"))
	if !got.IsMemcached || got.ServerVersion != "1.6.22" || got.State != "open" || string(sent) != string(versionCommand) || string(got.Raw) != "VERSION 1.6.22\r\n" {
		t.Fatalf("version = %+v sent = %q", got, sent)
	}
}

func TestProbeRejectsANonMemcachedReply(t *testing.T) {
	got, _ := serveMemcached(t, []byte("HTTP/1.0 200 OK\r\n\r\n"))
	if got.IsMemcached || got.ServerVersion != "" || got.State != "open" {
		t.Fatalf("http = %+v", got)
	}
	if echoed, _ := serveMemcached(t, append([]byte(nil), versionCommand...)); echoed.IsMemcached {
		t.Fatalf("echo = %+v", echoed)
	}
	if errLine, _ := serveMemcached(t, []byte("ERROR\r\n")); errLine.IsMemcached {
		t.Fatalf("error = %+v", errLine)
	}
	if empty, _ := serveMemcached(t, []byte("VERSION \r\n")); empty.IsMemcached {
		t.Fatalf("empty token = %+v", empty)
	}
	if spaced, _ := serveMemcached(t, []byte("VERSION 1.6.22 build\r\n")); spaced.IsMemcached {
		t.Fatalf("spaced token = %+v", spaced)
	}
	oversize := append([]byte("VERSION "), bytesRepeat('a', MaxReplyBytes)...)
	if huge, _ := serveMemcached(t, oversize); huge.IsMemcached || len(huge.Raw) > MaxReplyBytes {
		t.Fatalf("oversize = %+v len = %d", huge, len(huge.Raw))
	}
}

func TestProbeForPortSelectsOnly11211(t *testing.T) {
	if ProbeForPort(11211) != Name || ProbeForPort(11212) != "" || ProbeForPort(11210) != "" {
		t.Fatalf("11211 = %s 11212 = %s 11210 = %s", ProbeForPort(11211), ProbeForPort(11212), ProbeForPort(11210))
	}
}

func bytesRepeat(b byte, n int) []byte {
	raw := make([]byte, n)
	for i := range raw {
		raw[i] = b
	}
	return raw
}

func serveMemcached(t *testing.T, response []byte) (Result, []byte) {
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
