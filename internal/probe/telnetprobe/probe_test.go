package telnetprobe

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

func TestProbeRecognizesIACAndALoginLine(t *testing.T) {
	got, sent := serveTelnet(t, []byte{0xff, 0xfb, 0x01})
	if !got.IsTelnet || got.Banner != "" || got.State != "open" || len(sent) != 0 {
		t.Fatalf("iac = %+v sent = %q", got, sent)
	}
	login, sent := serveTelnet(t, []byte("User login:\r\n"))
	if !login.IsTelnet || login.Banner != "User login:" || len(sent) != 0 {
		t.Fatalf("login = %+v sent = %q", login, sent)
	}
}

func TestProbeRejectsTextThatIsNotTelnet(t *testing.T) {
	http, _ := serveTelnet(t, []byte("HTTP/1.0 200 OK\r\n\r\n"))
	if http.IsTelnet {
		t.Fatalf("http = %+v", http)
	}
	page, _ := serveTelnet(t, []byte("Please login: now\r\n"))
	if !page.IsTelnet || page.Banner != "Please login: now" {
		t.Fatalf("login line = %+v", page)
	}
	welcome, _ := serveTelnet(t, []byte("Welcome\r\n"))
	if welcome.IsTelnet {
		t.Fatalf("welcome = %+v", welcome)
	}
	escaped, _ := serveTelnet(t, []byte{0xff, 0xff, 'A', '\r', '\n'})
	if escaped.IsTelnet {
		t.Fatalf("escaped = %+v", escaped)
	}
	bare, _ := serveTelnet(t, []byte("login:\n"))
	if bare.IsTelnet {
		t.Fatalf("lf = %+v", bare)
	}
}

func TestProbeForPortSelectsOnly23(t *testing.T) {
	if ProbeForPort(23) != Name || ProbeForPort(22) != "" || ProbeForPort(2323) != "" {
		t.Fatalf("23 = %s", ProbeForPort(23))
	}
}

func TestBudgetStopsBeforeDial(t *testing.T) {
	result, err := Probe(context.Background(), dialer(), deny{}, netip.MustParseAddr("127.0.0.1"), 1, time.Now)
	if err == nil || result.State != "not_scanned" {
		t.Fatalf("result = %+v err = %v", result, err)
	}
}

func serveTelnet(t *testing.T, response []byte) (Result, []byte) {
	t.Helper()
	return serveBanner(t, response)
}

func serveBanner(t *testing.T, response []byte) (Result, []byte) {
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
