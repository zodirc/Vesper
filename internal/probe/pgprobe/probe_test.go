package pgprobe

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/zodirc/Vesper/internal/scope"
	"github.com/zodirc/Vesper/pkg/probesdk"
)

func TestProbeSendsOneStartupAndStopsBeforeAuthentication(t *testing.T) {
	got, sent := servePG(t, authMessage(5))
	if !got.IsPostgreSQL || got.MessageType != "R" || got.AuthMethod != 5 || got.State != "open" || string(sent) != string(startupMessage) {
		t.Fatalf("result = %+v sent = %x", got, sent)
	}
	trusted, sent := servePG(t, authMessage(0))
	if !trusted.IsPostgreSQL || trusted.AuthMethod != 0 || string(sent) != string(startupMessage) {
		t.Fatalf("trusted = %+v sent = %x", trusted, sent)
	}
	failed, _ := servePG(t, errorMessage())
	if !failed.IsPostgreSQL || failed.MessageType != "E" || failed.AuthMethod != -1 {
		t.Fatalf("error response = %+v", failed)
	}
}

func TestProbeRejectsANonPostgreSQLBanner(t *testing.T) {
	got, _ := servePG(t, []byte("HTTP/1.0 200 OK\r\n\r\n"))
	if got.IsPostgreSQL || got.MessageType != "" || got.State != "open" {
		t.Fatalf("http = %+v", got)
	}
	short := []byte{'R', 0, 0, 0, 8}
	if partial, _ := servePG(t, short); partial.IsPostgreSQL {
		t.Fatalf("partial = %+v", partial)
	}
	oversize := []byte{'R', 0, 0, 4, 1}
	if huge, _ := servePG(t, oversize); huge.IsPostgreSQL || len(huge.Raw) > MaxMessageBytes {
		t.Fatalf("oversize = %+v len = %d", huge, len(huge.Raw))
	}
}

func TestProbeForPortSelectsOnly5432(t *testing.T) {
	if ProbeForPort(5432) != Name || ProbeForPort(5433) != "" || ProbeForPort(3306) != "" {
		t.Fatalf("5432 = %s 5433 = %s 3306 = %s", ProbeForPort(5432), ProbeForPort(5433), ProbeForPort(3306))
	}
}

func authMessage(method uint32) []byte {
	raw := []byte{'R', 0, 0, 0, 8, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(raw[5:], method)
	return raw
}

func errorMessage() []byte {
	fields := []byte("SERROR\x00C28000\x00Mno\x00\x00")
	raw := make([]byte, 5+len(fields))
	raw[0] = 'E'
	binary.BigEndian.PutUint32(raw[1:5], uint32(4+len(fields)))
	copy(raw[5:], fields)
	return raw
}

func servePG(t *testing.T, reply []byte) (Result, []byte) {
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
		_, _ = conn.Write(reply)
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
