package mysqlprobe

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/zodirc/Vesper/internal/scope"
	"github.com/zodirc/Vesper/pkg/probesdk"
)

func TestProbeReadsTheHandshakeAndSendsNothing(t *testing.T) {
	got, sent := serveMySQL(t, packet("8.0.36"))
	if !got.IsMySQL || got.ProtocolVersion != 10 || got.ServerVersion != "8.0.36" || got.State != "open" || len(sent) != 0 {
		t.Fatalf("result = %+v sent = %q", got, sent)
	}
	maria, _ := serveMySQL(t, packet("5.5.5-10.11.6-MariaDB"))
	if !maria.IsMySQL || maria.ServerVersion != "5.5.5-10.11.6-MariaDB" {
		t.Fatalf("maria = %+v", maria)
	}
}

func TestProbeRejectsANonMySQLBanner(t *testing.T) {
	got, _ := serveMySQL(t, []byte("220 (vsFTPd 3.0.5)\r\n"))
	if got.IsMySQL || got.ServerVersion != "" || got.State != "open" {
		t.Fatalf("ftp = %+v", got)
	}
	old := packet("5.0.0")
	old[4] = 9
	rejected, _ := serveMySQL(t, old)
	if rejected.IsMySQL {
		t.Fatalf("protocol 9 = %+v", rejected)
	}
	sequenced := packet("8.0.36")
	sequenced[3] = 1
	if again, _ := serveMySQL(t, sequenced); again.IsMySQL {
		t.Fatalf("sequence = %+v", again)
	}
	empty := []byte{2, 0, 0, 0, 10, 0}
	if bare, _ := serveMySQL(t, empty); bare.IsMySQL {
		t.Fatalf("empty version = %+v", bare)
	}
	oversize := []byte{255, 0, 0, 0, 10}
	if huge, _ := serveMySQL(t, oversize); huge.IsMySQL || len(huge.Raw) > MaxHandshakeBytes {
		t.Fatalf("oversize = %+v len = %d", huge, len(huge.Raw))
	}
}

func TestProbeForPortSelectsOnly3306(t *testing.T) {
	if ProbeForPort(3306) != Name || ProbeForPort(3307) != "" || ProbeForPort(5432) != "" {
		t.Fatalf("3306 = %s 3307 = %s 5432 = %s", ProbeForPort(3306), ProbeForPort(3307), ProbeForPort(5432))
	}
}

func packet(version string) []byte {
	payload := append([]byte{10}, []byte(version)...)
	payload = append(payload, 0, 1, 0, 0, 0)
	raw := []byte{byte(len(payload)), byte(len(payload) >> 8), byte(len(payload) >> 16), 0}
	return append(raw, payload...)
}

func serveMySQL(t *testing.T, greeting []byte) (Result, []byte) {
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
		_, _ = conn.Write(greeting)
		_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		buf := make([]byte, 64)
		n, _ := conn.Read(buf)
		sent <- append([]byte(nil), buf[:n]...)
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
