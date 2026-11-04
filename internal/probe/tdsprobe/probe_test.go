package tdsprobe

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

func TestProbeSendsOnePreloginAndStops(t *testing.T) {
	version, encryption, ok := prelogin(preloginMessage)
	if !ok || version != "0.0.0.0" || encryption != 2 || int(preloginMessage[2])<<8|int(preloginMessage[3]) != len(preloginMessage) {
		t.Fatalf("request = %s encryption = %d ok = %v len = %d", version, encryption, ok, len(preloginMessage))
	}
	reply := serverPrelogin(0x04, []byte{15, 0, 0x07, 0xd0, 0, 5}, 3)
	got, sent := serveTDS(t, reply)
	if !got.IsTDS || got.ServerVersion != "15.0.2000.5" || got.Encryption != 3 || got.State != "open" || string(sent) != string(preloginMessage) || len(got.Raw) != len(reply) {
		t.Fatalf("required = %+v sent = %x", got, sent)
	}
	plain := serverPrelogin(0x12, []byte{0, 0, 0, 0, 0, 0}, 0)
	clear, sent := serveTDS(t, plain)
	if !clear.IsTDS || clear.Encryption != 0 || clear.ServerVersion != "0.0.0.0" || string(sent) != string(preloginMessage) {
		t.Fatalf("clear = %+v sent = %x", clear, sent)
	}
}

func TestProbeRejectsANonTDSPacket(t *testing.T) {
	got, _ := serveTDS(t, []byte("HTTP/1.0 200 OK\r\n\r\n"))
	if got.IsTDS || got.ServerVersion != "" || got.Encryption != -1 || got.State != "open" {
		t.Fatalf("http = %+v", got)
	}
	partial := serverPrelogin(0x04, []byte{15, 0, 0, 1, 0, 0}, 0)
	partial[1] = 0
	if split, _ := serveTDS(t, partial); split.IsTDS {
		t.Fatalf("fragment = %+v", split)
	}
	unknown := serverPrelogin(0x04, []byte{15, 0, 0, 1, 0, 0}, 0)
	unknown = append(unknown[:8], append([]byte{0x08, 0x00, 0x0b, 0x00, 0x01}, unknown[8:]...)...)
	binary.BigEndian.PutUint16(unknown[2:4], uint16(len(unknown)))
	if extra, _ := serveTDS(t, unknown); extra.IsTDS {
		t.Fatalf("token = %+v", extra)
	}
	oversize := []byte{0x04, 0x01, 0x02, 0x01, 0x00, 0x00, 0x01, 0x00}
	if huge, _ := serveTDS(t, oversize); huge.IsTDS || len(huge.Raw) > MaxPacketBytes {
		t.Fatalf("oversize = %+v len = %d", huge, len(huge.Raw))
	}
}

func TestProbeForPortSelectsOnly1433(t *testing.T) {
	if ProbeForPort(1433) != Name || ProbeForPort(1434) != "" || ProbeForPort(3306) != "" {
		t.Fatalf("1433 = %s 1434 = %s 3306 = %s", ProbeForPort(1433), ProbeForPort(1434), ProbeForPort(3306))
	}
}

func serverPrelogin(kind byte, version []byte, encryption byte) []byte {
	body := []byte{
		0x00, 0x00, 0x0b, 0x00, 0x06,
		0x01, 0x00, 0x11, 0x00, 0x01,
		0xff,
	}
	body = append(body, version...)
	body = append(body, encryption)
	raw := make([]byte, 8+len(body))
	raw[0] = kind
	raw[1] = statusEOM
	binary.BigEndian.PutUint16(raw[2:4], uint16(len(raw)))
	raw[6] = 1
	copy(raw[8:], body)
	return raw
}

func serveTDS(t *testing.T, response []byte) (Result, []byte) {
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
