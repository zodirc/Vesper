package rdpprobe

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/zodirc/Vesper/internal/scope"
	"github.com/zodirc/Vesper/pkg/probesdk"
)

func TestRequestAsksForStandardRDPSecurity(t *testing.T) {
	raw := Request()
	if len(raw) != 19 || raw[0] != 0x03 || binary.BigEndian.Uint16(raw[2:4]) != 19 || raw[5] != 0xe0 || raw[11] != 0x01 {
		t.Fatalf("request = %x", raw)
	}
	if binary.LittleEndian.Uint32(raw[15:19]) != 0 {
		t.Fatalf("protocols = %x", raw[15:])
	}
}

func TestProbeStopsAfterConnectionConfirm(t *testing.T) {
	got, sent := serveRDP(t, negotiationPacket(negotiationResponse, 1))
	if !got.IsRDP || got.Negotiation != "response" || got.SelectedProtocol != 1 || !bytes.Equal(sent, Request()) {
		t.Fatalf("tls selected = %+v sent = %x", got, sent)
	}
	failure, sent := serveRDP(t, negotiationPacket(negotiationFailure, 2))
	if !failure.IsRDP || failure.Negotiation != "failure" || failure.FailureCode != 2 || !bytes.Equal(sent, Request()) {
		t.Fatalf("failure = %+v sent = %x", failure, sent)
	}
	legacy := make([]byte, 11)
	legacy[0] = 0x03
	binary.BigEndian.PutUint16(legacy[2:4], 11)
	legacy[5] = x224ConnectionConfirm
	plain, _ := serveRDP(t, legacy)
	if !plain.IsRDP || plain.Negotiation != "" {
		t.Fatalf("legacy = %+v", plain)
	}
}

func TestProbeRejectsARequestEcho(t *testing.T) {
	echo := Request()
	got, sent := serveRDP(t, echo)
	if got.IsRDP || !bytes.Equal(sent, Request()) {
		t.Fatalf("echo = %+v sent = %x", got, sent)
	}
}

func TestProbeForPortSelectsOnly3389(t *testing.T) {
	if ProbeForPort(3389) != Name || ProbeForPort(3390) != "" || ProbeForPort(3388) != "" {
		t.Fatalf("3389 = %s", ProbeForPort(3389))
	}
}

func TestBudgetStopsBeforeDial(t *testing.T) {
	result, err := Probe(context.Background(), dialer(), deny{}, netip.MustParseAddr("127.0.0.1"), 1, time.Now)
	if err == nil || result.State != "not_scanned" {
		t.Fatalf("result = %+v err = %v", result, err)
	}
}

func negotiationPacket(kind byte, value uint32) []byte {
	raw := make([]byte, 19)
	raw[0] = 0x03
	binary.BigEndian.PutUint16(raw[2:4], 19)
	raw[4] = 0x0e
	raw[5] = x224ConnectionConfirm
	raw[11] = kind
	binary.LittleEndian.PutUint16(raw[13:15], 8)
	binary.LittleEndian.PutUint32(raw[15:19], value)
	return raw
}

func serveRDP(t *testing.T, response []byte) (Result, []byte) {
	t.Helper()
	return serveRequest(t, response, 64)
}

func serveRequest(t *testing.T, response []byte, limit int) (Result, []byte) {
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
		buf := make([]byte, limit)
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
