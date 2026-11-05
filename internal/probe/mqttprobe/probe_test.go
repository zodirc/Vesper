package mqttprobe

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

func TestConnectHasNoCredentials(t *testing.T) {
	raw := Request()
	if len(raw) != 20 || raw[0] != 0x10 || raw[1] != 0x12 || raw[8] != 0x04 || raw[9] != 0x02 || string(raw[14:]) != "vesper" {
		t.Fatalf("connect = %x", raw)
	}
}

func TestProbeAcceptsAnyDefinedReturnCodeAndStops(t *testing.T) {
	got, sent := serveMQTT(t, []byte{0x20, 0x02, 0x00, 0x00})
	if !got.IsMQTT || got.AckCode != 0 || !bytes.Equal(sent, Request()) {
		t.Fatalf("accept = %+v sent = %x", got, sent)
	}
	denied, sent := serveMQTT(t, []byte{0x20, 0x02, 0x00, 0x05})
	if !denied.IsMQTT || denied.AckCode != 5 || !bytes.Equal(sent, Request()) {
		t.Fatalf("denied = %+v sent = %x", denied, sent)
	}
	present, _ := serveMQTT(t, []byte{0x20, 0x02, 0x01, 0x00})
	if !present.IsMQTT || present.AckCode != 0 {
		t.Fatalf("session = %+v", present)
	}
}

func TestProbeRejectsAMalformedConnack(t *testing.T) {
	for _, payload := range [][]byte{{0x20, 0x02, 0x00, 0x06}, {0x20, 0x02, 0x02, 0x00}, {0x10, 0x02, 0x00, 0x00}} {
		got, _ := serveMQTT(t, payload)
		if got.IsMQTT {
			t.Fatalf("%x = %+v", payload, got)
		}
	}
}

func TestProbeForPortSelectsOnly1883(t *testing.T) {
	if ProbeForPort(1883) != Name || ProbeForPort(8883) != "" || ProbeForPort(1884) != "" {
		t.Fatalf("1883 = %s", ProbeForPort(1883))
	}
}

func TestBudgetStopsBeforeDial(t *testing.T) {
	result, err := Probe(context.Background(), dialer(), deny{}, netip.MustParseAddr("127.0.0.1"), 1, time.Now)
	if err == nil || result.State != "not_scanned" {
		t.Fatalf("result = %+v err = %v", result, err)
	}
}

func serveMQTT(t *testing.T, response []byte) (Result, []byte) {
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
