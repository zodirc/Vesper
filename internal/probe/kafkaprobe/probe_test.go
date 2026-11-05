package kafkaprobe

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

func TestRequestIsApiVersionsWithoutABody(t *testing.T) {
	raw := Request()
	if len(raw) != 20 || binary.BigEndian.Uint32(raw[:4]) != 16 || binary.BigEndian.Uint16(raw[4:6]) != apiVersionsKey || binary.BigEndian.Uint16(raw[6:8]) != 0 {
		t.Fatalf("request = %x", raw)
	}
	if binary.BigEndian.Uint32(raw[8:12]) != correlationID || string(raw[14:]) != "vesper" {
		t.Fatalf("header = %x", raw)
	}
}

func TestProbeMatchesTheCorrelationAndStops(t *testing.T) {
	got, sent := serveKafka(t, frame(correlationID, 0, 0))
	if !got.IsKafka || got.ErrorCode != 0 || !bytes.Equal(sent, Request()) {
		t.Fatalf("empty = %+v sent = %x", got, sent)
	}
	unsupported, sent := serveKafka(t, frame(correlationID, 35, -1))
	if !unsupported.IsKafka || unsupported.ErrorCode != 35 || !bytes.Equal(sent, Request()) {
		t.Fatalf("unsupported = %+v sent = %x", unsupported, sent)
	}
}

func TestProbeRejectsADifferentCorrelation(t *testing.T) {
	got, _ := serveKafka(t, frame(2, 0, 0))
	if got.IsKafka {
		t.Fatalf("correlation = %+v", got)
	}
	short := make([]byte, 8)
	binary.BigEndian.PutUint32(short[:4], 4)
	if other, _ := serveKafka(t, short); other.IsKafka {
		t.Fatalf("short = %+v", other)
	}
}

func TestProbeForPortSelectsOnly9092(t *testing.T) {
	if ProbeForPort(9092) != Name || ProbeForPort(9093) != "" || ProbeForPort(9091) != "" {
		t.Fatalf("9092 = %s", ProbeForPort(9092))
	}
}

func TestBudgetStopsBeforeDial(t *testing.T) {
	result, err := Probe(context.Background(), dialer(), deny{}, netip.MustParseAddr("127.0.0.1"), 1, time.Now)
	if err == nil || result.State != "not_scanned" {
		t.Fatalf("result = %+v err = %v", result, err)
	}
}

func frame(correlation uint32, code int16, apis int) []byte {
	size := 6
	if apis >= 0 {
		size = 10 + apis*6
	}
	body := make([]byte, size)
	binary.BigEndian.PutUint32(body[0:4], correlation)
	binary.BigEndian.PutUint16(body[4:6], uint16(code))
	if apis >= 0 {
		binary.BigEndian.PutUint32(body[6:10], uint32(apis))
	}
	raw := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(raw[:4], uint32(len(body)))
	copy(raw[4:], body)
	return raw
}

func serveKafka(t *testing.T, response []byte) (Result, []byte) {
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
