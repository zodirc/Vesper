package tnsprobe

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/zodirc/Vesper/internal/scope"
	"github.com/zodirc/Vesper/pkg/probesdk"
)

func TestProbeSendsOnePingAndStops(t *testing.T) {
	if int(pingMessage[0])<<8|int(pingMessage[1]) != len(pingMessage) || string(pingMessage[58:]) != "(CONNECT_DATA=(COMMAND=ping))" || strings.Contains(string(pingMessage), "version") {
		t.Fatalf("request len = %d data = %q", len(pingMessage), pingMessage[58:])
	}
	reply := descriptionPacket(4, "(DESCRIPTION=(TMP=)(VSNNUM=318767104)(ERR=12505))")
	got, sent := serveTNS(t, reply)
	if !got.IsTNS || got.ServerVersion != "19.0.0.0.0" || got.ErrorCode != 12505 || got.State != "open" || string(sent) != string(pingMessage) || len(got.Raw) != len(reply) {
		t.Fatalf("refuse = %+v sent = %x", got, sent)
	}
	older, _ := vsnnum("153092352")
	if older != "9.2.0.1.0" {
		t.Fatalf("older = %s", older)
	}
	redirect := descriptionPacket(5, "(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=db)(PORT=1521)))")
	moved, sent := serveTNS(t, redirect)
	if !moved.IsTNS || moved.ServerVersion != "" || moved.ErrorCode != -1 || string(sent) != string(pingMessage) {
		t.Fatalf("redirect = %+v sent = %x", moved, sent)
	}
}

func TestProbeRejectsANonTNSPacket(t *testing.T) {
	got, _ := serveTNS(t, []byte("HTTP/1.0 200 OK\r\n\r\n"))
	if got.IsTNS || got.ServerVersion != "" || got.ErrorCode != -1 || got.State != "open" {
		t.Fatalf("http = %+v", got)
	}
	echo := append([]byte(nil), pingMessage...)
	if request, _ := serveTNS(t, echo); request.IsTNS {
		t.Fatalf("echo = %+v", request)
	}
	bare := descriptionPacket(4, "(ERR=0)")
	if missing, _ := serveTNS(t, bare); missing.IsTNS {
		t.Fatalf("missing description = %+v", missing)
	}
	oversize := []byte{0x04, 0x01, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00}
	if huge, _ := serveTNS(t, oversize); huge.IsTNS || len(huge.Raw) > MaxPacketBytes {
		t.Fatalf("oversize = %+v len = %d", huge, len(huge.Raw))
	}
}

func TestProbeForPortSelectsOnly1521(t *testing.T) {
	if ProbeForPort(1521) != Name || ProbeForPort(1522) != "" || ProbeForPort(2484) != "" {
		t.Fatalf("1521 = %s 1522 = %s 2484 = %s", ProbeForPort(1521), ProbeForPort(1522), ProbeForPort(2484))
	}
}

func descriptionPacket(kind byte, text string) []byte {
	raw := make([]byte, 12+len(text))
	raw[4] = kind
	binary.BigEndian.PutUint16(raw[10:12], uint16(len(text)))
	copy(raw[12:], text)
	binary.BigEndian.PutUint16(raw[0:2], uint16(len(raw)))
	return raw
}

func serveTNS(t *testing.T, response []byte) (Result, []byte) {
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
		buf := make([]byte, 128)
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
