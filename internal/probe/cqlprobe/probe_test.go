package cqlprobe

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

func TestProbeSendsOneStartupAndStops(t *testing.T) {
	if int(binary.BigEndian.Uint32(startupMessage[5:9]))+9 != len(startupMessage) || string(startupMessage[len(startupMessage)-5:]) != "3.0.0" {
		t.Fatalf("request = %x", startupMessage)
	}
	ready := frame(0x84, 0x02, nil)
	got, sent := serveCQL(t, ready)
	if !got.IsCQL || got.Reply != ReplyReady || got.ProtocolVersion != 4 || got.State != "open" || string(sent) != string(startupMessage) || len(got.Raw) != len(ready) {
		t.Fatalf("ready = %+v sent = %x", got, sent)
	}
	auth := frame(0x83, 0x03, cqlString("PasswordAuthenticator"))
	challenge, sent := serveCQL(t, auth)
	if !challenge.IsCQL || challenge.Reply != ReplyAuthenticate || challenge.ProtocolVersion != 3 || string(sent) != string(startupMessage) {
		t.Fatalf("auth = %+v sent = %x", challenge, sent)
	}
}

func TestProbeRejectsANonCQLFrame(t *testing.T) {
	got, _ := serveCQL(t, []byte("HTTP/1.0 200 OK\r\n\r\n"))
	if got.IsCQL || got.Reply != "" || got.ProtocolVersion != 0 || got.State != "open" {
		t.Fatalf("http = %+v", got)
	}
	if echoed, _ := serveCQL(t, append([]byte(nil), startupMessage...)); echoed.IsCQL {
		t.Fatalf("echo = %+v", echoed)
	}
	compressed := frame(0x84, 0x02, nil)
	compressed[1] = 0x01
	if flagged, _ := serveCQL(t, compressed); flagged.IsCQL {
		t.Fatalf("compressed = %+v", flagged)
	}
	if empty, _ := serveCQL(t, frame(0x84, 0x03, cqlString(""))); empty.IsCQL {
		t.Fatalf("empty authenticator = %+v", empty)
	}
	oversize := []byte{0x84, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x02, 0x00}
	if huge, _ := serveCQL(t, oversize); huge.IsCQL || len(huge.Raw) > MaxFrameBytes {
		t.Fatalf("oversize = %+v len = %d", huge, len(huge.Raw))
	}
}

func TestProbeForPortSelectsOnly9042(t *testing.T) {
	if ProbeForPort(9042) != Name || ProbeForPort(9043) != "" || ProbeForPort(9160) != "" {
		t.Fatalf("9042 = %s 9043 = %s 9160 = %s", ProbeForPort(9042), ProbeForPort(9043), ProbeForPort(9160))
	}
}

func frame(version, opcode byte, body []byte) []byte {
	raw := make([]byte, 9+len(body))
	raw[0] = version
	raw[4] = opcode
	binary.BigEndian.PutUint32(raw[5:9], uint32(len(body)))
	copy(raw[9:], body)
	return raw
}

func cqlString(text string) []byte {
	raw := make([]byte, 2+len(text))
	binary.BigEndian.PutUint16(raw[:2], uint16(len(text)))
	copy(raw[2:], text)
	return raw
}

func serveCQL(t *testing.T, response []byte) (Result, []byte) {
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
