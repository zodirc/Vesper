package udp

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/zodirc/Vesper/internal/scope"
	"github.com/zodirc/Vesper/pkg/probesdk"
)

func TestQueryEncodesTheNameAndMatchesOnlyItsResponse(t *testing.T) {
	query, err := Query(0x1234, "example.com", dnsQTypeA)
	if err != nil {
		t.Fatal(err)
	}
	if binary.BigEndian.Uint16(query[0:2]) != 0x1234 || binary.BigEndian.Uint16(query[2:4]) != 0x0100 || binary.BigEndian.Uint16(query[4:6]) != 1 {
		t.Fatalf("header = %x", query[:12])
	}
	name := append([]byte{7}, []byte("example")...)
	name = append(name, 3)
	name = append(name, []byte("com")...)
	name = append(name, 0)
	if string(query[12:12+len(name)]) != string(name) {
		t.Fatalf("name = %x", query[12:])
	}
	qtypeOff := 12 + len(name)
	if binary.BigEndian.Uint16(query[qtypeOff:]) != dnsQTypeA || binary.BigEndian.Uint16(query[qtypeOff+2:]) != dnsClassIN {
		t.Fatalf("question = %x", query[qtypeOff:])
	}
	response := make([]byte, 12)
	copy(response[:2], query[:2])
	response[2] = 0x80
	if !ResponseMatches(0x1234, response) {
		t.Fatal("matching response was rejected")
	}
	response[2] = 0x00
	if ResponseMatches(0x1234, response) {
		t.Fatal("response without QR matched")
	}
	response[2] = 0x88
	if ResponseMatches(0x1234, response) {
		t.Fatal("non-query opcode matched")
	}
	if _, err := Query(1, "bad_name", dnsQTypeA); err == nil {
		t.Fatal("invalid label was accepted")
	}
}

func TestProbeDNSRetriesTimeoutAndStopsOnICMPOrMismatch(t *testing.T) {
	var calls int
	result, err := ProbeDNS(context.Background(), func(context.Context, []byte) ([]byte, error) {
		calls++
		if calls == 1 {
			return nil, &probesdk.Error{Class: probesdk.ClassTimeout, Message: "timeout"}
		}
		return nil, &probesdk.Error{Class: probesdk.ClassTimeout, Message: "timeout"}
	}, "example.com")
	if err != nil || calls != DNSAttempts || result.Rounds != DNSAttempts || result.Outcome.State != "no_response" || result.QType != dnsQTypeA {
		t.Fatalf("calls=%d result=%+v err=%v", calls, result, err)
	}

	calls = 0
	result, err = ProbeDNS(context.Background(), func(_ context.Context, payload []byte) ([]byte, error) {
		calls++
		if calls == 1 {
			return nil, &probesdk.Error{Class: probesdk.ClassTimeout, Message: "timeout"}
		}
		response := make([]byte, 12)
		copy(response[:2], payload[:2])
		response[2] = 0x80
		return response, nil
	}, "")
	if err != nil || calls != 2 || result.Outcome.State != "open" || result.Rounds != 2 || result.QName != "." || result.QType != dnsQTypeNS {
		t.Fatalf("calls=%d result=%+v err=%v", calls, result, err)
	}

	calls = 0
	result, err = ProbeDNS(context.Background(), func(context.Context, []byte) ([]byte, error) {
		calls++
		return nil, &probesdk.Error{Class: probesdk.ClassICMPUnreachable, Message: "icmp port unreachable"}
	}, "example.com")
	if err != nil || calls != 1 || result.Outcome.State != "closed" || result.Rounds != 1 {
		t.Fatalf("calls=%d result=%+v err=%v", calls, result, err)
	}

	calls = 0
	result, err = ProbeDNS(context.Background(), func(context.Context, []byte) ([]byte, error) {
		calls++
		response := make([]byte, 12)
		response[2] = 0x80
		return response, nil
	}, "example.com")
	if err != nil || calls != 1 || result.Outcome.State != "unknown" || result.Outcome.Status != "observed" {
		t.Fatalf("calls=%d result=%+v err=%v", calls, result, err)
	}
}

func TestProbeDNSAuthorizationDoesNotCountARound(t *testing.T) {
	result, err := ProbeDNS(context.Background(), func(context.Context, []byte) ([]byte, error) {
		return nil, &probesdk.Error{Class: probesdk.ClassAuthorization, Message: "denied"}
	}, "example.com")
	if err != nil || result.Rounds != 0 || result.Outcome.State != "not_scanned" {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}

func TestExchangeUDPHonorsMatchTimeoutICMPAndDenial(t *testing.T) {
	match, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer match.Close()
	go func() {
		buf := make([]byte, DNSMaxResponseBytes)
		_ = match.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, addr, err := match.ReadFrom(buf)
		if err != nil || n < 2 || addr == nil {
			return
		}
		response := make([]byte, 12)
		copy(response[:2], buf[:2])
		response[2] = 0x80
		_, _ = match.WriteTo(response, addr)
	}()
	matchPort := match.LocalAddr().(*net.UDPAddr).Port
	dial, account := udpDialer(t, time.Second, true)
	result, err := ProbeDNS(context.Background(), func(ctx context.Context, payload []byte) ([]byte, error) {
		return dial.ExchangeUDP(ctx, netip.MustParseAddr("127.0.0.1"), matchPort, "protocol_probe", payload, DNSMaxResponseBytes)
	}, "example.com")
	if err != nil || result.Outcome.State != "open" || result.Rounds != 1 || account.ExportUsage().Requests != 1 || account.ExportUsage().Connections != 0 {
		t.Fatalf("result=%+v requests=%d connections=%d err=%v", result, account.ExportUsage().Requests, account.ExportUsage().Connections, err)
	}

	silent, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()
	silentPort := silent.LocalAddr().(*net.UDPAddr).Port
	slow, slowAccount := udpDialer(t, 50*time.Millisecond, true)
	result, err = ProbeDNS(context.Background(), func(ctx context.Context, payload []byte) ([]byte, error) {
		return slow.ExchangeUDP(ctx, netip.MustParseAddr("127.0.0.1"), silentPort, "protocol_probe", payload, DNSMaxResponseBytes)
	}, "")
	if err != nil || result.Outcome.State != "no_response" || result.Rounds != DNSAttempts || slowAccount.ExportUsage().Requests != int64(DNSAttempts) {
		t.Fatalf("result=%+v requests=%d err=%v", result, slowAccount.ExportUsage().Requests, err)
	}

	closed, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedPort := closed.LocalAddr().(*net.UDPAddr).Port
	if err := closed.Close(); err != nil {
		t.Fatal(err)
	}
	icmpDial, icmpAccount := udpDialer(t, time.Second, true)
	result, err = ProbeDNS(context.Background(), func(ctx context.Context, payload []byte) ([]byte, error) {
		return icmpDial.ExchangeUDP(ctx, netip.MustParseAddr("127.0.0.1"), closedPort, "protocol_probe", payload, DNSMaxResponseBytes)
	}, "")
	if err != nil || result.Outcome.State != "closed" || result.Rounds != 1 || icmpAccount.ExportUsage().Requests != 1 {
		t.Fatalf("result=%+v requests=%d err=%v", result, icmpAccount.ExportUsage().Requests, err)
	}

	deniedConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer deniedConn.Close()
	deniedPort := deniedConn.LocalAddr().(*net.UDPAddr).Port
	deniedDial, deniedAccount := udpDialer(t, 50*time.Millisecond, false)
	result, err = ProbeDNS(context.Background(), func(ctx context.Context, payload []byte) ([]byte, error) {
		return deniedDial.ExchangeUDP(ctx, netip.MustParseAddr("127.0.0.1"), deniedPort, "protocol_probe", payload, DNSMaxResponseBytes)
	}, "example.com")
	if err != nil || result.Outcome.State != "not_scanned" || result.Rounds != 0 || deniedAccount.ExportUsage().Requests != 0 {
		t.Fatalf("result=%+v requests=%d err=%v", result, deniedAccount.ExportUsage().Requests, err)
	}
	_ = deniedConn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	buf := make([]byte, 16)
	if _, _, readErr := deniedConn.ReadFrom(buf); readErr == nil {
		t.Fatal("authorization denial still sent a datagram")
	}
}

type staticAuth struct{ err error }

func (a staticAuth) Authorize(context.Context, netip.Addr, int, string, string) error { return a.err }

func udpDialer(t *testing.T, timeout time.Duration, allow bool) (probesdk.Dialer, *scope.Account) {
	t.Helper()
	account := scope.NewAccount(scope.Budget{
		MaxTargets: 4, MaxAddresses: 4, MaxConnections: 10, MaxRequests: 10,
		MaxConcurrency: 2, MaxRatePerSecond: 1000, MaxRuntime: time.Minute, MaxEvidenceBytes: 1 << 20,
	}, time.Now())
	var authErr error
	if !allow {
		authErr = errors.New("denied")
	}
	return probesdk.Dialer{Auth: staticAuth{err: authErr}, Budget: account, Timeout: timeout, Now: time.Now}, account
}
