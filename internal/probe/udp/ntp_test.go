package udp

import (
	"bytes"
	"context"
	"testing"

	"github.com/zodirc/Vesper/pkg/probesdk"
)

func TestNTPRequestIsAClientPacket(t *testing.T) {
	raw := NTPRequest()
	if len(raw) != NTPPacketBytes || raw[0] != 0x23 {
		t.Fatalf("request = %x", raw)
	}
	for _, b := range raw[1:] {
		if b != 0 {
			t.Fatalf("request = %x", raw)
		}
	}
	if ProbeForPort(NTPPort) != NTPName || ProbeForPort(DNSPort) != DNSName || ProbeForPort(161) != "" {
		t.Fatalf("123 = %s 53 = %s 161 = %s", ProbeForPort(NTPPort), ProbeForPort(DNSPort), ProbeForPort(161))
	}
	if ResponseLimit(NTPName) != NTPPacketBytes || ResponseLimit("snmp") != 0 {
		t.Fatalf("limit = %d", ResponseLimit(NTPName))
	}
}

func TestNTPMatchesOnlyAServerPacket(t *testing.T) {
	server := make([]byte, NTPPacketBytes)
	server[0] = 0x24
	server[1] = 2
	got, sent := exchangeNTP(t, server, nil)
	if got.Outcome.State != "open" || got.Rounds != 1 || got.Probe != NTPName || got.Version != NTPVersion || !bytes.Equal(sent, NTPRequest()) {
		t.Fatalf("server = %+v sent = %x", got, sent)
	}
	if !ntpMatches(server) {
		t.Fatal("version 4 server was rejected")
	}
	v3 := append([]byte(nil), server...)
	v3[0] = 0x1c
	if !ntpMatches(v3) {
		t.Fatal("version 3 server was rejected")
	}
	for _, first := range []byte{0x23, 0x17, 0x0e} {
		other := append([]byte(nil), server...)
		other[0] = first
		if ntpMatches(other) {
			t.Fatalf("mode %x matched", first)
		}
	}
	if ntpMatches(server[:47]) {
		t.Fatal("short packet matched")
	}
}

func TestNTPTimeoutRetriesAndICMPCloses(t *testing.T) {
	calls := 0
	result, err := ProbeNTP(context.Background(), func(context.Context, []byte) ([]byte, error) {
		calls++
		return nil, &probesdk.Error{Class: probesdk.ClassTimeout, Message: "timeout"}
	})
	if err != nil || calls != NTPAttempts || result.Outcome.State != "no_response" || result.Rounds != NTPAttempts {
		t.Fatalf("timeout = %+v calls = %d err = %v", result.Outcome, calls, err)
	}
	calls = 0
	result, err = ProbeNTP(context.Background(), func(context.Context, []byte) ([]byte, error) {
		calls++
		return nil, &probesdk.Error{Class: probesdk.ClassICMPUnreachable, Message: "icmp"}
	})
	if err != nil || calls != 1 || result.Outcome.State != "closed" || result.Rounds != 1 {
		t.Fatalf("icmp = %+v calls = %d err = %v", result.Outcome, calls, err)
	}
}

func exchangeNTP(t *testing.T, response []byte, exchangeErr error) (Result, []byte) {
	t.Helper()
	var sent []byte
	result, err := Execute(context.Background(), NTPName, func(_ context.Context, payload []byte) ([]byte, error) {
		sent = append([]byte(nil), payload...)
		if exchangeErr != nil {
			return nil, exchangeErr
		}
		return response, nil
	}, "ignored.example")
	if err != nil {
		t.Fatal(err)
	}
	if result.QName != "" || result.QType != 0 {
		t.Fatalf("dns fields = %q %d", result.QName, result.QType)
	}
	return result, sent
}
