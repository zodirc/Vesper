package icmpprobe

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

func TestClassifyReplyMatchesTheEcho(t *testing.T) {
	reply := mustMessage(t, ipv4.ICMPTypeEchoReply, &icmp.Echo{ID: 7, Seq: 1, Data: []byte("vesper")})
	if got := ClassifyReply(netip.MustParseAddr("203.0.113.10"), 7, 1, reply); got != "reachable" {
		t.Fatalf("reply = %s", got)
	}
	other := mustMessage(t, ipv4.ICMPTypeEchoReply, &icmp.Echo{ID: 8, Seq: 1, Data: []byte("vesper")})
	if got := ClassifyReply(netip.MustParseAddr("203.0.113.10"), 7, 1, other); got != "ignore" {
		t.Fatalf("other = %s", got)
	}
	unreachable := mustMessage(t, ipv4.ICMPTypeDestinationUnreachable, &icmp.DstUnreach{Data: []byte("vesper")})
	if got := ClassifyReply(netip.MustParseAddr("203.0.113.10"), 7, 1, unreachable); got != "unreachable" {
		t.Fatalf("unreachable = %s", got)
	}
	exceeded := mustMessage(t, ipv6.ICMPTypeTimeExceeded, &icmp.TimeExceeded{Data: []byte("vesper")})
	if got := ClassifyReply(netip.MustParseAddr("2001:db8::1"), 7, 1, exceeded); got != "unreachable" {
		t.Fatalf("exceeded = %s", got)
	}
}

func TestEchoLoopbackDoesNotReportPermissionAsNoResponse(t *testing.T) {
	state, err := Echo(context.Background(), netip.MustParseAddr("127.0.0.1"), 200*time.Millisecond, nil)
	if err != nil {
		t.Fatal(err)
	}
	switch state {
	case "reachable", "unsupported":
	default:
		t.Fatalf("state = %s", state)
	}
}

func mustMessage(t *testing.T, kind icmp.Type, body icmp.MessageBody) []byte {
	t.Helper()
	packet, err := (&icmp.Message{Type: kind, Code: 0, Body: body}).Marshal(nil)
	if err != nil {
		t.Fatal(err)
	}
	return packet
}
