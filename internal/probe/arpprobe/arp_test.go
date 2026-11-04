package arpprobe

import (
	"net"
	"net/netip"
	"testing"
)

func TestSelectPrefixSkipsLoopbackAndOffLinkAddresses(t *testing.T) {
	prefixes := []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("192.0.2.0/24")}
	if _, ok := SelectPrefix(netip.MustParseAddr("203.0.113.10"), prefixes); ok {
		t.Fatal("off-link address was selected")
	}
	if _, ok := SelectPrefix(netip.MustParseAddr("127.0.0.1"), prefixes); ok {
		t.Fatal("loopback address was selected")
	}
	got, ok := SelectPrefix(netip.MustParseAddr("192.0.2.10"), prefixes)
	if !ok || got.String() != "192.0.2.0/24" {
		t.Fatalf("prefix = %s %v", got, ok)
	}
}

func TestReplyMatchesTheTarget(t *testing.T) {
	sender := netip.MustParseAddr("192.0.2.10")
	target := netip.MustParseAddr("192.0.2.20")
	request, err := Request(net.HardwareAddr{0x02, 0, 0, 0, 0, 1}, target, sender)
	if err != nil {
		t.Fatal(err)
	}
	if ReplyMatches(request, sender) {
		t.Fatal("request was treated as a reply")
	}
	reply := append([]byte(nil), request...)
	reply[7] = 2
	senderIP := sender.As4()
	copy(reply[14:18], senderIP[:])
	if !ReplyMatches(reply, sender) {
		t.Fatal("reply did not match the target")
	}
	if ReplyMatches(reply, target) {
		t.Fatal("reply matched the requester")
	}
}
