package scope

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/zodirc/Vesper/internal/id"
)

func TestCheckRejectsBroadGrantForLoopback(t *testing.T) {
	g := testGrant(t)
	wide, err := ParseSelector("cidr", "0.0.0.0/0")
	if err != nil {
		t.Fatal(err)
	}
	g.Selectors = []Selector{wide}
	d := g.Check(CheckInput{
		IP: netip.MustParseAddr("127.0.0.1"), Port: 80, Transport: "tcp",
		Operation: OpConnect, ObservationPointID: g.ObservationPointIDs[0], Now: g.ValidFrom,
	})
	if d.Allowed || d.Code != "protected_address" {
		t.Fatalf("decision = %+v", d)
	}
}

func TestCheckAllowsExplicitLoopback(t *testing.T) {
	g := testGrant(t)
	d := g.Check(CheckInput{
		IP: netip.MustParseAddr("127.0.0.1"), Port: 80, Transport: "tcp", Operation: OpConnect,
		ObservationPointID: g.ObservationPointIDs[0], Now: g.ValidFrom,
	})
	if !d.Allowed {
		t.Fatalf("decision = %+v", d)
	}
}

func TestCheckHostnameDoesNotAuthorizeResolvedMetadataAddress(t *testing.T) {
	g := testGrant(t)
	host, err := ParseSelector("hostname", "Example.COM.")
	if err != nil {
		t.Fatal(err)
	}
	g.Selectors = []Selector{host}
	pre := g.CheckHostname("example.com", "tcp", OpConnect, 80, g.ObservationPointIDs[0], g.ValidFrom)
	if !pre.Allowed {
		t.Fatalf("hostname decision = %+v", pre)
	}
	d := g.Check(CheckInput{
		IP: netip.MustParseAddr("169.254.169.254"), Hostname: "example.com", ResolvedFromGrant: true,
		Port: 80, Transport: "tcp", Operation: OpConnect, ObservationPointID: g.ObservationPointIDs[0], Now: g.ValidFrom,
	})
	if d.Allowed || d.Code != "protected_address" {
		t.Fatalf("decision = %+v", d)
	}
}

func TestCheckRejectsExpiredAndEmptyObservationPoint(t *testing.T) {
	g := testGrant(t)
	until := g.ValidFrom.Add(time.Minute)
	g.ValidUntil = &until
	d := g.Check(CheckInput{
		IP: netip.MustParseAddr("127.0.0.1"), Port: 80, Transport: "tcp", Operation: OpConnect,
		ObservationPointID: g.ObservationPointIDs[0], Now: until,
	})
	if d.Code != "grant_expired" {
		t.Fatalf("code = %s", d.Code)
	}
	g.ValidUntil = nil
	g.ObservationPointIDs = nil
	d = g.Check(CheckInput{
		IP: netip.MustParseAddr("127.0.0.1"), Port: 80, Transport: "tcp", Operation: OpConnect, Now: g.ValidFrom,
	})
	if d.Code != "observation_point_denied" {
		t.Fatalf("code = %s", d.Code)
	}
}

func TestPublicResolutionOfAuthorizedHostnameIsAllowed(t *testing.T) {
	g := testGrant(t)
	host, err := ParseSelector("hostname", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	g.Selectors = []Selector{host}
	d := g.Check(CheckInput{
		IP: netip.MustParseAddr("93.184.216.34"), Hostname: "example.com", ResolvedFromGrant: true,
		Port: 80, Transport: "tcp", Operation: OpConnect, ObservationPointID: g.ObservationPointIDs[0], Now: g.ValidFrom,
	})
	if !d.Allowed {
		t.Fatalf("decision = %+v", d)
	}
}

func TestNarrowUsesStricterCeiling(t *testing.T) {
	out := Narrow(
		Budget{MaxConnections: 10, MaxRequests: 2, MaxRatePerSecond: 5, MaxRuntime: time.Second, MaxTargets: 4, MaxAddresses: 4, MaxConcurrency: 2, MaxEvidenceBytes: 100},
		Budget{MaxConnections: 3, MaxRequests: 8, MaxRatePerSecond: 1, MaxRuntime: time.Minute, MaxTargets: 9, MaxAddresses: 1, MaxConcurrency: 8, MaxEvidenceBytes: 50},
	)
	if out.MaxConnections != 3 || out.MaxRequests != 2 || out.MaxRatePerSecond != 1 || out.MaxRuntime != time.Second || out.MaxEvidenceBytes != 50 {
		t.Fatalf("budget = %+v", out)
	}
}

func TestAcquireConnectionStopsAtCeiling(t *testing.T) {
	account := NewAccount(Budget{MaxConnections: 1, MaxRequests: 1, MaxRatePerSecond: 1000, MaxRuntime: time.Minute}, time.Now().UTC())
	if err := account.AcquireConnection(context.Background(), time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	err := account.AcquireConnection(context.Background(), time.Now().UTC())
	if err == nil {
		t.Fatal("expected budget error")
	}
}

func testGrant(t *testing.T) Grant {
	t.Helper()
	sel, err := ParseSelector("ip", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	return Grant{
		ID: id.MustNew(), Name: "lab", SubjectType: "user", Selectors: []Selector{sel},
		AllowedTransports: []string{"tcp"}, Ports: []PortRange{{Start: 80, End: 80}},
		AllowedOperations:   []string{OpDiscovery, OpConnect, OpProtocolProbe},
		ObservationPointIDs: []id.ID{id.MustNew()},
		ValidFrom:           time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC),
		MaxTargets:          10, MaxAddresses: 10, MaxConnections: 100, MaxRequests: 100, MaxConcurrency: 4,
		MaxRatePerSecond: 100, MaxRuntime: time.Minute, MaxEvidenceBytes: 1 << 20, Status: StatusActive,
		CreatedAt: time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC),
	}
}
