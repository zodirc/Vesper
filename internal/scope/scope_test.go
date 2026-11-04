package scope

import (
	"context"
	"errors"
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

func TestNormalizeHostnameUsesIDNA(t *testing.T) {
	got, err := NormalizeHostname("München.Example.")
	if err != nil {
		t.Fatal(err)
	}
	puny, err := NormalizeHostname("xn--mnchen-3ya.example")
	if err != nil {
		t.Fatal(err)
	}
	if got != "xn--mnchen-3ya.example" || got != puny {
		t.Fatalf("normalized = %s puny = %s", got, puny)
	}
	plain, err := NormalizeHostname("Example.COM.")
	if err != nil || plain != "example.com" {
		t.Fatalf("ascii = %s err = %v", plain, err)
	}
	if _, err := NormalizeHostname("-bad.example"); err == nil {
		t.Fatal("illegal label was accepted")
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

func TestCancelDuringRateWaitReleasesConnection(t *testing.T) {
	start := time.Now().UTC()
	account := NewAccount(Budget{MaxConnections: 2, MaxRequests: 2, MaxRatePerSecond: 0.2, MaxRuntime: time.Minute}, start)
	if err := account.AcquireConnection(context.Background(), start); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- account.AcquireConnection(ctx, start)
	}()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) && account.ExportUsage().Connections < 2 {
		time.Sleep(time.Millisecond)
	}
	if account.ExportUsage().Connections != 2 {
		t.Fatal("rate wait did not reserve a connection")
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
	if account.ExportUsage().Connections != 1 {
		t.Fatalf("connections = %d", account.ExportUsage().Connections)
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
