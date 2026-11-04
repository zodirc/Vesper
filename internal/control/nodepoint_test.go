package control

import (
	"context"
	"encoding/json"
	"runtime"
	"testing"
	"time"

	"github.com/zodirc/Vesper/internal/activedetect"
	"github.com/zodirc/Vesper/internal/id"
	"github.com/zodirc/Vesper/internal/scope"
	"github.com/zodirc/Vesper/internal/task"
)

func TestCapabilitySnapshotIdentityFollowsContent(t *testing.T) {
	previousICMP, previousARP := icmpAvailability, arpAvailability
	t.Cleanup(func() {
		icmpAvailability = previousICMP
		arpAvailability = previousARP
	})
	icmpAvailability = func() string { return "permission_denied" }
	arpAvailability = func() string { return "not_implemented" }
	worker := task.Worker{ID: id.MustNew(), Capabilities: map[string]struct{}{"tcp_connect": {}, "udp_dns": {}}}
	now := time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC)
	point := captureObservationPoint(id.MustNew(), worker, now)
	if point.Platform != runtime.GOOS || point.Architecture != runtime.GOARCH {
		t.Fatalf("platform = %s/%s", point.Platform, point.Architecture)
	}
	if point.Privileges["icmp_echo"] != "permission_denied" || point.Privileges["arp"] != "not_implemented" {
		t.Fatalf("privileges = %+v", point.Privileges)
	}
	if point.NetworkIsolation["active_detection"] != activedetect.Availability() {
		t.Fatalf("isolation = %+v", point.NetworkIsolation)
	}
	if point.Capabilities["tcp_connect"] != "available" || point.ProbeCompatibility["udp_dns"] != "available" {
		t.Fatalf("capabilities = %+v compatibility = %+v", point.Capabilities, point.ProbeCompatibility)
	}
	later := captureObservationPoint(point.ID, worker, now.Add(time.Hour))
	if later.CapabilitySnapshotID != point.CapabilitySnapshotID || later.CapabilitySnapshotID.IsZero() {
		t.Fatalf("snapshot = %s later = %s", point.CapabilitySnapshotID, later.CapabilitySnapshotID)
	}
	if len(point.Interfaces) == 0 {
		t.Fatal("interfaces are empty")
	}
}

func TestCreatedScanKeepsObservationEnvironment(t *testing.T) {
	now := time.Date(2026, 11, 4, 8, 0, 0, 0, time.UTC)
	svc, err := New(t.TempDir(), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	actor := id.MustNew()
	grant, err := svc.CreateGrant(GrantInput{
		Name: "local", SubjectType: "user",
		Selectors:  []SelectorInput{{Kind: "ip", Value: "127.0.0.1"}},
		Transports: []string{"tcp"}, Ports: []scope.PortRange{{Start: 1, End: 1}},
		Operations:          []string{scope.OpDiscovery, scope.OpConnect},
		ObservationPointIDs: []id.ID{svc.ObservationPointID()}, ValidFrom: now.Add(-time.Minute),
		MaxTargets: 2, MaxAddresses: 2, MaxConnections: 2, MaxRequests: 2, MaxConcurrency: 1,
		MaxRatePerSecond: 1000, MaxRuntimeSeconds: 60, MaxEvidenceBytes: 1000,
	}, actor)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.ApproveGrant(grant.ID, actor); err != nil {
		t.Fatal(err)
	}
	run, err := svc.CreateScan(context.Background(), ScanInput{Name: "frozen", Target: "127.0.0.1", Type: "ip", Ports: []int{1}, GrantID: grant.ID})
	if err != nil {
		t.Fatal(err)
	}
	stored := environmentFromPlan(t, run.Plan)
	current := svc.currentEnvironment(now)
	if stored.ObservationPointID != svc.ObservationPointID().String() || stored.CapabilitySnapshotID != current.CapabilitySnapshotID {
		t.Fatalf("stored = %+v current = %+v", stored, current)
	}
	if len(stored.Interfaces) == 0 || stored.Interfaces[0].Name == "" {
		t.Fatalf("interfaces = %+v", stored.Interfaces)
	}
	if !jsonEqual(stored.Interfaces, current.Interfaces) {
		t.Fatalf("stored interfaces = %+v current = %+v", stored.Interfaces, current.Interfaces)
	}
}

func environmentFromPlan(t *testing.T, raw []byte) observationEnvironment {
	t.Helper()
	var plan planBody
	if err := json.Unmarshal(raw, &plan); err != nil {
		t.Fatal(err)
	}
	if plan.Environment == nil || len(plan.Allowed) == 0 {
		t.Fatalf("plan = %s", raw)
	}
	return *plan.Environment
}

func jsonEqual(left, right any) bool {
	first, err := json.Marshal(left)
	if err != nil {
		return false
	}
	second, err := json.Marshal(right)
	if err != nil {
		return false
	}
	return string(first) == string(second)
}

func TestInterfaceSnapshotIncludesLoopback(t *testing.T) {
	var sawLoopback bool
	for _, iface := range localInterfaces() {
		if iface.Loopback && iface.Name != "" {
			sawLoopback = true
		}
	}
	if !sawLoopback {
		t.Fatal("loopback interface was not recorded")
	}
}
