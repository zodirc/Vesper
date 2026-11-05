package control

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/zodirc/Vesper/internal/assess"
	"github.com/zodirc/Vesper/internal/id"
	"github.com/zodirc/Vesper/internal/identity"
	"github.com/zodirc/Vesper/internal/scope"
	"github.com/zodirc/Vesper/internal/task"
)

func TestSupplementalCollectionRefreshesStaleEvidenceAndSkipsUncoveredTargets(t *testing.T) {
	now := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	svc, err := New(t.TempDir(), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	actor := id.MustNew()
	grant, err := svc.CreateGrant(GrantInput{
		Name: "lab", SubjectType: "user",
		Selectors:  []SelectorInput{{Kind: "ip", Value: "203.0.113.10"}},
		Transports: []string{"tcp"}, Ports: []scope.PortRange{{Start: 80, End: 80}},
		Operations:          []string{scope.OpConnect, scope.OpProtocolProbe, scope.OpConfigCheck},
		ObservationPointIDs: []id.ID{svc.ObservationPointID()}, ValidFrom: now.Add(-time.Hour),
		MaxTargets: 4, MaxAddresses: 4, MaxConnections: 20, MaxRequests: 20, MaxConcurrency: 2,
		MaxRatePerSecond: 10, MaxRuntimeSeconds: 60, MaxEvidenceBytes: 1 << 20,
	}, actor)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.ApproveGrant(grant.ID, actor); err != nil {
		t.Fatal(err)
	}
	endpoint := svc.catalog.ObserveEndpoint(netip.MustParseAddr("203.0.113.10"), "tcp", 80, "open", now.Add(-2*time.Hour))
	svc.mu.Lock()
	svc.appendObservation(Observation{
		EndpointID: &endpoint.ID, Type: "protocol_response", SubjectKey: "tcp:80",
		ObservedAt: now.Add(-2 * time.Hour), CollectedAt: now.Add(-2 * time.Hour), ResultStatus: "observed",
		Value: map[string]any{"protocol": "http"},
	})
	svc.hypotheses = append(svc.hypotheses, identity.Hypothesis{ID: id.MustNew(), EndpointID: endpoint.ID, EvaluatedAt: now})
	before := len(svc.observations)
	svc.mu.Unlock()
	if err := svc.AddStatement(testStatement()); err != nil {
		t.Fatal(err)
	}
	snapshot := svc.Snapshots()[0]
	result, err := svc.Reassess(context.Background(), snapshot.ID, ReassessOptions{MaxAge: time.Hour, GrantID: grant.ID})
	if err != nil {
		t.Fatal(err)
	}
	if result.Supplemental != 1 || result.Uncovered != 0 {
		t.Fatalf("result = %+v", result)
	}
	runs := supplementalRuns(svc)
	if len(runs) != 1 || runs[0].TriggerType != "supplemental" || runs[0].Name != "supplemental:tcp:203.0.113.10:80" {
		t.Fatalf("runs = %+v", runs)
	}
	svc.mu.Lock()
	if len(svc.observations) != before {
		t.Fatalf("observations = %d, want %d", len(svc.observations), before)
	}
	svc.mu.Unlock()
	again, err := svc.Reassess(context.Background(), snapshot.ID, ReassessOptions{MaxAge: time.Hour, GrantID: grant.ID})
	if err != nil {
		t.Fatal(err)
	}
	if again.Supplemental != 0 || len(supplementalRuns(svc)) != 1 {
		t.Fatalf("repeat = %+v runs = %d", again, len(supplementalRuns(svc)))
	}
}

func TestSupplementalCollectionRequiresACoveringGrant(t *testing.T) {
	now := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	svc, err := New(t.TempDir(), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	endpoint := svc.catalog.ObserveEndpoint(netip.MustParseAddr("203.0.113.10"), "tcp", 80, "open", now.Add(-2*time.Hour))
	svc.mu.Lock()
	svc.appendObservation(Observation{
		EndpointID: &endpoint.ID, Type: "protocol_response", SubjectKey: "tcp:80",
		ObservedAt: now.Add(-2 * time.Hour), CollectedAt: now.Add(-2 * time.Hour), ResultStatus: "observed",
	})
	svc.hypotheses = append(svc.hypotheses, identity.Hypothesis{ID: id.MustNew(), EndpointID: endpoint.ID, EvaluatedAt: now})
	svc.mu.Unlock()
	if err := svc.AddStatement(testStatement()); err != nil {
		t.Fatal(err)
	}
	result, err := svc.Reassess(context.Background(), svc.Snapshots()[0].ID, ReassessOptions{MaxAge: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if result.Supplemental != 0 || result.Uncovered != 1 || len(supplementalRuns(svc)) != 0 {
		t.Fatalf("result = %+v", result)
	}
}

func TestFreshAndBrokenEvidence(t *testing.T) {
	now := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	svc, err := New(t.TempDir(), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	actor := id.MustNew()
	grant := approveLabGrant(t, svc, actor, now)
	endpoint := svc.catalog.ObserveEndpoint(netip.MustParseAddr("203.0.113.10"), "tcp", 80, "open", now)
	evidenceID := id.MustNew()
	svc.mu.Lock()
	svc.appendObservation(Observation{
		EndpointID: &endpoint.ID, Type: "protocol_response", SubjectKey: "tcp:80",
		ObservedAt: now, CollectedAt: now, ResultStatus: "observed", EvidenceIDs: []id.ID{evidenceID},
	})
	svc.evidenceRows = append(svc.evidenceRows, EvidenceRecord{ID: evidenceID, IntegrityStatus: "verified"})
	svc.hypotheses = append(svc.hypotheses, identity.Hypothesis{ID: id.MustNew(), EndpointID: endpoint.ID, EvaluatedAt: now})
	svc.mu.Unlock()
	if err := svc.AddStatement(testStatement()); err != nil {
		t.Fatal(err)
	}
	snapshot := svc.Snapshots()[0].ID
	fresh, err := svc.Reassess(context.Background(), snapshot, ReassessOptions{MaxAge: time.Hour, GrantID: grant})
	if err != nil {
		t.Fatal(err)
	}
	if fresh.Supplemental != 0 || fresh.Uncovered != 0 {
		t.Fatalf("fresh = %+v", fresh)
	}
	svc.mu.Lock()
	svc.evidenceRows[0].IntegrityStatus = "mismatch"
	svc.mu.Unlock()
	broken, err := svc.Reassess(context.Background(), snapshot, ReassessOptions{MaxAge: time.Hour, GrantID: grant})
	if err != nil {
		t.Fatal(err)
	}
	if broken.Supplemental != 1 {
		t.Fatalf("broken = %+v", broken)
	}
}

func TestAcceptedFindingDoesNotCreateSupplementalCollection(t *testing.T) {
	now := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	svc, err := New(t.TempDir(), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	actor := id.MustNew()
	grant := approveLabGrant(t, svc, actor, now)
	endpoint := svc.catalog.ObserveEndpoint(netip.MustParseAddr("203.0.113.10"), "tcp", 80, "open", now.Add(-2*time.Hour))
	svc.mu.Lock()
	svc.appendObservation(Observation{
		EndpointID: &endpoint.ID, Type: "protocol_response", SubjectKey: "tcp:80",
		ObservedAt: now.Add(-2 * time.Hour), CollectedAt: now.Add(-2 * time.Hour), ResultStatus: "observed",
	})
	findingID := id.MustNew()
	svc.findings[endpoint.ID.String()+"|CVE"] = &Finding{
		ID: findingID, FindingKey: endpoint.ID.String() + "|CVE", EndpointID: endpoint.ID, Status: "accepted", VulnerabilityID: "CVE-2026-9000",
	}
	svc.mu.Unlock()
	if err := svc.AddStatement(testStatement()); err != nil {
		t.Fatal(err)
	}
	result, err := svc.Reassess(context.Background(), svc.Snapshots()[0].ID, ReassessOptions{MaxAge: time.Hour, GrantID: grant})
	if err != nil {
		t.Fatal(err)
	}
	if result.Supplemental != 0 || result.Uncovered != 0 {
		t.Fatalf("result = %+v", result)
	}
}

func TestSupplementalHostCollectionUsesLocalInventory(t *testing.T) {
	now := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	svc, err := New(t.TempDir(), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	actor := id.MustNew()
	grant := approveLabGrant(t, svc, actor, now)
	assetID := id.MustNew()
	svc.mu.Lock()
	svc.appendObservation(Observation{
		AssetID: assetID, Type: "host_inventory", SubjectKey: "local:collect_packages", SourceKind: "local_collector",
		ObservedAt: now.Add(-2 * time.Hour), CollectedAt: now.Add(-2 * time.Hour), ResultStatus: "observed",
		Value: map[string]any{"collection_status": "collected"},
	})
	svc.findings[assetID.String()+"|pkg"] = &Finding{
		ID: id.MustNew(), FindingKey: assetID.String() + "|pkg", FindingType: "vulnerability", AssetID: assetID,
		Status: "confirmed", VulnerabilityID: "CVE-2026-9001",
	}
	svc.mu.Unlock()
	if err := svc.AddStatement(testStatement()); err != nil {
		t.Fatal(err)
	}
	result, err := svc.Reassess(context.Background(), svc.Snapshots()[0].ID, ReassessOptions{MaxAge: time.Hour, GrantID: grant})
	if err != nil {
		t.Fatal(err)
	}
	if result.Supplemental != 1 {
		t.Fatalf("result = %+v", result)
	}
	runs, units, _ := svc.tasks.Export()
	var found bool
	for _, run := range runs {
		if run.TriggerType != "supplemental" {
			continue
		}
		for _, unit := range units {
			if unit.ScanRunID == run.ID && unit.UnitType == "host_collect" && strings.Contains(string(unit.Input), "collect_packages") && strings.Contains(string(unit.Input), "collect_os_info") {
				found = true
			}
			if unit.ScanRunID == run.ID && unit.UnitType != "host_collect" {
				t.Fatalf("unit = %+v", unit)
			}
		}
	}
	if !found {
		t.Fatal("host collection unit was not created")
	}
}

func TestReassessmentScheduleSuppliesTheEvidenceAge(t *testing.T) {
	now := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	svc, err := New(t.TempDir(), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	actor := id.MustNew()
	grant := approveLabGrant(t, svc, actor, now)
	later := now.Add(24 * time.Hour)
	if _, err := svc.CreateSchedule(context.Background(), ScheduleInput{
		Name: "rejudge", TriggerType: "reassessment", IntervalSeconds: 3600, NextRunAt: &later, GrantID: grant,
	}); err != nil {
		t.Fatal(err)
	}
	endpoint := svc.catalog.ObserveEndpoint(netip.MustParseAddr("203.0.113.10"), "tcp", 80, "open", now.Add(-2*time.Hour))
	svc.mu.Lock()
	svc.appendObservation(Observation{
		EndpointID: &endpoint.ID, Type: "protocol_response", SubjectKey: "tcp:80",
		ObservedAt: now.Add(-2 * time.Hour), CollectedAt: now.Add(-2 * time.Hour), ResultStatus: "observed",
	})
	svc.hypotheses = append(svc.hypotheses, identity.Hypothesis{ID: id.MustNew(), EndpointID: endpoint.ID, EvaluatedAt: now})
	svc.mu.Unlock()
	if err := svc.AddStatement(testStatement()); err != nil {
		t.Fatal(err)
	}
	result, err := svc.Reassess(context.Background(), svc.Snapshots()[0].ID, ReassessOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Supplemental != 1 {
		t.Fatalf("result = %+v", result)
	}
}

func approveLabGrant(t *testing.T, svc *Service, actor id.ID, now time.Time) id.ID {
	t.Helper()
	grant, err := svc.CreateGrant(GrantInput{
		Name: "lab", SubjectType: "user",
		Selectors:  []SelectorInput{{Kind: "ip", Value: "203.0.113.10"}},
		Transports: []string{"tcp"}, Ports: []scope.PortRange{{Start: 80, End: 80}},
		Operations:          []string{scope.OpConnect, scope.OpProtocolProbe, scope.OpConfigCheck},
		ObservationPointIDs: []id.ID{svc.ObservationPointID()}, ValidFrom: now.Add(-time.Hour),
		MaxTargets: 4, MaxAddresses: 4, MaxConnections: 20, MaxRequests: 20, MaxConcurrency: 2,
		MaxRatePerSecond: 10, MaxRuntimeSeconds: 60, MaxEvidenceBytes: 1 << 20,
	}, actor)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.ApproveGrant(grant.ID, actor); err != nil {
		t.Fatal(err)
	}
	return grant.ID
}

func supplementalRuns(svc *Service) []task.Run {
	runs, _, _ := svc.tasks.Export()
	var out []task.Run
	for _, run := range runs {
		if run.TriggerType == "supplemental" {
			out = append(out, run)
		}
	}
	return out
}

func testStatement() assess.Statement {
	return assess.Statement{VulnerabilityID: "CVE-2026-9000", Ecosystem: "generic", ProductKey: "generic:none"}
}
