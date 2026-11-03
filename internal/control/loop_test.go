package control

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/zodirc/Vesper/internal/assess"
	"github.com/zodirc/Vesper/internal/id"
	"github.com/zodirc/Vesper/internal/scope"
	"github.com/zodirc/Vesper/internal/task"
	"github.com/zodirc/Vesper/pkg/probesdk"
)

func TestScanLoopIdentifiesHTTPAndMergesFinding(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				_, _ = c.Read(buf)
				_, _ = io.WriteString(c, "HTTP/1.0 200 OK\r\nServer: nginx/1.24.0\r\nContent-Length: 2\r\n\r\nok")
			}(conn)
		}
	}()
	port := listener.Addr().(*net.TCPAddr).Port
	now := time.Date(2026, 11, 3, 1, 0, 0, 0, time.UTC)
	svc, err := New(t.TempDir(), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	actor := id.MustNew()
	grant, err := svc.CreateGrant(GrantInput{
		Name: "lab", SubjectType: "user",
		Selectors:  []SelectorInput{{Kind: "ip", Value: "127.0.0.1"}},
		Transports: []string{"tcp"}, Ports: []scope.PortRange{{Start: port, End: port}},
		Operations:          []string{scope.OpDiscovery, scope.OpConnect, scope.OpProtocolProbe, scope.OpConfigCheck},
		ObservationPointIDs: []id.ID{svc.ObservationPointID()}, ValidFrom: now.Add(-time.Minute),
		MaxTargets: 4, MaxAddresses: 4, MaxConnections: 50, MaxRequests: 50, MaxConcurrency: 4,
		MaxRatePerSecond: 1000, MaxRuntimeSeconds: 60, MaxEvidenceBytes: 1 << 20,
	}, actor)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.ApproveGrant(grant.ID, actor); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.AddProduct("generic", "nginx", "generic:nginx", "nginx"); err != nil {
		t.Fatal(err)
	}
	if err := svc.AddStatement(assess.Statement{
		VulnerabilityID: "CVE-2026-0001", Ecosystem: "generic", ProductKey: "generic:nginx", Severity: "high",
		Ranges: []assess.Range{{Ecosystem: "generic", Start: "1.0.0", StartInclusive: true, End: "1.25.0", EndInclusive: true}},
	}); err != nil {
		t.Fatal(err)
	}
	run, err := svc.CreateScan(context.Background(), ScanInput{Name: "local", Target: "127.0.0.1", Type: "ip", Ports: []int{port}, GrantID: grant.ID})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		worked, err := svc.ExecuteAvailable(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if !worked {
			break
		}
	}
	got, err := svc.Run(run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "completed" && got.Status != "completed_with_errors" {
		t.Fatalf("status = %s failure=%s", got.Status, got.FailureSummary)
	}
	if got.TriggerType != "manual" || !strings.Contains(string(got.EffectiveBudget), `"max_connections":50`) {
		t.Fatalf("trigger = %s budget = %s", got.TriggerType, got.EffectiveBudget)
	}
	if got.IntelSnapshotID.IsZero() {
		t.Fatal("scan run did not freeze an intel snapshot")
	}
	var sawOpen bool
	for _, item := range svc.Observations(run.ID) {
		if item.Type == "port_state" && item.Value["state"] == "open" {
			sawOpen = true
		}
	}
	if !sawOpen {
		t.Fatal("expected an open port observation")
	}
	var sawHTTP bool
	for _, item := range svc.Hypotheses() {
		if item.ServiceType == "http" && item.RawProductName == "nginx" && item.RawVersion == "1.24.0" && item.ProductIdentityID != nil {
			sawHTTP = true
		}
	}
	if !sawHTTP {
		t.Fatalf("hypotheses = %+v", svc.Hypotheses())
	}
	findings := svc.Findings()
	if len(findings) != 1 || findings[0].VulnerabilityID != "CVE-2026-0001" || findings[0].Status != "open" || findings[0].Severity != "high" {
		t.Fatalf("findings = %+v", findings)
	}
	if len(svc.occurrences) != 1 || len(svc.occurrences[0].EvidenceIDs) == 0 || findings[0].LastOccurrenceID != svc.occurrences[0].ID || findings[0].ProductID.IsZero() {
		t.Fatalf("findings = %+v occurrences = %+v", findings, svc.occurrences)
	}
	var sawGrantContent bool
	for _, revision := range svc.revisions {
		if revision.Action == "approve" && strings.Contains(string(revision.Content), `"status":"active"`) && strings.Contains(string(revision.Content), `"value":"127.0.0.1"`) {
			sawGrantContent = true
		}
	}
	if !sawGrantContent {
		t.Fatalf("revisions = %+v", svc.revisions)
	}
	for _, item := range svc.Observations(run.ID) {
		if item.SourceIdentity != svc.worker.ID.String() {
			t.Fatalf("source identity = %s", item.SourceIdentity)
		}
	}
	_, units, attempts := svc.tasks.Export()
	var sawPortUsage bool
	for _, unit := range units {
		if unit.UnitType != "port_scan" || unit.Status != task.UnitSucceeded {
			continue
		}
		var summary struct {
			Observations int `json:"observations"`
		}
		if err := json.Unmarshal(unit.ResultSummary, &summary); err != nil || summary.Observations < 1 {
			t.Fatalf("result summary = %s", unit.ResultSummary)
		}
		for _, attempt := range attempts {
			if attempt.ScanUnitID != unit.ID || attempt.Status != task.AttemptSucceeded || attempt.ResultDigest == "" {
				continue
			}
			var usage struct {
				Connections int64 `json:"connections"`
			}
			if err := json.Unmarshal(attempt.ResourceUsage, &usage); err != nil || usage.Connections < 1 {
				t.Fatalf("usage = %s err = %v", attempt.ResourceUsage, err)
			}
			sawPortUsage = true
		}
	}
	if !sawPortUsage {
		t.Fatal("port scan did not record measured attempt usage")
	}
	if raw, err := os.ReadFile("/etc/machine-id"); err == nil && strings.TrimSpace(string(raw)) != "" {
		var linked bool
		for _, item := range svc.Observations(run.ID) {
			if item.Type == "host_inventory" && !item.AssetID.IsZero() {
				linked = true
			}
		}
		if !linked {
			t.Fatal("host inventory was not linked to the machine asset")
		}
		var sawRule bool
		for _, item := range svc.detections {
			if item.VulnerabilityID == "host_identity_present" && !item.RuleID.IsZero() && item.RuleVersion == "builtin-1" && item.Severity == "low" && strings.Contains(string(item.Matched), `"pass_field":"name"`) {
				sawRule = true
			}
		}
		if !sawRule {
			t.Fatalf("detections = %+v", svc.detections)
		}
	}
	var confirmed bool
	for _, item := range svc.detections {
		if item.VulnerabilityID == "CVE-2026-0001" && item.ResultStatus == "confirmed" && len(item.EvidenceIDs) > 0 {
			confirmed = true
		}
	}
	if !confirmed {
		t.Fatalf("detections = %+v", svc.detections)
	}
	beforeObservations := svc.Observations(run.ID)
	beforeDetections := append([]Detection(nil), svc.detections...)
	added, err := svc.Reassess(context.Background(), got.IntelSnapshotID)
	if err != nil {
		t.Fatal(err)
	}
	if added < 1 {
		t.Fatalf("reassess added %d detections", added)
	}
	afterObservations := svc.Observations(run.ID)
	if len(afterObservations) != len(beforeObservations) {
		t.Fatalf("observations changed from %d to %d", len(beforeObservations), len(afterObservations))
	}
	for _, previous := range beforeDetections {
		found := false
		for _, item := range svc.detections {
			if item.ID == previous.ID {
				found = true
			}
		}
		if !found {
			t.Fatalf("reassess dropped detection %s", previous.ID)
		}
	}
	var sawEvidence bool
	for _, row := range svc.evidenceRows {
		if row.EvidenceType == "raw_response" && row.SourceModule == "httpprobe" && row.ContentType == "application/http" && row.ContentEncoding == "identity" && row.Sensitivity == "internal" && row.IntegrityStatus == "verified" && row.StoredAt != nil {
			sawEvidence = true
		}
	}
	if !sawEvidence {
		t.Fatalf("evidence = %+v", svc.evidenceRows)
	}
}

func TestBroadGrantDoesNotScanLoopback(t *testing.T) {
	now := time.Date(2026, 11, 3, 1, 0, 0, 0, time.UTC)
	svc, err := New(t.TempDir(), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	actor := id.MustNew()
	grant, err := svc.CreateGrant(GrantInput{
		Name: "wide", SubjectType: "user",
		Selectors:  []SelectorInput{{Kind: "cidr", Value: "0.0.0.0/0"}},
		Transports: []string{"tcp"}, Ports: []scope.PortRange{{Start: 80, End: 80}},
		Operations: []string{scope.OpConnect}, ObservationPointIDs: []id.ID{svc.ObservationPointID()},
		ValidFrom: now.Add(-time.Minute), MaxTargets: 4, MaxAddresses: 4, MaxConnections: 4,
		MaxRequests: 4, MaxConcurrency: 1, MaxRatePerSecond: 10, MaxRuntimeSeconds: 60, MaxEvidenceBytes: 1000,
	}, actor)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.ApproveGrant(grant.ID, actor); err != nil {
		t.Fatal(err)
	}
	run, err := svc.CreateScan(context.Background(), ScanInput{Target: "127.0.0.1", Type: "ip", Ports: []int{80}, GrantID: grant.ID})
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != "failed" {
		t.Fatalf("status = %s", run.Status)
	}
}

func TestCancelledRunDoesNotClaimQueuedUnit(t *testing.T) {
	now := time.Date(2026, 11, 3, 1, 0, 0, 0, time.UTC)
	svc, err := New(t.TempDir(), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	actor := id.MustNew()
	grant, err := svc.CreateGrant(GrantInput{
		Name: "lab", SubjectType: "user",
		Selectors:  []SelectorInput{{Kind: "ip", Value: "127.0.0.1"}},
		Transports: []string{"tcp"}, Ports: []scope.PortRange{{Start: 9, End: 9}},
		Operations: []string{scope.OpDiscovery, scope.OpConnect}, ObservationPointIDs: []id.ID{svc.ObservationPointID()},
		ValidFrom: now.Add(-time.Minute), MaxTargets: 2, MaxAddresses: 2, MaxConnections: 10,
		MaxRequests: 10, MaxConcurrency: 1, MaxRatePerSecond: 10, MaxRuntimeSeconds: 60, MaxEvidenceBytes: 1000,
	}, actor)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.ApproveGrant(grant.ID, actor); err != nil {
		t.Fatal(err)
	}
	run, err := svc.CreateScan(context.Background(), ScanInput{Target: "127.0.0.1", Type: "ip", Ports: []int{9}, GrantID: grant.ID})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.Cancel(run.ID); err != nil {
		t.Fatal(err)
	}
	worked, err := svc.ExecuteAvailable(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if worked {
		t.Fatal("cancelled run still executed a unit")
	}
	got, err := svc.Run(run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "cancelled" {
		t.Fatalf("status = %s", got.Status)
	}
}

func TestIdempotencyKeyIncludesStage(t *testing.T) {
	now := time.Date(2026, 11, 3, 1, 0, 0, 0, time.UTC)
	svc, err := New(t.TempDir(), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	runID := id.MustNew()
	targetID := id.MustNew()
	if err := svc.tasks.CreateRun(task.Run{ID: runID, TargetIDs: []id.ID{targetID}, ObservationPointIDs: []id.ID{svc.pointID}, CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := svc.tasks.AddUnit(task.Unit{ScanRunID: runID, TargetID: targetID, ObservationPointID: svc.pointID, UnitType: "port_scan", StageKey: "port_scan:a", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := svc.tasks.AddUnit(task.Unit{ScanRunID: runID, TargetID: targetID, ObservationPointID: svc.pointID, UnitType: "port_scan", StageKey: "port_scan:b", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	_, units, err := svc.tasks.Snapshot(runID)
	if err != nil || len(units) != 2 {
		t.Fatalf("units = %+v err=%v", units, err)
	}
	value := map[string]any{"state": "open"}
	first := Observation{ScanRunID: runID, ScanUnitID: units[0].ID, Type: "port_state", SubjectKey: "tcp:203.0.113.5:80", ResultStatus: "observed", Value: value}
	if _, created := svc.appendObservation(first); !created {
		t.Fatal("first observation was not stored")
	}
	second := first
	second.ID = id.ID{}
	second.ScanUnitID = units[1].ID
	if _, created := svc.appendObservation(second); !created {
		t.Fatal("a different stage must be stored again")
	}
	repeat := second
	repeat.ID = id.ID{}
	if _, created := svc.appendObservation(repeat); created {
		t.Fatal("the same stage and content was stored twice")
	}
}

func TestBudgetExhaustionIsNotRetryable(t *testing.T) {
	if retryableExecution(&probesdk.Error{Class: probesdk.ClassBudget, Message: "ceiling"}) {
		t.Fatal("budget exhaustion was treated as retryable")
	}
	if retryableExecution(&probesdk.Error{Class: probesdk.ClassAuthorization, Message: "denied"}) {
		t.Fatal("authorization denial was treated as retryable")
	}
	if !retryableExecution(&probesdk.Error{Class: probesdk.ClassTimeout, Message: "timeout"}) {
		t.Fatal("timeout was treated as fatal")
	}
}

func TestInterruptedHostnamePlanningStaysRecoverable(t *testing.T) {
	now := time.Date(2026, 11, 3, 1, 0, 0, 0, time.UTC)
	svc, err := New(t.TempDir(), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	svc.resolver = func(context.Context, string) (Resolution, error) {
		return Resolution{}, context.Canceled
	}
	actor := id.MustNew()
	grant, err := svc.CreateGrant(GrantInput{
		Name: "names", SubjectType: "user",
		Selectors:  []SelectorInput{{Kind: "hostname", Value: "example.com"}},
		Transports: []string{"tcp"}, Ports: []scope.PortRange{{Start: 80, End: 80}},
		Operations: []string{scope.OpDiscovery, scope.OpConnect}, ObservationPointIDs: []id.ID{svc.ObservationPointID()},
		ValidFrom: now.Add(-time.Minute), MaxTargets: 2, MaxAddresses: 4, MaxConnections: 4,
		MaxRequests: 4, MaxConcurrency: 1, MaxRatePerSecond: 10, MaxRuntimeSeconds: 60, MaxEvidenceBytes: 1000,
	}, actor)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.ApproveGrant(grant.ID, actor); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	run, err := svc.CreateScan(ctx, ScanInput{Target: "example.com", Type: "hostname", Ports: []int{80}, GrantID: grant.ID})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("create scan err = %v", err)
	}
	if run.Status != task.RunPlanning {
		t.Fatalf("status = %s", run.Status)
	}
	svc.resolver = func(context.Context, string) (Resolution, error) {
		return Resolution{}, errors.New("dns unavailable")
	}
	worked, err := svc.ExecuteAvailable(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if worked {
		t.Fatal("dns failure executed a unit")
	}
	got, err := svc.Run(run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != task.RunFailed || got.FailureSummary != "dns unavailable" {
		t.Fatalf("status = %s summary = %s", got.Status, got.FailureSummary)
	}
}

func TestHostnameResolutionIsStoredBeforeScan(t *testing.T) {
	now := time.Date(2026, 11, 3, 1, 0, 0, 0, time.UTC)
	svc, err := New(t.TempDir(), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	svc.resolver = func(context.Context, string) (Resolution, error) {
		return Resolution{CanonicalName: "www.example.com.", Addresses: []netip.Addr{netip.MustParseAddr("203.0.113.10")}}, nil
	}
	actor := id.MustNew()
	grant, err := svc.CreateGrant(GrantInput{
		Name: "names", SubjectType: "user",
		Selectors:  []SelectorInput{{Kind: "hostname", Value: "example.com"}},
		Transports: []string{"tcp"}, Ports: []scope.PortRange{{Start: 80, End: 80}},
		Operations: []string{scope.OpDiscovery, scope.OpConnect}, ObservationPointIDs: []id.ID{svc.ObservationPointID()},
		ValidFrom: now.Add(-time.Minute), MaxTargets: 2, MaxAddresses: 4, MaxConnections: 4,
		MaxRequests: 4, MaxConcurrency: 1, MaxRatePerSecond: 10, MaxRuntimeSeconds: 60, MaxEvidenceBytes: 1000,
	}, actor)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.ApproveGrant(grant.ID, actor); err != nil {
		t.Fatal(err)
	}
	run, err := svc.CreateScan(context.Background(), ScanInput{Target: "example.com", Type: "hostname", Ports: []int{80}, GrantID: grant.ID})
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != task.RunRunning || !strings.Contains(string(run.Plan), "203.0.113.10") {
		t.Fatalf("status = %s plan = %s", run.Status, run.Plan)
	}
	var resolution Observation
	for _, item := range svc.Observations(run.ID) {
		if item.Type == "dns_resolution" {
			resolution = item
		}
	}
	if resolution.Type != "dns_resolution" || resolution.Value["canonical_name"] != "www.example.com." {
		t.Fatalf("resolution = %+v", resolution)
	}
	if _, ok := resolution.Value["ttl_seconds"]; ok {
		t.Fatal("ttl was stored without a resolver value")
	}
	records, ok := resolution.Value["records"].([]map[string]string)
	if !ok || len(records) != 1 || records[0]["type"] != "A" || records[0]["address"] != "203.0.113.10" {
		t.Fatalf("records = %#v", resolution.Value["records"])
	}
}

func TestRevokedGrantIsNotClaimed(t *testing.T) {
	now := time.Date(2026, 11, 3, 1, 0, 0, 0, time.UTC)
	svc, err := New(t.TempDir(), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	actor := id.MustNew()
	grant, err := svc.CreateGrant(GrantInput{
		Name: "lab", SubjectType: "user",
		Selectors:  []SelectorInput{{Kind: "ip", Value: "203.0.113.5"}},
		Transports: []string{"tcp"}, Ports: []scope.PortRange{{Start: 9, End: 9}},
		Operations: []string{scope.OpDiscovery, scope.OpConnect}, ObservationPointIDs: []id.ID{svc.ObservationPointID()},
		ValidFrom: now.Add(-time.Minute), MaxTargets: 2, MaxAddresses: 2, MaxConnections: 10,
		MaxRequests: 10, MaxConcurrency: 1, MaxRatePerSecond: 10, MaxRuntimeSeconds: 60, MaxEvidenceBytes: 1000,
	}, actor)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.ApproveGrant(grant.ID, actor); err != nil {
		t.Fatal(err)
	}
	run, err := svc.CreateScan(context.Background(), ScanInput{Target: "203.0.113.5", Type: "ip", Ports: []int{9}, GrantID: grant.ID})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.RevokeGrant(grant.ID, actor, "withdrawn"); err != nil {
		t.Fatal(err)
	}
	worked, err := svc.ExecuteAvailable(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if worked {
		t.Fatal("revoked grant still executed a unit")
	}
	got, err := svc.Run(run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != task.RunCompletedWithErrors {
		t.Fatalf("status = %s", got.Status)
	}
}
