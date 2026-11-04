package control

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zodirc/Vesper/internal/assess"
	"github.com/zodirc/Vesper/internal/id"
	"github.com/zodirc/Vesper/internal/scope"
	"github.com/zodirc/Vesper/internal/task"
)

func TestVerificationRetestsTheEndpointAndDoesNotCloseWithoutContraryEvidence(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	var version atomic.Value
	version.Store("1.24.0")
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
				_, _ = io.WriteString(c, "HTTP/1.0 200 OK\r\nServer: nginx/"+version.Load().(string)+"\r\nContent-Length: 2\r\n\r\nok")
			}(conn)
		}
	}()
	port := listener.Addr().(*net.TCPAddr).Port
	current := time.Date(2026, 11, 4, 5, 0, 0, 0, time.UTC)
	svc, err := New(t.TempDir(), func() time.Time { return current })
	if err != nil {
		t.Fatal(err)
	}
	actor := id.MustNew()
	grant, err := svc.CreateGrant(GrantInput{
		Name: "lab", SubjectType: "user",
		Selectors:  []SelectorInput{{Kind: "ip", Value: "127.0.0.1"}},
		Transports: []string{"tcp"}, Ports: []scope.PortRange{{Start: port, End: port}},
		Operations:          []string{scope.OpDiscovery, scope.OpConnect, scope.OpProtocolProbe},
		ObservationPointIDs: []id.ID{svc.ObservationPointID()}, ValidFrom: current.Add(-time.Minute),
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
	first, err := svc.CreateScan(context.Background(), ScanInput{Name: "initial", Target: "127.0.0.1", Type: "ip", Ports: []int{port}, GrantID: grant.ID})
	if err != nil {
		t.Fatal(err)
	}
	finishRun(t, svc)
	findings := svc.Findings()
	if len(findings) != 1 || findings[0].Status != "open" {
		t.Fatalf("findings = %+v", findings)
	}
	if _, err := svc.CreateVerification(context.Background(), id.MustNew(), grant.ID); !errors.Is(err, ErrFindingNotFound) {
		t.Fatalf("err = %v", err)
	}
	version.Store("1.26.0")
	current = current.Add(time.Minute)
	verification, err := svc.CreateVerification(context.Background(), findings[0].ID, grant.ID)
	if err != nil {
		t.Fatal(err)
	}
	if verification.TriggerType != "verification" || verification.Status != task.RunRunning {
		t.Fatalf("verification = %+v", verification)
	}
	if first.TriggerType != "manual" || strings.Contains(string(first.Plan), "finding_id") {
		t.Fatalf("trigger = %s plan = %s", first.TriggerType, first.Plan)
	}
	if svc.accounts[first.ID] == nil || svc.accounts[verification.ID] == nil || svc.accounts[first.ID] == svc.accounts[verification.ID] {
		t.Fatal("verification reused the original budget account")
	}
	var plan planBody
	if err := json.Unmarshal(verification.Plan, &plan); err != nil {
		t.Fatal(err)
	}
	if plan.FindingID != findings[0].ID.String() || plan.VulnerabilityID != "CVE-2026-0001" || len(plan.Ports) != 1 || plan.Ports[0] != port || plan.Transport != "tcp" {
		t.Fatalf("plan = %+v", plan)
	}
	_, units, err := svc.tasks.Snapshot(verification.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, unit := range units {
		if unit.UnitType == "host_collect" {
			t.Fatal("verification created host collection")
		}
	}
	finishRun(t, svc)
	var contrary *Detection
	for i := range svc.detections {
		item := &svc.detections[i]
		if item.VulnerabilityID == "CVE-2026-0001" && item.ResultStatus == "not_vulnerable" && item.EvaluatedAt.After(findings[0].LastSeenAt) {
			contrary = item
			break
		}
	}
	if contrary == nil || len(contrary.EvidenceIDs) == 0 {
		t.Fatalf("detections = %+v", svc.detections)
	}
	if _, err := svc.AddDisposition(findings[0].ID, actor, DispositionInput{Type: DispositionResolve, Reason: "patched", DetectionID: contrary.ID}); err != nil {
		t.Fatal(err)
	}
	if got := svc.Findings(); len(got) != 1 || got[0].Status != "resolved" || len(svc.occurrences) != 1 {
		t.Fatalf("findings = %+v occurrences = %d", got, len(svc.occurrences))
	}
}

func TestVerificationNoResponseDoesNotResolve(t *testing.T) {
	current := time.Date(2026, 11, 4, 6, 0, 0, 0, time.UTC)
	svc, err := New(t.TempDir(), func() time.Time { return current })
	if err != nil {
		t.Fatal(err)
	}
	svc.DialTimeout = 200 * time.Millisecond
	findingID := seedCatalogFinding(svc, netip.MustParseAddr("203.0.113.10"), "tcp", 80, current)
	before, _, _ := svc.tasks.Export()
	if _, err := svc.CreateVerification(context.Background(), findingID, id.MustNew()); err == nil {
		t.Fatal("missing grant created a run")
	}
	after, _, _ := svc.tasks.Export()
	if len(after) != len(before) {
		t.Fatal("rejected verification created a run")
	}
	actor := id.MustNew()
	grant, err := svc.CreateGrant(GrantInput{
		Name: "quiet", SubjectType: "user",
		Selectors:  []SelectorInput{{Kind: "ip", Value: "203.0.113.10"}},
		Transports: []string{"tcp"}, Ports: []scope.PortRange{{Start: 80, End: 80}},
		Operations:          []string{scope.OpConnect, scope.OpProtocolProbe},
		ObservationPointIDs: []id.ID{svc.ObservationPointID()}, ValidFrom: current.Add(-time.Minute),
		MaxTargets: 2, MaxAddresses: 2, MaxConnections: 4, MaxRequests: 4, MaxConcurrency: 1,
		MaxRatePerSecond: 1000, MaxRuntimeSeconds: 60, MaxEvidenceBytes: 1000,
	}, actor)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.ApproveGrant(grant.ID, actor); err != nil {
		t.Fatal(err)
	}
	run, err := svc.CreateVerification(context.Background(), findingID, grant.ID)
	if err != nil {
		t.Fatal(err)
	}
	finishRun(t, svc)
	got, err := svc.Run(run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != task.RunCompleted && got.Status != task.RunCompletedWithErrors {
		t.Fatalf("status = %s summary = %s", got.Status, got.FailureSummary)
	}
	for _, item := range svc.detections {
		if item.ResultStatus == "not_vulnerable" && item.VulnerabilityID == "CVE-2026-0001" {
			t.Fatalf("no response produced a contrary detection: %+v", item)
		}
	}
	if _, err := svc.AddDisposition(findingID, actor, DispositionInput{Type: DispositionResolve, Reason: "gone", DetectionID: id.MustNew()}); !errors.Is(err, ErrDispositionVerification) {
		t.Fatalf("err = %v", err)
	}
	if status := findingStatus(svc, findingID); status != "open" || occurrenceCount(svc, findingID) != 1 {
		t.Fatalf("status = %s occurrences = %d", status, occurrenceCount(svc, findingID))
	}
}

func TestVerificationUDPRetestsOnlyTheDNSProbe(t *testing.T) {
	current := time.Date(2026, 11, 4, 6, 30, 0, 0, time.UTC)
	svc, err := New(t.TempDir(), func() time.Time { return current })
	if err != nil {
		t.Fatal(err)
	}
	findingID := seedCatalogFinding(svc, netip.MustParseAddr("203.0.113.53"), "udp", 53, current)
	actor := id.MustNew()
	grant, err := svc.CreateGrant(GrantInput{
		Name: "dns", SubjectType: "user",
		Selectors:  []SelectorInput{{Kind: "ip", Value: "203.0.113.53"}},
		Transports: []string{"udp"}, Ports: []scope.PortRange{{Start: 53, End: 53}},
		Operations:          []string{scope.OpProtocolProbe},
		ObservationPointIDs: []id.ID{svc.ObservationPointID()}, ValidFrom: current.Add(-time.Minute),
		MaxTargets: 2, MaxAddresses: 2, MaxConnections: 2, MaxRequests: 4, MaxConcurrency: 1,
		MaxRatePerSecond: 1000, MaxRuntimeSeconds: 60, MaxEvidenceBytes: 1000,
	}, actor)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.ApproveGrant(grant.ID, actor); err != nil {
		t.Fatal(err)
	}
	run, err := svc.CreateVerification(context.Background(), findingID, grant.ID)
	if err != nil {
		t.Fatal(err)
	}
	_, units, err := svc.tasks.Snapshot(run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(units) != 1 || units[0].UnitType != "udp_probe" {
		t.Fatalf("units = %+v", units)
	}
	if err := svc.Cancel(run.ID); err != nil {
		t.Fatal(err)
	}
}

func TestConfigurationVerificationCollectsOnlyTheOriginalOperation(t *testing.T) {
	current := time.Date(2026, 11, 4, 7, 0, 0, 0, time.UTC)
	svc, err := New(t.TempDir(), func() time.Time { return current })
	if err != nil {
		t.Fatal(err)
	}
	findingID := id.MustNew()
	assetID := id.MustNew()
	svc.findings[assetID.String()+"|host_identity_present"] = &Finding{
		ID: findingID, FindingKey: assetID.String() + "|host_identity_present", FindingType: "misconfiguration",
		AssetID: assetID, VulnerabilityID: "host_identity_present", Title: "host_identity_present", Severity: "low",
		Status: "open", FirstSeenAt: current, LastSeenAt: current,
	}
	svc.occurrences = append(svc.occurrences, Occurrence{
		ID: id.MustNew(), FindingID: findingID, AssessmentRunID: id.MustNew(), DetectionID: id.MustNew(),
		ObservedAt: current, Severity: "low", ConditionDigest: "present",
	})
	actor := id.MustNew()
	grant, err := svc.CreateGrant(GrantInput{
		Name: "collect", SubjectType: "user",
		Selectors:  []SelectorInput{{Kind: "ip", Value: "127.0.0.1"}},
		Transports: []string{"tcp"}, Ports: []scope.PortRange{{Start: 1, End: 1}},
		Operations:          []string{scope.OpConfigCheck},
		ObservationPointIDs: []id.ID{svc.ObservationPointID()}, ValidFrom: current.Add(-time.Minute),
		MaxTargets: 2, MaxAddresses: 2, MaxConnections: 2, MaxRequests: 2, MaxConcurrency: 1,
		MaxRatePerSecond: 1000, MaxRuntimeSeconds: 60, MaxEvidenceBytes: 1000,
	}, actor)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.ApproveGrant(grant.ID, actor); err != nil {
		t.Fatal(err)
	}
	run, err := svc.CreateVerification(context.Background(), findingID, grant.ID)
	if err != nil {
		t.Fatal(err)
	}
	if run.TriggerType != "verification" {
		t.Fatalf("trigger = %s", run.TriggerType)
	}
	var plan planBody
	if err := json.Unmarshal(run.Plan, &plan); err != nil {
		t.Fatal(err)
	}
	if plan.Environment == nil || plan.Environment.ObservationPointID != svc.ObservationPointID().String() || plan.Environment.CapabilitySnapshotID == "" {
		t.Fatalf("environment = %+v", plan.Environment)
	}
	_, units, err := svc.tasks.Snapshot(run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(units) != 1 || units[0].UnitType != "host_collect" || !json.Valid(units[0].Input) || !strings.Contains(string(units[0].Input), "collect_os_info") || strings.Contains(string(units[0].Input), "collect_interfaces") {
		t.Fatalf("units = %+v", units)
	}
	for _, unit := range units {
		if unit.UnitType == "port_scan" || unit.UnitType == "udp_probe" {
			t.Fatalf("configuration verification dialed: %+v", unit)
		}
	}
	finishRun(t, svc)
	for _, item := range svc.detections {
		if item.ResultStatus != "not_vulnerable" {
			continue
		}
		if _, err := svc.AddDisposition(findingID, actor, DispositionInput{Type: DispositionResolve, Reason: "field present", DetectionID: item.ID}); !errors.Is(err, ErrDispositionVerification) {
			t.Fatalf("configuration retest closed the finding: %v", err)
		}
	}
	if status := findingStatus(svc, findingID); status != "open" || occurrenceCount(svc, findingID) != 1 {
		t.Fatalf("status = %s occurrences = %d", status, occurrenceCount(svc, findingID))
	}
}

func TestVerificationRequiresAnOccurrence(t *testing.T) {
	current := time.Date(2026, 11, 4, 8, 0, 0, 0, time.UTC)
	svc, err := New(t.TempDir(), func() time.Time { return current })
	if err != nil {
		t.Fatal(err)
	}
	findingID := id.MustNew()
	endpoint := svc.catalog.ObserveEndpoint(netip.MustParseAddr("203.0.113.11"), "tcp", 80, "open", current)
	svc.findings[endpoint.ID.String()+"|CVE-2026-0001"] = &Finding{
		ID: findingID, FindingKey: endpoint.ID.String() + "|CVE-2026-0001", FindingType: "vulnerability",
		EndpointID: endpoint.ID, VulnerabilityID: "CVE-2026-0001", Status: "open", FirstSeenAt: current, LastSeenAt: current,
	}
	if _, err := svc.CreateVerification(context.Background(), findingID, id.MustNew()); !errors.Is(err, ErrVerificationUnavailable) {
		t.Fatalf("err = %v", err)
	}
	configID := id.MustNew()
	svc.findings["asset|unknown_rule"] = &Finding{
		ID: configID, FindingKey: "asset|unknown_rule", FindingType: "misconfiguration",
		AssetID: id.MustNew(), VulnerabilityID: "unknown_rule", Status: "open", FirstSeenAt: current, LastSeenAt: current,
	}
	svc.occurrences = append(svc.occurrences, Occurrence{
		ID: id.MustNew(), FindingID: configID, AssessmentRunID: id.MustNew(), DetectionID: id.MustNew(), ObservedAt: current,
	})
	if _, err := svc.CreateVerification(context.Background(), configID, id.MustNew()); !errors.Is(err, ErrVerificationUnavailable) {
		t.Fatalf("err = %v", err)
	}
	if runs, _, _ := svc.tasks.Export(); len(runs) != 0 {
		t.Fatalf("runs = %+v", runs)
	}
}

func seedCatalogFinding(svc *Service, addr netip.Addr, transport string, port int, when time.Time) id.ID {
	endpoint := svc.catalog.ObserveEndpoint(addr, transport, port, "open", when)
	findingID := id.MustNew()
	svc.findings[endpoint.ID.String()+"|CVE-2026-0001"] = &Finding{
		ID: findingID, FindingKey: endpoint.ID.String() + "|CVE-2026-0001", FindingType: "vulnerability",
		EndpointID: endpoint.ID, VulnerabilityID: "CVE-2026-0001", Title: "CVE-2026-0001", Severity: "high",
		Status: "open", FirstSeenAt: when, LastSeenAt: when,
	}
	svc.occurrences = append(svc.occurrences, Occurrence{
		ID: id.MustNew(), FindingID: findingID, AssessmentRunID: id.MustNew(), DetectionID: id.MustNew(),
		ObservedAt: when, Severity: "high", ConditionDigest: "confirmed",
	})
	return findingID
}

func findingStatus(svc *Service, findingID id.ID) string {
	for _, item := range svc.Findings() {
		if item.ID == findingID {
			return item.Status
		}
	}
	return ""
}

func occurrenceCount(svc *Service, findingID id.ID) int {
	count := 0
	for _, item := range svc.occurrences {
		if item.FindingID == findingID {
			count++
		}
	}
	return count
}
