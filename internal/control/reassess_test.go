package control

import (
	"context"
	"testing"
	"time"

	"github.com/zodirc/Vesper/internal/assess"
	"github.com/zodirc/Vesper/internal/id"
)

func TestReassessAppendsNewJudgmentsAndKeepsHistory(t *testing.T) {
	now := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	svc, err := New(t.TempDir(), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	product, err := svc.AddProduct("generic", "nginx", "generic:nginx", "nginx")
	if err != nil {
		t.Fatal(err)
	}
	statement := assess.Statement{
		SourceRecordID: "nginx-range", VulnerabilityID: "CVE-2026-5000", Ecosystem: "generic", ProductKey: product.CanonicalKey, Severity: "high",
		Ranges: []assess.Range{{Ecosystem: "generic", Start: "1.0.0", StartInclusive: true, End: "2.0.0", EndInclusive: false}},
	}
	if err := svc.AddStatement(statement); err != nil {
		t.Fatal(err)
	}
	endpoint := id.MustNew()
	svc.mu.Lock()
	svc.appendObservation(Observation{
		EndpointID: &endpoint, Type: "protocol_response", SubjectKey: "tcp:80",
		ObservedAt: now, CollectedAt: now, ResultStatus: "observed",
		Value: map[string]any{"protocol": "http", "headers": map[string]any{"server": "nginx/1.24.0"}},
	})
	svc.mu.Unlock()
	snapshots := svc.Snapshots()
	first := snapshots[len(snapshots)-1]
	added, err := svc.Reassess(context.Background(), first.ID)
	if err != nil {
		t.Fatal(err)
	}
	if added != 1 || len(svc.hypotheses) != 1 || svc.hypotheses[0].RawProductName != "nginx" || svc.hypotheses[0].RawVersion != "1.24.0" {
		t.Fatalf("added = %d hypotheses = %+v", added, svc.hypotheses)
	}
	originalHypothesis := svc.hypotheses[0]
	originalDetection := svc.detections[0]
	if originalDetection.ResultStatus != "confirmed" || originalDetection.IntelSnapshotID != first.ID {
		t.Fatalf("detection = %+v", originalDetection)
	}
	findings := svc.Findings()
	if len(findings) != 1 || findings[0].Severity != "high" || findings[0].Status != "confirmed" {
		t.Fatalf("findings = %+v", findings)
	}
	added, err = svc.Reassess(context.Background(), first.ID)
	if err != nil {
		t.Fatal(err)
	}
	if added != 0 || len(svc.detections) != 1 || len(svc.occurrences) != 1 || svc.hypotheses[0].ID != originalHypothesis.ID || svc.hypotheses[0].RawVersion != originalHypothesis.RawVersion {
		t.Fatalf("repeat added = %d detections = %d occurrences = %d", added, len(svc.detections), len(svc.occurrences))
	}
	statement.Severity = "critical"
	if err := svc.AddStatement(statement); err != nil {
		t.Fatal(err)
	}
	snapshots = svc.Snapshots()
	second := snapshots[len(snapshots)-1]
	added, err = svc.Reassess(context.Background(), second.ID)
	if err != nil {
		t.Fatal(err)
	}
	if added != 1 {
		t.Fatalf("severity change added %d", added)
	}
	var kept bool
	for _, item := range svc.detections {
		if item.ID == originalDetection.ID && item.Severity == "high" && item.ResultStatus == "confirmed" {
			kept = true
		}
	}
	findings = svc.Findings()
	if !kept || len(findings) != 1 || findings[0].Severity != "critical" || findings[0].Status != "confirmed" || len(svc.occurrences) != 2 {
		t.Fatalf("kept = %v findings = %+v occurrences = %d", kept, findings, len(svc.occurrences))
	}
	statement.Severity = "low"
	statement.Ranges = []assess.Range{{Ecosystem: "generic", Start: "1.0.0", StartInclusive: true, End: "1.24.0", EndInclusive: false}}
	if err := svc.AddStatement(statement); err != nil {
		t.Fatal(err)
	}
	snapshots = svc.Snapshots()
	third := snapshots[len(snapshots)-1]
	if _, err := svc.Reassess(context.Background(), third.ID); err != nil {
		t.Fatal(err)
	}
	var cleared bool
	for _, item := range svc.detections {
		if item.IntelSnapshotID == third.ID && item.ResultStatus == "not_vulnerable" {
			cleared = true
		}
	}
	findings = svc.Findings()
	if !cleared || len(findings) != 1 || findings[0].Status != "confirmed" || findings[0].Severity != "critical" || len(svc.occurrences) != 2 {
		t.Fatalf("cleared = %v findings = %+v occurrences = %d detections = %+v", cleared, findings, len(svc.occurrences), svc.detections)
	}
}
