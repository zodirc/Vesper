package control

import (
	"context"
	"testing"
	"time"

	"github.com/zodirc/Vesper/internal/assess"
	"github.com/zodirc/Vesper/internal/id"
	"github.com/zodirc/Vesper/internal/identity"
)

func TestContradictoryAndConflictedIdentityDoNotConfirm(t *testing.T) {
	now := time.Date(2026, 11, 5, 11, 0, 0, 0, time.UTC)
	svc, err := New(t.TempDir(), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	product, err := svc.AddProduct("generic", "nginx", "generic:nginx", "nginx")
	if err != nil {
		t.Fatal(err)
	}
	affected := assess.Statement{
		VulnerabilityID: "CVE-2026-4100", Ecosystem: "generic", ProductKey: product.CanonicalKey, Severity: "high",
		Ranges: []assess.Range{{Ecosystem: "generic", Start: "1.0.0", StartInclusive: true, End: "2.0.0", EndInclusive: false}},
	}
	if err := svc.AddStatement(affected); err != nil {
		t.Fatal(err)
	}
	excluded := affected
	excluded.SourceRecordID = "exclude-1.2.0"
	excluded.Ranges = []assess.Range{{Ecosystem: "generic", Start: "1.2.0", StartInclusive: true, End: "1.2.0", EndInclusive: true, Exact: true, Excluded: true}}
	if err := svc.AddStatement(excluded); err != nil {
		t.Fatal(err)
	}
	snapshots := svc.Snapshots()
	snapshot := snapshots[len(snapshots)-1]
	productID := product.ID
	endpoint := id.MustNew()
	svc.hypotheses = append(svc.hypotheses,
		identity.Hypothesis{ID: id.MustNew(), EndpointID: endpoint, ProductIdentityID: &productID, RawVersion: "1.2.0", IdentityStatus: "candidate", EvaluatedAt: now},
		identity.Hypothesis{ID: id.MustNew(), EndpointID: id.MustNew(), ProductIdentityID: &productID, RawVersion: "1.5.0", IdentityStatus: "conflict", EvaluatedAt: now},
	)
	if _, err := svc.Reassess(context.Background(), snapshot.ID, ReassessOptions{}); err != nil {
		t.Fatal(err)
	}
	for _, detection := range svc.detections {
		if detection.IntelSnapshotID == snapshot.ID && detection.ResultStatus == "confirmed" {
			t.Fatalf("contradiction confirmed: %+v", detection)
		}
	}
	if findings := svc.Findings(); len(findings) != 0 {
		t.Fatalf("findings = %+v", findings)
	}
}

func TestRPMPackageUsesEpochVersionRelease(t *testing.T) {
	now := time.Date(2026, 11, 5, 11, 30, 0, 0, time.UTC)
	svc, err := New(t.TempDir(), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	document := []byte(`{
	  "id": "CVE-2026-4200",
	  "affected": [{"package": {"ecosystem": "Red Hat:enterprise_linux:8::baseos", "name": "bash"},
	    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "0:5.1.8-9.el8"}]}]}]
	}`)
	snapshot, err := svc.ImportIntel(context.Background(), "osv", document)
	if err != nil {
		t.Fatal(err)
	}
	assetID := id.MustNew()
	svc.mu.Lock()
	svc.appendObservation(Observation{
		AssetID: assetID, Type: "host_inventory", SubjectKey: "local:collect_os_info",
		ObservedAt: now, CollectedAt: now, ResultStatus: "observed",
		Value: map[string]any{"id": "rhel", "version_id": "8.10"},
	})
	svc.appendObservation(Observation{
		AssetID: assetID, Type: "host_inventory", SubjectKey: "local:collect_packages",
		ObservedAt: now, CollectedAt: now, ResultStatus: "observed",
		Value: map[string]any{"packages": []map[string]any{
			{"name": "bash", "epoch": "0", "version": "5.1.8", "release": "6.el8", "source": "rpm"},
		}},
	})
	svc.mu.Unlock()
	added, err := svc.Reassess(context.Background(), snapshot.ID, ReassessOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if added.Detections != 1 || svc.detections[0].ResultStatus != "confirmed" || svc.detections[0].SubjectType != "software_package" {
		t.Fatalf("added = %d detections = %+v", added.Detections, svc.detections)
	}
	svc.mu.Lock()
	svc.appendObservation(Observation{
		AssetID: assetID, Type: "host_inventory", SubjectKey: "local:collect_packages",
		ObservedAt: now.Add(time.Minute), CollectedAt: now.Add(time.Minute), ResultStatus: "observed",
		Value: map[string]any{"packages": []map[string]any{
			{"name": "bash", "epoch": "0", "version": "5.1.8", "release": "9.el8", "source": "rpm"},
		}},
	})
	svc.mu.Unlock()
	if _, err := svc.Reassess(context.Background(), snapshot.ID, ReassessOptions{}); err != nil {
		t.Fatal(err)
	}
	last := svc.detections[len(svc.detections)-1]
	if last.ResultStatus != "not_vulnerable" || last.VulnerabilityID != "CVE-2026-4200" {
		t.Fatalf("fixed rpm = %+v", last)
	}
}
