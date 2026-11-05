package control

import (
	"context"
	"testing"
	"time"

	"github.com/zodirc/Vesper/internal/id"
)

func TestDistroAdvisoryConfirmsBackportAndLeavesFixedPackage(t *testing.T) {
	now := time.Date(2026, 11, 5, 6, 0, 0, 0, time.UTC)
	svc, err := New(t.TempDir(), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	document := []byte(`{"openssl":{"CVE-2026-2000":{"releases":{"bookworm":{"status":"resolved","fixed_version":"3.0.11-1~deb12u2"}}}}}`)
	snapshot, err := svc.ImportIntel(context.Background(), "distro_advisory", document)
	if err != nil {
		t.Fatal(err)
	}
	assetID := id.MustNew()
	svc.mu.Lock()
	svc.appendObservation(Observation{
		AssetID: assetID, Type: "host_inventory", SubjectKey: "local:collect_os_info",
		ObservedAt: now, CollectedAt: now, ResultStatus: "observed",
		Value: map[string]any{"id": "debian", "version_codename": "bookworm", "version_id": "12"},
	})
	svc.appendObservation(Observation{
		AssetID: assetID, Type: "host_inventory", SubjectKey: "local:collect_packages",
		ObservedAt: now, CollectedAt: now, ResultStatus: "observed",
		Value: map[string]any{"packages": []map[string]any{
			{"name": "libssl3", "version": "3.0.11-1~deb12u1", "source": "dpkg", "source_package": "openssl"},
			{"name": "openssl", "version": "3.0.11-1~deb12u2", "source": "dpkg"},
		}},
	})
	svc.mu.Unlock()
	added, err := svc.Reassess(context.Background(), snapshot.ID, ReassessOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if added.Detections != 2 {
		t.Fatalf("added %d detections", added.Detections)
	}
	var affected, fixed bool
	for _, item := range svc.detections {
		if item.VulnerabilityID != "CVE-2026-2000" || item.Executor != "applicability" || item.SubjectType != "software_package" {
			continue
		}
		if item.ResultStatus == "confirmed" && item.Summary == "affected" {
			affected = true
		}
		if item.ResultStatus == "not_vulnerable" && item.Summary == "not_affected" {
			fixed = true
		}
	}
	if !affected || !fixed {
		t.Fatalf("detections = %+v", svc.detections)
	}
	findings := svc.Findings()
	if len(findings) != 1 || findings[0].VulnerabilityID != "CVE-2026-2000" || findings[0].AssetID != assetID || findings[0].Status != "confirmed" {
		t.Fatalf("findings = %+v", findings)
	}
}
