package control

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/zodirc/Vesper/internal/assess"
)

func TestImportPublishesImmutableSnapshot(t *testing.T) {
	now := time.Date(2026, 11, 3, 1, 0, 0, 0, time.UTC)
	svc, err := New(t.TempDir(), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	document := []byte(`{
	  "schema_version": "1.6.1",
	  "id": "GHSA-test-0001",
	  "aliases": ["CVE-2026-1000"],
	  "affected": [{
	    "package": {"ecosystem": "Debian", "name": "nginx"},
	    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "1.0.0"}, {"fixed": "1.26.0"}]}]
	  }]
	}`)
	first, err := svc.ImportIntel(context.Background(), "osv", document)
	if err != nil {
		t.Fatal(err)
	}
	again, err := svc.ImportIntel(context.Background(), "osv", document)
	if err != nil {
		t.Fatal(err)
	}
	if again.ID != first.ID || len(svc.statements) != 1 {
		t.Fatalf("snapshot = %s statements = %d", again.ID, len(svc.statements))
	}
	if _, err := svc.ImportIntel(context.Background(), "osv", []byte(`{"id":`)); err == nil {
		t.Fatal("invalid osv document was imported")
	}
	if len(svc.Snapshots()) != 1 {
		t.Fatalf("snapshots = %+v", svc.Snapshots())
	}
	changed := []byte(`{
	  "schema_version": "1.6.1",
	  "id": "GHSA-test-0001",
	  "aliases": ["CVE-2026-1000"],
	  "affected": [{
	    "package": {"ecosystem": "Debian", "name": "nginx"},
	    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "1.0.0"}, {"fixed": "1.27.0"}]}]
	  }]
	}`)
	next, err := svc.ImportIntel(context.Background(), "osv", changed)
	if err != nil {
		t.Fatal(err)
	}
	if next.ID == first.ID || len(svc.statements) != 2 || len(svc.Snapshots()) != 2 {
		t.Fatalf("next = %s statements = %d snapshots = %d", next.ID, len(svc.statements), len(svc.Snapshots()))
	}
	old := svc.statementsIn(first.ID)
	if len(old) != 1 || old[0].FixedVersions[0] != "1.26.0" {
		t.Fatalf("old snapshot = %+v", old)
	}
	current := svc.statementsIn(next.ID)
	if len(current) != 1 || current[0].FixedVersions[0] != "1.27.0" || current[0].SupersedesID != old[0].ID {
		t.Fatalf("current snapshot = %+v", current)
	}
}

func TestImportedScoreSurvivesRestart(t *testing.T) {
	dsn := os.Getenv("VESPER_TEST_DSN")
	if dsn == "" {
		t.Skip("VESPER_TEST_DSN is not set")
	}
	resetDatabase(t, dsn)
	ctx := context.Background()
	now := time.Date(2026, 11, 3, 1, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	migration := filepath.Join("..", "..", "migrations")
	first, err := Open(ctx, t.TempDir(), dsn, migration, clock)
	if err != nil {
		t.Fatal(err)
	}
	document := []byte("#model_version:v2026.01.01\ncve,epss,percentile\nCVE-2026-1000,0.5,0.9\n")
	snapshot, err := first.ImportIntel(ctx, "epss", document)
	if err != nil {
		t.Fatal(err)
	}
	first.Close()
	second, err := Open(ctx, t.TempDir(), dsn, migration, clock)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	restored := second.Snapshots()
	if len(restored) != 1 || restored[0].ID != snapshot.ID || restored[0].ContentDigest != snapshot.ContentDigest {
		t.Fatalf("snapshots = %+v", restored)
	}
	statements := second.statementsIn(snapshot.ID)
	if len(statements) != 1 || statements[0].VulnerabilityID != "CVE-2026-1000" || statements[0].EPSS == nil || *statements[0].EPSS != 0.5 {
		t.Fatalf("statements = %+v", statements)
	}
}

func TestConfigurationConstraintBlocksAffected(t *testing.T) {
	statement := assess.Statement{
		Ecosystem: "generic",
		Ranges:    []assess.Range{{Ecosystem: "generic", Start: "1.0.0", StartInclusive: true, End: "1.26.0", EndInclusive: true}},
	}
	if applicabilityFor("generic", "1.24.0", statement) != assess.Affected {
		t.Fatal("version inside the range was not affected")
	}
	statement.ConfigurationConstraints = []byte(`{"required":"auth"}`)
	if applicabilityFor("generic", "1.24.0", statement) != assess.InsufficientEvidence {
		t.Fatal("configuration constraint was treated as affected")
	}
	deb := assess.Statement{
		Ecosystem: "deb", KEV: true,
		Ranges: []assess.Range{{Ecosystem: "deb", Start: "1.0.0", StartInclusive: true, End: "2.0.0", EndInclusive: true}},
	}
	if applicabilityFor("deb", "1.24.0", deb) != assess.InsufficientEvidence {
		t.Fatal("deb range used a generic comparison")
	}
}
