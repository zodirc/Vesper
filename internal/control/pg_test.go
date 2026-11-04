package control

import (
	"context"
	"encoding/binary"
	"testing"
	"time"

	"github.com/zodirc/Vesper/internal/probe/pgprobe"
)

func TestPostgreSQLStartupIdentifiesTheProtocolWithoutAProduct(t *testing.T) {
	port := serveBytes(t, pgAuthMessage(5))
	restore := pgProbeForPort
	pgProbeForPort = func(candidate int) string {
		if candidate == port {
			return pgprobe.Name
		}
		return ""
	}
	t.Cleanup(func() { pgProbeForPort = restore })
	now := time.Date(2026, 11, 4, 11, 40, 0, 0, time.UTC)
	svc, err := New(t.TempDir(), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	grantID := approveTCPGrant(t, svc, "127.0.0.1", port, now)
	run, err := svc.CreateScan(context.Background(), ScanInput{Name: "postgresql", Target: "127.0.0.1", Type: "ip", Ports: []int{port}, GrantID: grantID})
	if err != nil {
		t.Fatal(err)
	}
	finishRun(t, svc)
	var sawUnit bool
	_, units, _ := svc.tasks.Export()
	for _, unit := range units {
		if unit.ScanRunID == run.ID && unit.UnitType == "protocol_probe" && len(unit.RequiredCapabilities) == 1 && unit.RequiredCapabilities[0] == "protocol_postgresql" {
			sawUnit = true
		}
	}
	if !sawUnit {
		t.Fatal("postgresql probe was not scheduled")
	}
	var sawPostgreSQL bool
	for _, item := range svc.Hypotheses() {
		if item.ServiceType == "postgresql" && item.RawProductName == "" && item.RawVersion == "" && item.IdentityStatus == "unknown" && item.FingerprintPackVersion == "builtin-14" {
			sawPostgreSQL = true
		}
		if item.ServiceType != "" && item.ServiceType != "postgresql" {
			t.Fatalf("unexpected service %s", item.ServiceType)
		}
	}
	if !sawPostgreSQL {
		t.Fatalf("hypotheses = %+v", svc.Hypotheses())
	}
	var sawEvidence bool
	for _, item := range svc.evidenceRows {
		if item.EvidenceType == "raw_response" && item.SourceModule == "postgresqlprobe" && item.ContentType == "application/octet-stream" && item.ContentEncoding == "identity" && item.Sensitivity == "internal" && item.IntegrityStatus == "verified" && item.StoredAt != nil {
			sawEvidence = true
		}
	}
	if !sawEvidence {
		t.Fatalf("evidence = %+v", svc.evidenceRows)
	}
	for _, item := range svc.Observations(run.ID) {
		if item.Type == "protocol_response" && item.Value["protocol"] == "postgresql" && item.Value["message_type"] == "R" && item.Value["auth_method"] == 5 {
			return
		}
	}
	t.Fatal("postgresql protocol observation was not recorded")
}

func TestPostgreSQLPortHintDoesNotOverrideTheResponse(t *testing.T) {
	port := serveBytes(t, []byte("HTTP/1.0 200 OK\r\n\r\n"))
	restore := pgProbeForPort
	pgProbeForPort = func(candidate int) string {
		if candidate == port {
			return pgprobe.Name
		}
		return ""
	}
	t.Cleanup(func() { pgProbeForPort = restore })
	now := time.Date(2026, 11, 4, 11, 50, 0, 0, time.UTC)
	svc, err := New(t.TempDir(), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	grantID := approveTCPGrant(t, svc, "127.0.0.1", port, now)
	if _, err := svc.CreateScan(context.Background(), ScanInput{Name: "not-postgresql", Target: "127.0.0.1", Type: "ip", Ports: []int{port}, GrantID: grantID}); err != nil {
		t.Fatal(err)
	}
	finishRun(t, svc)
	for _, item := range svc.Hypotheses() {
		if item.ServiceType == "postgresql" {
			t.Fatalf("http response became postgresql: %+v", item)
		}
	}
}

func pgAuthMessage(method uint32) []byte {
	raw := []byte{'R', 0, 0, 0, 8, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(raw[5:], method)
	return raw
}
