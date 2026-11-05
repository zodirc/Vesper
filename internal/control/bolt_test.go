package control

import (
	"context"
	"testing"
	"time"

	"github.com/zodirc/Vesper/internal/probe/boltprobe"
)

func TestBoltHandshakeIdentifiesTheProtocolWithoutAProduct(t *testing.T) {
	port := serveBytes(t, []byte{0x00, 0x00, 0x04, 0x05})
	restore := boltProbeForPort
	boltProbeForPort = func(candidate int) string {
		if candidate == port {
			return boltprobe.Name
		}
		return ""
	}
	t.Cleanup(func() { boltProbeForPort = restore })
	now := time.Date(2026, 11, 4, 13, 40, 0, 0, time.UTC)
	svc, err := New(t.TempDir(), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	grantID := approveTCPGrant(t, svc, "127.0.0.1", port, now)
	run, err := svc.CreateScan(context.Background(), ScanInput{Name: "bolt", Target: "127.0.0.1", Type: "ip", Ports: []int{port}, GrantID: grantID})
	if err != nil {
		t.Fatal(err)
	}
	finishRun(t, svc)
	var sawUnit bool
	_, units, _ := svc.tasks.Export()
	for _, unit := range units {
		if unit.ScanRunID == run.ID && unit.UnitType == "protocol_probe" && len(unit.RequiredCapabilities) == 1 && unit.RequiredCapabilities[0] == "protocol_bolt" {
			sawUnit = true
		}
	}
	if !sawUnit {
		t.Fatal("bolt probe was not scheduled")
	}
	var sawBolt bool
	for _, item := range svc.Hypotheses() {
		if item.ServiceType == "bolt" && item.RawProductName == "" && item.RawVersion == "" && item.IdentityStatus == "unknown" && item.FingerprintPackVersion == "builtin-15" {
			sawBolt = true
		}
		if item.ServiceType != "" && item.ServiceType != "bolt" {
			t.Fatalf("unexpected service %s", item.ServiceType)
		}
	}
	if !sawBolt {
		t.Fatalf("hypotheses = %+v", svc.Hypotheses())
	}
	var sawEvidence bool
	for _, item := range svc.evidenceRows {
		if item.EvidenceType == "raw_response" && item.SourceModule == "boltprobe" && item.ContentType == "application/octet-stream" && item.ContentEncoding == "identity" && item.Sensitivity == "internal" && item.IntegrityStatus == "verified" && item.StoredAt != nil {
			sawEvidence = true
		}
	}
	if !sawEvidence {
		t.Fatalf("evidence = %+v", svc.evidenceRows)
	}
	for _, item := range svc.Observations(run.ID) {
		if item.Type == "protocol_response" && item.Value["protocol"] == "bolt" && item.Value["protocol_version"] == "5.4" {
			return
		}
	}
	t.Fatal("bolt protocol observation was not recorded")
}

func TestBoltPortHintDoesNotOverrideTheResponse(t *testing.T) {
	port := serveBytes(t, []byte("HTTP/1.0 200 OK\r\n\r\n"))
	restore := boltProbeForPort
	boltProbeForPort = func(candidate int) string {
		if candidate == port {
			return boltprobe.Name
		}
		return ""
	}
	t.Cleanup(func() { boltProbeForPort = restore })
	now := time.Date(2026, 11, 4, 13, 50, 0, 0, time.UTC)
	svc, err := New(t.TempDir(), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	grantID := approveTCPGrant(t, svc, "127.0.0.1", port, now)
	if _, err := svc.CreateScan(context.Background(), ScanInput{Name: "not-bolt", Target: "127.0.0.1", Type: "ip", Ports: []int{port}, GrantID: grantID}); err != nil {
		t.Fatal(err)
	}
	finishRun(t, svc)
	for _, item := range svc.Hypotheses() {
		if item.ServiceType == "bolt" {
			t.Fatalf("http response became bolt: %+v", item)
		}
	}
}
