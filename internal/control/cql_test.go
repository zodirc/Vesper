package control

import (
	"context"
	"encoding/binary"
	"testing"
	"time"

	"github.com/zodirc/Vesper/internal/probe/cqlprobe"
)

func TestCQLStartupIdentifiesTheProtocolWithoutAProduct(t *testing.T) {
	port := serveBytes(t, cqlReady())
	restore := cqlProbeForPort
	cqlProbeForPort = func(candidate int) string {
		if candidate == port {
			return cqlprobe.Name
		}
		return ""
	}
	t.Cleanup(func() { cqlProbeForPort = restore })
	now := time.Date(2026, 11, 4, 13, 20, 0, 0, time.UTC)
	svc, err := New(t.TempDir(), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	grantID := approveTCPGrant(t, svc, "127.0.0.1", port, now)
	run, err := svc.CreateScan(context.Background(), ScanInput{Name: "cql", Target: "127.0.0.1", Type: "ip", Ports: []int{port}, GrantID: grantID})
	if err != nil {
		t.Fatal(err)
	}
	finishRun(t, svc)
	var sawUnit bool
	_, units, _ := svc.tasks.Export()
	for _, unit := range units {
		if unit.ScanRunID == run.ID && unit.UnitType == "protocol_probe" && len(unit.RequiredCapabilities) == 1 && unit.RequiredCapabilities[0] == "protocol_cql" {
			sawUnit = true
		}
	}
	if !sawUnit {
		t.Fatal("cql probe was not scheduled")
	}
	var sawCQL bool
	for _, item := range svc.Hypotheses() {
		if item.ServiceType == "cql" && item.RawProductName == "" && item.RawVersion == "" && item.IdentityStatus == "unknown" && item.FingerprintPackVersion == "builtin-15" {
			sawCQL = true
		}
		if item.ServiceType != "" && item.ServiceType != "cql" {
			t.Fatalf("unexpected service %s", item.ServiceType)
		}
	}
	if !sawCQL {
		t.Fatalf("hypotheses = %+v", svc.Hypotheses())
	}
	var sawEvidence bool
	for _, item := range svc.evidenceRows {
		if item.EvidenceType == "raw_response" && item.SourceModule == "cqlprobe" && item.ContentType == "application/octet-stream" && item.ContentEncoding == "identity" && item.Sensitivity == "internal" && item.IntegrityStatus == "verified" && item.StoredAt != nil {
			sawEvidence = true
		}
	}
	if !sawEvidence {
		t.Fatalf("evidence = %+v", svc.evidenceRows)
	}
	for _, item := range svc.Observations(run.ID) {
		if item.Type == "protocol_response" && item.Value["protocol"] == "cql" && item.Value["protocol_version"] == 4 && item.Value["reply"] == "READY" {
			return
		}
	}
	t.Fatal("cql protocol observation was not recorded")
}

func TestCQLPortHintDoesNotOverrideTheResponse(t *testing.T) {
	port := serveBytes(t, []byte("HTTP/1.0 200 OK\r\n\r\n"))
	restore := cqlProbeForPort
	cqlProbeForPort = func(candidate int) string {
		if candidate == port {
			return cqlprobe.Name
		}
		return ""
	}
	t.Cleanup(func() { cqlProbeForPort = restore })
	now := time.Date(2026, 11, 4, 13, 30, 0, 0, time.UTC)
	svc, err := New(t.TempDir(), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	grantID := approveTCPGrant(t, svc, "127.0.0.1", port, now)
	if _, err := svc.CreateScan(context.Background(), ScanInput{Name: "not-cql", Target: "127.0.0.1", Type: "ip", Ports: []int{port}, GrantID: grantID}); err != nil {
		t.Fatal(err)
	}
	finishRun(t, svc)
	for _, item := range svc.Hypotheses() {
		if item.ServiceType == "cql" {
			t.Fatalf("http response became cql: %+v", item)
		}
	}
}

func cqlReady() []byte {
	raw := make([]byte, 9)
	raw[0] = 0x84
	raw[4] = 0x02
	binary.BigEndian.PutUint32(raw[5:9], 0)
	return raw
}
