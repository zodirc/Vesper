package control

import (
	"context"
	"testing"
	"time"

	"github.com/zodirc/Vesper/internal/probe/clickhouseprobe"
)

func TestClickHouseHelloIdentifiesTheProtocolWithoutAProduct(t *testing.T) {
	port := serveBytes(t, []byte{0x00, 0x04, 'N', 'o', 'd', 'e', 0x18, 0x03, 0xdf, 0xa9, 0x03})
	restore := clickHouseProbeForPort
	clickHouseProbeForPort = func(candidate int) string {
		if candidate == port {
			return clickhouseprobe.Name
		}
		return ""
	}
	t.Cleanup(func() { clickHouseProbeForPort = restore })
	now := time.Date(2026, 11, 4, 14, 20, 0, 0, time.UTC)
	svc, err := New(t.TempDir(), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	grantID := approveTCPGrant(t, svc, "127.0.0.1", port, now)
	run, err := svc.CreateScan(context.Background(), ScanInput{Name: "clickhouse", Target: "127.0.0.1", Type: "ip", Ports: []int{port}, GrantID: grantID})
	if err != nil {
		t.Fatal(err)
	}
	finishRun(t, svc)
	var sawUnit bool
	_, units, _ := svc.tasks.Export()
	for _, unit := range units {
		if unit.ScanRunID == run.ID && unit.UnitType == "protocol_probe" && len(unit.RequiredCapabilities) == 1 && unit.RequiredCapabilities[0] == "protocol_clickhouse" {
			sawUnit = true
		}
	}
	if !sawUnit {
		t.Fatal("clickhouse probe was not scheduled")
	}
	var sawClickHouse bool
	for _, item := range svc.Hypotheses() {
		if item.ServiceType == "clickhouse" && item.RawProductName == "" && item.RawVersion == "" && item.IdentityStatus == "unknown" && item.FingerprintPackVersion == "builtin-15" {
			sawClickHouse = true
		}
		if item.ServiceType != "" && item.ServiceType != "clickhouse" {
			t.Fatalf("unexpected service %s", item.ServiceType)
		}
	}
	if !sawClickHouse {
		t.Fatalf("hypotheses = %+v", svc.Hypotheses())
	}
	var sawEvidence bool
	for _, item := range svc.evidenceRows {
		if item.EvidenceType == "raw_response" && item.SourceModule == "clickhouseprobe" && item.ContentType == "application/octet-stream" && item.ContentEncoding == "identity" && item.Sensitivity == "internal" && item.IntegrityStatus == "verified" && item.StoredAt != nil {
			sawEvidence = true
		}
	}
	if !sawEvidence {
		t.Fatalf("evidence = %+v", svc.evidenceRows)
	}
	for _, item := range svc.Observations(run.ID) {
		if item.Type == "protocol_response" && item.Value["protocol"] == "clickhouse" && item.Value["reply"] == "HELLO" && item.Value["server_version"] == "24.3" && item.Value["protocol_revision"] == 54495 {
			return
		}
	}
	t.Fatal("clickhouse protocol observation was not recorded")
}

func TestClickHousePortHintDoesNotOverrideTheResponse(t *testing.T) {
	port := serveBytes(t, []byte("HTTP/1.0 200 OK\r\n\r\n"))
	restore := clickHouseProbeForPort
	clickHouseProbeForPort = func(candidate int) string {
		if candidate == port {
			return clickhouseprobe.Name
		}
		return ""
	}
	t.Cleanup(func() { clickHouseProbeForPort = restore })
	now := time.Date(2026, 11, 4, 14, 30, 0, 0, time.UTC)
	svc, err := New(t.TempDir(), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	grantID := approveTCPGrant(t, svc, "127.0.0.1", port, now)
	if _, err := svc.CreateScan(context.Background(), ScanInput{Name: "not-clickhouse", Target: "127.0.0.1", Type: "ip", Ports: []int{port}, GrantID: grantID}); err != nil {
		t.Fatal(err)
	}
	finishRun(t, svc)
	for _, item := range svc.Hypotheses() {
		if item.ServiceType == "clickhouse" {
			t.Fatalf("http response became clickhouse: %+v", item)
		}
	}
}
