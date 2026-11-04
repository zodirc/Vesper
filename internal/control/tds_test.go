package control

import (
	"context"
	"encoding/binary"
	"testing"
	"time"

	"github.com/zodirc/Vesper/internal/probe/tdsprobe"
)

func TestTDSPreloginIdentifiesTheProtocolWithoutAProduct(t *testing.T) {
	port := serveBytes(t, tdsReply())
	restore := tdsProbeForPort
	tdsProbeForPort = func(candidate int) string {
		if candidate == port {
			return tdsprobe.Name
		}
		return ""
	}
	t.Cleanup(func() { tdsProbeForPort = restore })
	now := time.Date(2026, 11, 4, 12, 40, 0, 0, time.UTC)
	svc, err := New(t.TempDir(), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	grantID := approveTCPGrant(t, svc, "127.0.0.1", port, now)
	run, err := svc.CreateScan(context.Background(), ScanInput{Name: "tds", Target: "127.0.0.1", Type: "ip", Ports: []int{port}, GrantID: grantID})
	if err != nil {
		t.Fatal(err)
	}
	finishRun(t, svc)
	var sawUnit bool
	_, units, _ := svc.tasks.Export()
	for _, unit := range units {
		if unit.ScanRunID == run.ID && unit.UnitType == "protocol_probe" && len(unit.RequiredCapabilities) == 1 && unit.RequiredCapabilities[0] == "protocol_tds" {
			sawUnit = true
		}
	}
	if !sawUnit {
		t.Fatal("tds probe was not scheduled")
	}
	var sawTDS bool
	for _, item := range svc.Hypotheses() {
		if item.ServiceType == "tds" && item.RawProductName == "" && item.RawVersion == "" && item.IdentityStatus == "unknown" && item.FingerprintPackVersion == "builtin-14" {
			sawTDS = true
		}
		if item.ServiceType != "" && item.ServiceType != "tds" {
			t.Fatalf("unexpected service %s", item.ServiceType)
		}
	}
	if !sawTDS {
		t.Fatalf("hypotheses = %+v", svc.Hypotheses())
	}
	var sawEvidence bool
	for _, item := range svc.evidenceRows {
		if item.EvidenceType == "raw_response" && item.SourceModule == "tdsprobe" && item.ContentType == "application/octet-stream" && item.ContentEncoding == "identity" && item.Sensitivity == "internal" && item.IntegrityStatus == "verified" && item.StoredAt != nil {
			sawEvidence = true
		}
	}
	if !sawEvidence {
		t.Fatalf("evidence = %+v", svc.evidenceRows)
	}
	for _, item := range svc.Observations(run.ID) {
		if item.Type == "protocol_response" && item.Value["protocol"] == "tds" && item.Value["server_version"] == "15.0.2000.5" && item.Value["encryption"] == 3 {
			return
		}
	}
	t.Fatal("tds protocol observation was not recorded")
}

func TestTDSPortHintDoesNotOverrideTheResponse(t *testing.T) {
	port := serveBytes(t, []byte("HTTP/1.0 200 OK\r\n\r\n"))
	restore := tdsProbeForPort
	tdsProbeForPort = func(candidate int) string {
		if candidate == port {
			return tdsprobe.Name
		}
		return ""
	}
	t.Cleanup(func() { tdsProbeForPort = restore })
	now := time.Date(2026, 11, 4, 12, 50, 0, 0, time.UTC)
	svc, err := New(t.TempDir(), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	grantID := approveTCPGrant(t, svc, "127.0.0.1", port, now)
	if _, err := svc.CreateScan(context.Background(), ScanInput{Name: "not-tds", Target: "127.0.0.1", Type: "ip", Ports: []int{port}, GrantID: grantID}); err != nil {
		t.Fatal(err)
	}
	finishRun(t, svc)
	for _, item := range svc.Hypotheses() {
		if item.ServiceType == "tds" {
			t.Fatalf("http response became tds: %+v", item)
		}
	}
}

func tdsReply() []byte {
	body := []byte{
		0x00, 0x00, 0x0b, 0x00, 0x06,
		0x01, 0x00, 0x11, 0x00, 0x01,
		0xff,
		15, 0, 0x07, 0xd0, 0, 5,
		3,
	}
	raw := make([]byte, 8+len(body))
	raw[0] = 0x04
	raw[1] = 0x01
	binary.BigEndian.PutUint16(raw[2:4], uint16(len(raw)))
	raw[6] = 1
	copy(raw[8:], body)
	return raw
}
