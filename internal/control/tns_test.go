package control

import (
	"context"
	"encoding/binary"
	"testing"
	"time"

	"github.com/zodirc/Vesper/internal/probe/tnsprobe"
)

func TestTNSPingIdentifiesTheProtocolWithoutAProduct(t *testing.T) {
	port := serveBytes(t, tnsReply())
	restore := tnsProbeForPort
	tnsProbeForPort = func(candidate int) string {
		if candidate == port {
			return tnsprobe.Name
		}
		return ""
	}
	t.Cleanup(func() { tnsProbeForPort = restore })
	now := time.Date(2026, 11, 4, 13, 0, 0, 0, time.UTC)
	svc, err := New(t.TempDir(), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	grantID := approveTCPGrant(t, svc, "127.0.0.1", port, now)
	run, err := svc.CreateScan(context.Background(), ScanInput{Name: "tns", Target: "127.0.0.1", Type: "ip", Ports: []int{port}, GrantID: grantID})
	if err != nil {
		t.Fatal(err)
	}
	finishRun(t, svc)
	var sawUnit bool
	_, units, _ := svc.tasks.Export()
	for _, unit := range units {
		if unit.ScanRunID == run.ID && unit.UnitType == "protocol_probe" && len(unit.RequiredCapabilities) == 1 && unit.RequiredCapabilities[0] == "protocol_tns" {
			sawUnit = true
		}
	}
	if !sawUnit {
		t.Fatal("tns probe was not scheduled")
	}
	var sawTNS bool
	for _, item := range svc.Hypotheses() {
		if item.ServiceType == "tns" && item.RawProductName == "" && item.RawVersion == "" && item.IdentityStatus == "unknown" && item.FingerprintPackVersion == "builtin-14" {
			sawTNS = true
		}
		if item.ServiceType != "" && item.ServiceType != "tns" {
			t.Fatalf("unexpected service %s", item.ServiceType)
		}
	}
	if !sawTNS {
		t.Fatalf("hypotheses = %+v", svc.Hypotheses())
	}
	var sawEvidence bool
	for _, item := range svc.evidenceRows {
		if item.EvidenceType == "raw_response" && item.SourceModule == "tnsprobe" && item.ContentType == "application/octet-stream" && item.ContentEncoding == "identity" && item.Sensitivity == "internal" && item.IntegrityStatus == "verified" && item.StoredAt != nil {
			sawEvidence = true
		}
	}
	if !sawEvidence {
		t.Fatalf("evidence = %+v", svc.evidenceRows)
	}
	for _, item := range svc.Observations(run.ID) {
		if item.Type == "protocol_response" && item.Value["protocol"] == "tns" && item.Value["server_version"] == "19.0.0.0.0" && item.Value["error_code"] == 12505 {
			return
		}
	}
	t.Fatal("tns protocol observation was not recorded")
}

func TestTNSPortHintDoesNotOverrideTheResponse(t *testing.T) {
	port := serveBytes(t, []byte("HTTP/1.0 200 OK\r\n\r\n"))
	restore := tnsProbeForPort
	tnsProbeForPort = func(candidate int) string {
		if candidate == port {
			return tnsprobe.Name
		}
		return ""
	}
	t.Cleanup(func() { tnsProbeForPort = restore })
	now := time.Date(2026, 11, 4, 13, 10, 0, 0, time.UTC)
	svc, err := New(t.TempDir(), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	grantID := approveTCPGrant(t, svc, "127.0.0.1", port, now)
	if _, err := svc.CreateScan(context.Background(), ScanInput{Name: "not-tns", Target: "127.0.0.1", Type: "ip", Ports: []int{port}, GrantID: grantID}); err != nil {
		t.Fatal(err)
	}
	finishRun(t, svc)
	for _, item := range svc.Hypotheses() {
		if item.ServiceType == "tns" {
			t.Fatalf("http response became tns: %+v", item)
		}
	}
}

func tnsReply() []byte {
	text := "(DESCRIPTION=(TMP=)(VSNNUM=318767104)(ERR=12505))"
	raw := make([]byte, 12+len(text))
	raw[4] = 4
	binary.BigEndian.PutUint16(raw[10:12], uint16(len(text)))
	copy(raw[12:], text)
	binary.BigEndian.PutUint16(raw[0:2], uint16(len(raw)))
	return raw
}
