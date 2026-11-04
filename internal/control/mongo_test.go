package control

import (
	"context"
	"encoding/binary"
	"testing"
	"time"

	"github.com/zodirc/Vesper/internal/probe/mongoprobe"
)

func TestMongoDBPingIdentifiesTheProtocolWithoutAProduct(t *testing.T) {
	port := serveBytes(t, mongoOKReply())
	restore := mongoProbeForPort
	mongoProbeForPort = func(candidate int) string {
		if candidate == port {
			return mongoprobe.Name
		}
		return ""
	}
	t.Cleanup(func() { mongoProbeForPort = restore })
	now := time.Date(2026, 11, 4, 12, 20, 0, 0, time.UTC)
	svc, err := New(t.TempDir(), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	grantID := approveTCPGrant(t, svc, "127.0.0.1", port, now)
	run, err := svc.CreateScan(context.Background(), ScanInput{Name: "mongodb", Target: "127.0.0.1", Type: "ip", Ports: []int{port}, GrantID: grantID})
	if err != nil {
		t.Fatal(err)
	}
	finishRun(t, svc)
	var sawUnit bool
	_, units, _ := svc.tasks.Export()
	for _, unit := range units {
		if unit.ScanRunID == run.ID && unit.UnitType == "protocol_probe" && len(unit.RequiredCapabilities) == 1 && unit.RequiredCapabilities[0] == "protocol_mongodb" {
			sawUnit = true
		}
	}
	if !sawUnit {
		t.Fatal("mongodb probe was not scheduled")
	}
	var sawMongoDB bool
	for _, item := range svc.Hypotheses() {
		if item.ServiceType == "mongodb" && item.RawProductName == "" && item.RawVersion == "" && item.IdentityStatus == "unknown" && item.FingerprintPackVersion == "builtin-14" {
			sawMongoDB = true
		}
		if item.ServiceType != "" && item.ServiceType != "mongodb" {
			t.Fatalf("unexpected service %s", item.ServiceType)
		}
	}
	if !sawMongoDB {
		t.Fatalf("hypotheses = %+v", svc.Hypotheses())
	}
	var sawEvidence bool
	for _, item := range svc.evidenceRows {
		if item.EvidenceType == "raw_response" && item.SourceModule == "mongodbprobe" && item.ContentType == "application/octet-stream" && item.ContentEncoding == "identity" && item.Sensitivity == "internal" && item.IntegrityStatus == "verified" && item.StoredAt != nil {
			sawEvidence = true
		}
	}
	if !sawEvidence {
		t.Fatalf("evidence = %+v", svc.evidenceRows)
	}
	for _, item := range svc.Observations(run.ID) {
		if item.Type == "protocol_response" && item.Value["protocol"] == "mongodb" && item.Value["reply"] == "ok" {
			return
		}
	}
	t.Fatal("mongodb protocol observation was not recorded")
}

func TestMongoDBPortHintDoesNotOverrideTheResponse(t *testing.T) {
	port := serveBytes(t, []byte("HTTP/1.0 200 OK\r\n\r\n"))
	restore := mongoProbeForPort
	mongoProbeForPort = func(candidate int) string {
		if candidate == port {
			return mongoprobe.Name
		}
		return ""
	}
	t.Cleanup(func() { mongoProbeForPort = restore })
	now := time.Date(2026, 11, 4, 12, 30, 0, 0, time.UTC)
	svc, err := New(t.TempDir(), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	grantID := approveTCPGrant(t, svc, "127.0.0.1", port, now)
	if _, err := svc.CreateScan(context.Background(), ScanInput{Name: "not-mongodb", Target: "127.0.0.1", Type: "ip", Ports: []int{port}, GrantID: grantID}); err != nil {
		t.Fatal(err)
	}
	finishRun(t, svc)
	for _, item := range svc.Hypotheses() {
		if item.ServiceType == "mongodb" {
			t.Fatalf("http response became mongodb: %+v", item)
		}
	}
}

func mongoOKReply() []byte {
	doc := []byte{
		0x11, 0x00, 0x00, 0x00,
		0x01, 'o', 'k', 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x3f,
		0x00,
	}
	raw := make([]byte, 21+len(doc))
	binary.LittleEndian.PutUint32(raw[0:], uint32(len(raw)))
	binary.LittleEndian.PutUint32(raw[8:], 1)
	binary.LittleEndian.PutUint32(raw[12:], 2013)
	copy(raw[21:], doc)
	return raw
}
