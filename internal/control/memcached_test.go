package control

import (
	"context"
	"testing"
	"time"

	"github.com/zodirc/Vesper/internal/probe/memcachedprobe"
)

func TestMemcachedVersionIdentifiesTheProtocolWithoutAProduct(t *testing.T) {
	port := serveBytes(t, []byte("VERSION 1.6.22\r\n"))
	restore := memcachedProbeForPort
	memcachedProbeForPort = func(candidate int) string {
		if candidate == port {
			return memcachedprobe.Name
		}
		return ""
	}
	t.Cleanup(func() { memcachedProbeForPort = restore })
	now := time.Date(2026, 11, 4, 14, 0, 0, 0, time.UTC)
	svc, err := New(t.TempDir(), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	grantID := approveTCPGrant(t, svc, "127.0.0.1", port, now)
	run, err := svc.CreateScan(context.Background(), ScanInput{Name: "memcached", Target: "127.0.0.1", Type: "ip", Ports: []int{port}, GrantID: grantID})
	if err != nil {
		t.Fatal(err)
	}
	finishRun(t, svc)
	var sawUnit bool
	_, units, _ := svc.tasks.Export()
	for _, unit := range units {
		if unit.ScanRunID == run.ID && unit.UnitType == "protocol_probe" && len(unit.RequiredCapabilities) == 1 && unit.RequiredCapabilities[0] == "protocol_memcached" {
			sawUnit = true
		}
	}
	if !sawUnit {
		t.Fatal("memcached probe was not scheduled")
	}
	var sawMemcached bool
	for _, item := range svc.Hypotheses() {
		if item.ServiceType == "memcached" && item.RawProductName == "" && item.RawVersion == "" && item.IdentityStatus == "unknown" && item.FingerprintPackVersion == "builtin-15" {
			sawMemcached = true
		}
		if item.ServiceType != "" && item.ServiceType != "memcached" {
			t.Fatalf("unexpected service %s", item.ServiceType)
		}
	}
	if !sawMemcached {
		t.Fatalf("hypotheses = %+v", svc.Hypotheses())
	}
	var sawEvidence bool
	for _, item := range svc.evidenceRows {
		if item.EvidenceType == "raw_response" && item.SourceModule == "memcachedprobe" && item.ContentType == "text/plain" && item.ContentEncoding == "identity" && item.Sensitivity == "internal" && item.IntegrityStatus == "verified" && item.StoredAt != nil {
			sawEvidence = true
		}
	}
	if !sawEvidence {
		t.Fatalf("evidence = %+v", svc.evidenceRows)
	}
	for _, item := range svc.Observations(run.ID) {
		if item.Type == "protocol_response" && item.Value["protocol"] == "memcached" && item.Value["server_version"] == "1.6.22" {
			return
		}
	}
	t.Fatal("memcached protocol observation was not recorded")
}

func TestMemcachedPortHintDoesNotOverrideTheResponse(t *testing.T) {
	port := serveBytes(t, []byte("HTTP/1.0 200 OK\r\n\r\n"))
	restore := memcachedProbeForPort
	memcachedProbeForPort = func(candidate int) string {
		if candidate == port {
			return memcachedprobe.Name
		}
		return ""
	}
	t.Cleanup(func() { memcachedProbeForPort = restore })
	now := time.Date(2026, 11, 4, 14, 10, 0, 0, time.UTC)
	svc, err := New(t.TempDir(), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	grantID := approveTCPGrant(t, svc, "127.0.0.1", port, now)
	if _, err := svc.CreateScan(context.Background(), ScanInput{Name: "not-memcached", Target: "127.0.0.1", Type: "ip", Ports: []int{port}, GrantID: grantID}); err != nil {
		t.Fatal(err)
	}
	finishRun(t, svc)
	for _, item := range svc.Hypotheses() {
		if item.ServiceType == "memcached" {
			t.Fatalf("http response became memcached: %+v", item)
		}
	}
}
