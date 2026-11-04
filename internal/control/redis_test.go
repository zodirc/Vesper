package control

import (
	"context"
	"testing"
	"time"

	"github.com/zodirc/Vesper/internal/probe/redisprobe"
)

func TestRedisPingIdentifiesTheProtocolWithoutAProduct(t *testing.T) {
	port := serveBytes(t, []byte("+PONG\r\n"))
	restore := redisProbeForPort
	redisProbeForPort = func(candidate int) string {
		if candidate == port {
			return redisprobe.Name
		}
		return ""
	}
	t.Cleanup(func() { redisProbeForPort = restore })
	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	svc, err := New(t.TempDir(), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	grantID := approveTCPGrant(t, svc, "127.0.0.1", port, now)
	run, err := svc.CreateScan(context.Background(), ScanInput{Name: "redis", Target: "127.0.0.1", Type: "ip", Ports: []int{port}, GrantID: grantID})
	if err != nil {
		t.Fatal(err)
	}
	finishRun(t, svc)
	var sawUnit bool
	_, units, _ := svc.tasks.Export()
	for _, unit := range units {
		if unit.ScanRunID == run.ID && unit.UnitType == "protocol_probe" && len(unit.RequiredCapabilities) == 1 && unit.RequiredCapabilities[0] == "protocol_redis" {
			sawUnit = true
		}
	}
	if !sawUnit {
		t.Fatal("redis probe was not scheduled")
	}
	var sawRedis bool
	for _, item := range svc.Hypotheses() {
		if item.ServiceType == "redis" && item.RawProductName == "" && item.RawVersion == "" && item.IdentityStatus == "unknown" && item.FingerprintPackVersion == "builtin-14" {
			sawRedis = true
		}
		if item.ServiceType != "" && item.ServiceType != "redis" {
			t.Fatalf("unexpected service %s", item.ServiceType)
		}
	}
	if !sawRedis {
		t.Fatalf("hypotheses = %+v", svc.Hypotheses())
	}
	var sawEvidence bool
	for _, item := range svc.evidenceRows {
		if item.EvidenceType == "raw_response" && item.SourceModule == "redisprobe" && item.ContentType == "text/plain" && item.ContentEncoding == "identity" && item.Sensitivity == "internal" && item.IntegrityStatus == "verified" && item.StoredAt != nil {
			sawEvidence = true
		}
	}
	if !sawEvidence {
		t.Fatalf("evidence = %+v", svc.evidenceRows)
	}
	for _, item := range svc.Observations(run.ID) {
		if item.Type == "protocol_response" && item.Value["protocol"] == "redis" && item.Value["reply"] == "PONG" {
			return
		}
	}
	t.Fatal("redis protocol observation was not recorded")
}

func TestRedisPortHintDoesNotOverrideTheResponse(t *testing.T) {
	port := serveBytes(t, []byte("HTTP/1.0 200 OK\r\n\r\n"))
	restore := redisProbeForPort
	redisProbeForPort = func(candidate int) string {
		if candidate == port {
			return redisprobe.Name
		}
		return ""
	}
	t.Cleanup(func() { redisProbeForPort = restore })
	now := time.Date(2026, 11, 4, 12, 10, 0, 0, time.UTC)
	svc, err := New(t.TempDir(), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	grantID := approveTCPGrant(t, svc, "127.0.0.1", port, now)
	if _, err := svc.CreateScan(context.Background(), ScanInput{Name: "not-redis", Target: "127.0.0.1", Type: "ip", Ports: []int{port}, GrantID: grantID}); err != nil {
		t.Fatal(err)
	}
	finishRun(t, svc)
	for _, item := range svc.Hypotheses() {
		if item.ServiceType == "redis" {
			t.Fatalf("http response became redis: %+v", item)
		}
	}
}
