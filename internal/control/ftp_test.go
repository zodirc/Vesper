package control

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/zodirc/Vesper/internal/id"
	"github.com/zodirc/Vesper/internal/probe/ftpprobe"
	"github.com/zodirc/Vesper/internal/scope"
)

func TestFTPGreetingIdentifiesTheServiceWithoutAProduct(t *testing.T) {
	port := serveGreeting(t, "220 (vsFTPd 3.0.5)\r\n")
	restore := ftpProbeForPort
	ftpProbeForPort = func(candidate int) string {
		if candidate == port {
			return ftpprobe.Name
		}
		return ""
	}
	t.Cleanup(func() { ftpProbeForPort = restore })
	now := time.Date(2026, 11, 4, 9, 0, 0, 0, time.UTC)
	svc, err := New(t.TempDir(), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	grantID := approveTCPGrant(t, svc, "127.0.0.1", port, now)
	run, err := svc.CreateScan(context.Background(), ScanInput{Name: "ftp", Target: "127.0.0.1", Type: "ip", Ports: []int{port}, GrantID: grantID})
	if err != nil {
		t.Fatal(err)
	}
	finishRun(t, svc)
	var sawUnit bool
	_, units, _ := svc.tasks.Export()
	for _, unit := range units {
		if unit.ScanRunID == run.ID && unit.UnitType == "protocol_probe" && unit.RequiredCapabilities[0] == "protocol_ftp" {
			sawUnit = true
		}
	}
	if !sawUnit {
		t.Fatal("ftp probe was not scheduled")
	}
	var sawFTP bool
	for _, item := range svc.Hypotheses() {
		if item.ServiceType == "ftp" && item.RawProductName == "" && item.RawVersion == "" && item.IdentityStatus == "unknown" && item.FingerprintPackVersion == "builtin-14" {
			sawFTP = true
		}
		if item.ServiceType != "" && item.ServiceType != "ftp" {
			t.Fatalf("unexpected service %s", item.ServiceType)
		}
	}
	if !sawFTP {
		t.Fatalf("hypotheses = %+v", svc.Hypotheses())
	}
	var sawEvidence bool
	for _, item := range svc.evidenceRows {
		if item.EvidenceType == "raw_response" && item.SourceModule == "ftpprobe" && item.ContentType == "text/plain" && item.ContentEncoding == "identity" && item.Sensitivity == "internal" && item.IntegrityStatus == "verified" && item.StoredAt != nil {
			sawEvidence = true
		}
	}
	if !sawEvidence {
		t.Fatalf("evidence = %+v", svc.evidenceRows)
	}
	for _, item := range svc.Observations(run.ID) {
		if item.Type == "protocol_response" && item.Value["protocol"] == "ftp" && item.Value["reply_code"] == "220" && item.Value["probe"] == "ftp" {
			return
		}
	}
	t.Fatal("ftp protocol observation was not recorded")
}

func TestFTPPortHintDoesNotOverrideTheResponse(t *testing.T) {
	port := serveGreeting(t, "HTTP/1.0 200 OK\r\nServer: nginx/1.24.0\r\nContent-Length: 0\r\n\r\n")
	restore := ftpProbeForPort
	ftpProbeForPort = func(candidate int) string {
		if candidate == port {
			return ftpprobe.Name
		}
		return ""
	}
	t.Cleanup(func() { ftpProbeForPort = restore })
	now := time.Date(2026, 11, 4, 9, 30, 0, 0, time.UTC)
	svc, err := New(t.TempDir(), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	grantID := approveTCPGrant(t, svc, "127.0.0.1", port, now)
	if _, err := svc.CreateScan(context.Background(), ScanInput{Name: "not-ftp", Target: "127.0.0.1", Type: "ip", Ports: []int{port}, GrantID: grantID}); err != nil {
		t.Fatal(err)
	}
	finishRun(t, svc)
	for _, item := range svc.Hypotheses() {
		if item.ServiceType == "ftp" {
			t.Fatalf("http response became ftp: %+v", item)
		}
	}
}

func serveGreeting(t *testing.T, greeting string) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.WriteString(c, greeting)
			}(conn)
		}
	}()
	return listener.Addr().(*net.TCPAddr).Port
}

func approveTCPGrant(t *testing.T, svc *Service, ip string, port int, now time.Time) id.ID {
	t.Helper()
	actor := id.MustNew()
	grant, err := svc.CreateGrant(GrantInput{
		Name: "ftp", SubjectType: "user",
		Selectors:  []SelectorInput{{Kind: "ip", Value: ip}},
		Transports: []string{"tcp"}, Ports: []scope.PortRange{{Start: port, End: port}},
		Operations:          []string{scope.OpDiscovery, scope.OpConnect, scope.OpProtocolProbe},
		ObservationPointIDs: []id.ID{svc.ObservationPointID()}, ValidFrom: now.Add(-time.Minute),
		MaxTargets: 2, MaxAddresses: 2, MaxConnections: 20, MaxRequests: 20, MaxConcurrency: 2,
		MaxRatePerSecond: 1000, MaxRuntimeSeconds: 60, MaxEvidenceBytes: 1 << 20,
	}, actor)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.ApproveGrant(grant.ID, actor); err != nil {
		t.Fatal(err)
	}
	return grant.ID
}
