package control

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/zodirc/Vesper/internal/probe/mysqlprobe"
)

func TestMySQLHandshakeIdentifiesTheProtocolWithoutAProduct(t *testing.T) {
	port := serveBytes(t, mysqlPacket("5.5.5-10.11.6-MariaDB"))
	restore := mysqlProbeForPort
	mysqlProbeForPort = func(candidate int) string {
		if candidate == port {
			return mysqlprobe.Name
		}
		return ""
	}
	t.Cleanup(func() { mysqlProbeForPort = restore })
	now := time.Date(2026, 11, 4, 11, 0, 0, 0, time.UTC)
	svc, err := New(t.TempDir(), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	grantID := approveTCPGrant(t, svc, "127.0.0.1", port, now)
	run, err := svc.CreateScan(context.Background(), ScanInput{Name: "mysql", Target: "127.0.0.1", Type: "ip", Ports: []int{port}, GrantID: grantID})
	if err != nil {
		t.Fatal(err)
	}
	finishRun(t, svc)
	var sawUnit bool
	_, units, _ := svc.tasks.Export()
	for _, unit := range units {
		if unit.ScanRunID == run.ID && unit.UnitType == "protocol_probe" && len(unit.RequiredCapabilities) == 1 && unit.RequiredCapabilities[0] == "protocol_mysql" {
			sawUnit = true
		}
	}
	if !sawUnit {
		t.Fatal("mysql probe was not scheduled")
	}
	var sawMySQL bool
	for _, item := range svc.Hypotheses() {
		if item.ServiceType == "mysql" && item.RawProductName == "" && item.RawVersion == "" && item.IdentityStatus == "unknown" && item.FingerprintPackVersion == "builtin-15" {
			sawMySQL = true
		}
		if item.ServiceType != "" && item.ServiceType != "mysql" {
			t.Fatalf("unexpected service %s", item.ServiceType)
		}
	}
	if !sawMySQL {
		t.Fatalf("hypotheses = %+v", svc.Hypotheses())
	}
	var sawEvidence bool
	for _, item := range svc.evidenceRows {
		if item.EvidenceType == "raw_response" && item.SourceModule == "mysqlprobe" && item.ContentType == "application/octet-stream" && item.ContentEncoding == "identity" && item.Sensitivity == "internal" && item.IntegrityStatus == "verified" && item.StoredAt != nil {
			sawEvidence = true
		}
	}
	if !sawEvidence {
		t.Fatalf("evidence = %+v", svc.evidenceRows)
	}
	for _, item := range svc.Observations(run.ID) {
		if item.Type == "protocol_response" && item.Value["protocol"] == "mysql" && item.Value["server_version"] == "5.5.5-10.11.6-MariaDB" && item.Value["protocol_version"] == 10 {
			return
		}
	}
	t.Fatal("mysql protocol observation was not recorded")
}

func TestMySQLPortHintDoesNotOverrideTheResponse(t *testing.T) {
	port := serveBytes(t, []byte("220 (vsFTPd 3.0.5)\r\n"))
	restore := mysqlProbeForPort
	mysqlProbeForPort = func(candidate int) string {
		if candidate == port {
			return mysqlprobe.Name
		}
		return ""
	}
	t.Cleanup(func() { mysqlProbeForPort = restore })
	now := time.Date(2026, 11, 4, 11, 20, 0, 0, time.UTC)
	svc, err := New(t.TempDir(), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	grantID := approveTCPGrant(t, svc, "127.0.0.1", port, now)
	if _, err := svc.CreateScan(context.Background(), ScanInput{Name: "not-mysql", Target: "127.0.0.1", Type: "ip", Ports: []int{port}, GrantID: grantID}); err != nil {
		t.Fatal(err)
	}
	finishRun(t, svc)
	for _, item := range svc.Hypotheses() {
		if item.ServiceType == "mysql" {
			t.Fatalf("ftp greeting became mysql: %+v", item)
		}
	}
}

func serveBytes(t *testing.T, payload []byte) int {
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
				_, _ = c.Write(payload)
			}(conn)
		}
	}()
	return listener.Addr().(*net.TCPAddr).Port
}

func mysqlPacket(version string) []byte {
	body := append([]byte{10}, []byte(version)...)
	body = append(body, 0, 1, 0, 0, 0)
	raw := []byte{byte(len(body)), byte(len(body) >> 8), byte(len(body) >> 16), 0}
	return append(raw, body...)
}
