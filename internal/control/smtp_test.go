package control

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/zodirc/Vesper/internal/probe/smtpprobe"
)

func TestSMTPGreetingIdentifiesTheServiceWithoutAProduct(t *testing.T) {
	port := serveGreeting(t, "220 mail.example.com ESMTP ready\r\n")
	restore := smtpProbeForPort
	smtpProbeForPort = func(candidate int) (string, bool) {
		if candidate == port {
			return smtpprobe.TransportPlain, true
		}
		return "", false
	}
	t.Cleanup(func() { smtpProbeForPort = restore })
	now := time.Date(2026, 11, 4, 10, 0, 0, 0, time.UTC)
	svc, err := New(t.TempDir(), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	grantID := approveTCPGrant(t, svc, "127.0.0.1", port, now)
	run, err := svc.CreateScan(context.Background(), ScanInput{Name: "smtp", Target: "127.0.0.1", Type: "ip", Ports: []int{port}, GrantID: grantID})
	if err != nil {
		t.Fatal(err)
	}
	finishRun(t, svc)
	var sawUnit bool
	_, units, _ := svc.tasks.Export()
	for _, unit := range units {
		if unit.ScanRunID == run.ID && unit.UnitType == "protocol_probe" && len(unit.RequiredCapabilities) == 1 && unit.RequiredCapabilities[0] == "protocol_smtp" {
			sawUnit = true
		}
	}
	if !sawUnit {
		t.Fatal("smtp probe was not scheduled")
	}
	var sawSMTP bool
	for _, item := range svc.Hypotheses() {
		if item.ServiceType == "smtp" && item.RawProductName == "" && item.RawVersion == "" && item.IdentityStatus == "unknown" && item.FingerprintPackVersion == "builtin-15" {
			sawSMTP = true
		}
		if item.ServiceType != "" && item.ServiceType != "smtp" {
			t.Fatalf("unexpected service %s", item.ServiceType)
		}
	}
	if !sawSMTP {
		t.Fatalf("hypotheses = %+v", svc.Hypotheses())
	}
	var sawEvidence bool
	for _, item := range svc.evidenceRows {
		if item.EvidenceType == "raw_response" && item.SourceModule == "smtpprobe" && item.ContentType == "text/plain" && item.ContentEncoding == "identity" && item.Sensitivity == "internal" && item.IntegrityStatus == "verified" && item.StoredAt != nil {
			sawEvidence = true
		}
	}
	if !sawEvidence {
		t.Fatalf("evidence = %+v", svc.evidenceRows)
	}
	for _, item := range svc.Observations(run.ID) {
		if item.Type == "protocol_response" && item.Value["protocol"] == "smtp" && item.Value["reply_code"] == "220" && item.Value["probe"] == "smtp" {
			return
		}
	}
	t.Fatal("smtp protocol observation was not recorded")
}

func TestSMTPPortHintDoesNotOverrideTheResponse(t *testing.T) {
	port := serveGreeting(t, "220 (vsFTPd 3.0.5)\r\n")
	restore := smtpProbeForPort
	smtpProbeForPort = func(candidate int) (string, bool) {
		if candidate == port {
			return smtpprobe.TransportPlain, true
		}
		return "", false
	}
	t.Cleanup(func() { smtpProbeForPort = restore })
	now := time.Date(2026, 11, 4, 10, 20, 0, 0, time.UTC)
	svc, err := New(t.TempDir(), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	grantID := approveTCPGrant(t, svc, "127.0.0.1", port, now)
	if _, err := svc.CreateScan(context.Background(), ScanInput{Name: "not-smtp", Target: "127.0.0.1", Type: "ip", Ports: []int{port}, GrantID: grantID}); err != nil {
		t.Fatal(err)
	}
	finishRun(t, svc)
	for _, item := range svc.Hypotheses() {
		if item.ServiceType == "smtp" {
			t.Fatalf("ftp greeting became smtp: %+v", item)
		}
	}
}

func TestSMTPImplicitTLSGreetingIdentifiesTheService(t *testing.T) {
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{smtpTestCertificate(t)}})
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
				_, _ = io.WriteString(c, "220 localhost ESMTP ready\r\n")
			}(conn)
		}
	}()
	port := listener.Addr().(*net.TCPAddr).Port
	restore := smtpProbeForPort
	smtpProbeForPort = func(candidate int) (string, bool) {
		if candidate == port {
			return smtpprobe.TransportTLS, true
		}
		return "", false
	}
	t.Cleanup(func() { smtpProbeForPort = restore })
	now := time.Date(2026, 11, 4, 10, 40, 0, 0, time.UTC)
	svc, err := New(t.TempDir(), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	grantID := approveTCPGrant(t, svc, "127.0.0.1", port, now)
	run, err := svc.CreateScan(context.Background(), ScanInput{Name: "smtps", Target: "127.0.0.1", Type: "ip", Ports: []int{port}, GrantID: grantID})
	if err != nil {
		t.Fatal(err)
	}
	finishRun(t, svc)
	for _, item := range svc.Observations(run.ID) {
		if item.Type == "protocol_response" && item.Value["protocol"] == "smtp" && item.Value["reply_code"] == "220" {
			return
		}
	}
	t.Fatal("implicit TLS greeting was not recorded as smtp")
}

func smtpTestCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}
