package smtpprobe

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
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/zodirc/Vesper/internal/scope"
	"github.com/zodirc/Vesper/pkg/probesdk"
)

func TestProbeReadsTheGreetingAndSendsNoSMTPCommand(t *testing.T) {
	got, sent := servePlain(t, "220 mail.example.com ESMTP ready\r\n")
	if !got.IsSMTP || got.ReplyCode != "220" || got.Banner != "220 mail.example.com ESMTP ready" || got.State != "open" || len(sent) != 0 {
		t.Fatalf("result = %+v sent = %q", got, sent)
	}
	multiline, _ := servePlain(t, "220-mail.example.com ESMTP\r\n220 ready\r\n")
	if !multiline.IsSMTP || multiline.ReplyCode != "220" || multiline.Banner != "220-mail.example.com ESMTP" {
		t.Fatalf("multiline = %+v", multiline)
	}
	rejected, _ := servePlain(t, "554 smtp.example.com ESMTP not accepting\r\n")
	if !rejected.IsSMTP || rejected.ReplyCode != "554" {
		t.Fatalf("rejected = %+v", rejected)
	}
	folded, _ := servePlain(t, "220 host Esmtp service\r\n")
	if !folded.IsSMTP {
		t.Fatalf("case = %+v", folded)
	}
}

func TestProbeRejectsFTPAndGenericReplies(t *testing.T) {
	ftp, _ := servePlain(t, "220 (vsFTPd 3.0.5)\r\n")
	if ftp.IsSMTP || ftp.ReplyCode != "" || ftp.State != "open" {
		t.Fatalf("ftp = %+v", ftp)
	}
	bare, _ := servePlain(t, "554 Transaction failed\r\n")
	if bare.IsSMTP {
		t.Fatalf("bare = %+v", bare)
	}
	http, _ := servePlain(t, "HTTP/1.0 200 OK\r\n\r\n")
	if http.IsSMTP || !strings.HasPrefix(http.Banner, "HTTP/1.0") {
		t.Fatalf("http = %+v", http)
	}
}

func TestProbeStopsAtTheReadLimit(t *testing.T) {
	got, _ := servePlain(t, strings.Repeat("A", MaxBannerBytes+40))
	if got.IsSMTP || len(got.Raw) != MaxBannerBytes {
		t.Fatalf("len = %d smtp = %v", len(got.Raw), got.IsSMTP)
	}
}

func TestProbeReadsTheGreetingAfterTLS(t *testing.T) {
	got := serveTLS(t, "220 localhost ESMTP ready\r\n")
	if !got.IsSMTP || got.ReplyCode != "220" || got.Banner != "220 localhost ESMTP ready" {
		t.Fatalf("tls = %+v", got)
	}
}

func TestProbeForPortSelectsTheSMTPTransports(t *testing.T) {
	plain, ok := ProbeForPort(25)
	submission, submissionOK := ProbeForPort(587)
	secure, secureOK := ProbeForPort(465)
	_, other := ProbeForPort(21)
	_, high := ProbeForPort(2525)
	if !ok || plain != TransportPlain || !submissionOK || submission != TransportPlain || !secureOK || secure != TransportTLS || other || high {
		t.Fatalf("25=%s/%v 587=%s/%v 465=%s/%v 21=%v 2525=%v", plain, ok, submission, submissionOK, secure, secureOK, other, high)
	}
}

func servePlain(t *testing.T, greeting string) (Result, []byte) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	sent := make(chan []byte, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			sent <- nil
			return
		}
		defer conn.Close()
		_, _ = io.WriteString(conn, greeting)
		_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		buf := make([]byte, 64)
		n, _ := conn.Read(buf)
		sent <- append([]byte(nil), buf[:n]...)
	}()
	result, err := dialProbe(t, listener.Addr().(*net.TCPAddr).Port, TransportPlain)
	if err != nil {
		t.Fatal(err)
	}
	return result, <-sent
}

func serveTLS(t *testing.T, greeting string) Result {
	t.Helper()
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{testCertificate(t)}})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = io.WriteString(conn, greeting)
	}()
	result, err := dialProbe(t, listener.Addr().(*net.TCPAddr).Port, TransportTLS)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func dialProbe(t *testing.T, port int, transport string) (Result, error) {
	t.Helper()
	account := scope.NewAccount(scope.Budget{
		MaxTargets: 1, MaxAddresses: 1, MaxConnections: 2, MaxRequests: 2, MaxConcurrency: 1,
		MaxRatePerSecond: 1000, MaxRuntime: time.Minute, MaxEvidenceBytes: 10000,
	}, time.Now())
	dial := probesdk.Dialer{Auth: allow{}, Budget: account, Timeout: time.Second, Now: time.Now}
	return Probe(context.Background(), dial, account, netip.MustParseAddr("127.0.0.1"), port, "localhost", transport, time.Now)
}

func testCertificate(t *testing.T) tls.Certificate {
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

type allow struct{}

func (allow) Authorize(context.Context, netip.Addr, int, string, string) error { return nil }
