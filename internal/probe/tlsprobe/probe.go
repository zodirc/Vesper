// Package tlsprobe 对已授权 IP 执行 TLS 握手并提取证书事实，不把证书校验失败当成目标无响应。
// Package tlsprobe performs a TLS handshake to an authorized IP and extracts certificate facts. Certificate verification failure is not treated as no response.
package tlsprobe

import (
	"context"
	"crypto/tls"
	"net"
	"net/netip"
	"time"

	"github.com/zodirc/Vesper/pkg/probesdk"
)

// Result 是一次 TLS 握手观察。
// Result is one TLS handshake observation.
type Result struct {
	Version     string
	CipherSuite string
	PeerCerts   [][]byte
	Subject     string
	Issuer      string
	DNSNames    []string
	State       string
	Message     string
}

// Probe 连接指定 IP，并使用 hostname 作为 SNI。
// Probe connects to the given IP and uses hostname as SNI.
//
// 证书校验被关闭，因为探测目的是采集证书，不是建立可信会话。校验错误仍会保留已获得的握手信息。
// Certificate verification is disabled because the probe collects the certificate rather than establishing a trusted session. A verification error still preserves handshake information already obtained.
func Probe(ctx context.Context, dial probesdk.Dialer, budget interface {
	AcquireRequest(context.Context, time.Time) error
}, ip netip.Addr, port int, hostname string, now func() time.Time) (Result, error) {
	if err := budget.AcquireRequest(ctx, now()); err != nil {
		return Result{State: "not_scanned", Message: err.Error()}, err
	}
	conn, err := dial.DialTCP(ctx, ip, port, "protocol_probe")
	if err != nil {
		return Result{State: probesdk.Classify(err), Message: err.Error()}, err
	}
	defer conn.Close()
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         hostname,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
	})
	_ = tlsConn.SetDeadline(time.Now().Add(dial.Timeout))
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		state := tlsConn.ConnectionState()
		result := resultFromState(state)
		result.State = "error"
		result.Message = err.Error()
		return result, err
	}
	result := resultFromState(tlsConn.ConnectionState())
	result.State = "open"
	return result, nil
}

func resultFromState(state tls.ConnectionState) Result {
	result := Result{Version: tlsVersion(state.Version), CipherSuite: tls.CipherSuiteName(state.CipherSuite)}
	for _, cert := range state.PeerCertificates {
		result.PeerCerts = append(result.PeerCerts, append([]byte(nil), cert.Raw...))
	}
	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		result.Subject = cert.Subject.String()
		result.Issuer = cert.Issuer.String()
		result.DNSNames = append([]string(nil), cert.DNSNames...)
	}
	return result
}

func tlsVersion(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS1.0"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS13:
		return "TLS1.3"
	default:
		return ""
	}
}

// 保留 net 引用，便于在握手前确认底层连接类型。
var _ net.Conn = (*tls.Conn)(nil)
