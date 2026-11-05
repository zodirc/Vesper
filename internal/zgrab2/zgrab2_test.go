package zgrab2

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCommandLinePinsHTTPAndTLS(t *testing.T) {
	ip := netip.MustParseAddr("203.0.113.10")
	args, stdin, err := CommandLine("/usr/bin/zgrab2", ip, 443, "app.example")
	if err != nil {
		t.Fatal(err)
	}
	if stdin != "203.0.113.10,app.example" {
		t.Fatalf("stdin = %s", stdin)
	}
	got := strings.Join(args, "\n")
	for _, want := range []string{
		"/usr/bin/zgrab2",
		"--senders=1",
		"--gomaxprocs=1",
		"--timeout=10",
		"http",
		"--port=443",
		"--method=GET",
		"--endpoint=/",
		"--user-agent=Vesper",
		"--max-size=4",
		"--max-redirects=0",
		"--no-http2",
		"tls",
		"--server-name=app.example",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %s in %s", want, got)
		}
	}
	for _, blocked := range []string{"heartbleed", "monlist", "ehlo", "password", "retry-https", "use-https", "smtp", "ssh", "smb", "telnet"} {
		if strings.Contains(strings.ToLower(got), blocked) {
			t.Fatalf("argument contains %s: %s", blocked, got)
		}
	}
	if _, stdin, err = CommandLine("/usr/bin/zgrab2", ip, 80, "bad host"); err != nil || stdin != "203.0.113.10" {
		t.Fatalf("stdin = %s err = %v", stdin, err)
	}
	if _, _, err = CommandLine("", ip, 80, ""); err == nil {
		t.Fatal("empty binary was accepted")
	}
}

func TestParseAcceptsOneMatchingTarget(t *testing.T) {
	raw := []byte(`{"ip":"203.0.113.10","data":{"http":{"status":"success","protocol":"http","result":{"response":{"status_code":200}}},"tls":{"status":"io-timeout","protocol":"tls","result":{}}}}`)
	report, err := Parse(raw, netip.MustParseAddr("203.0.113.10"))
	if err != nil {
		t.Fatal(err)
	}
	if ResultStatus(report.Modules) != "partial" {
		t.Fatalf("status = %s", ResultStatus(report.Modules))
	}
	if report.Modules[0].Name != "http" || report.Modules[0].HTTPStatus != 200 || report.Modules[1].Status != "io-timeout" {
		t.Fatalf("modules = %+v", report.Modules)
	}
	both := []byte(`{"ip":"203.0.113.10","data":{"http":{"status":"success","result":{"response":{"status_code":204}}},"tls":{"status":"success","result":{"handshake_log":{"server_hello":{"version":{"name":"TLSv1.2"}}}}}}}`)
	report, err = Parse(both, netip.MustParseAddr("203.0.113.10"))
	if err != nil || ResultStatus(report.Modules) != "observed" || report.Modules[1].TLSVersion != "TLSv1.2" {
		t.Fatalf("report = %+v err = %v", report, err)
	}
}

func TestParseRejectsScopeDrift(t *testing.T) {
	expect := netip.MustParseAddr("203.0.113.10")
	cases := []string{
		`{"ip":"198.51.100.8","data":{"http":{"status":"success"},"tls":{"status":"success"}}}`,
		`{"ip":"203.0.113.10","data":{"http":{"status":"success"},"tls":{"status":"success"},"smb":{"status":"success"}}}`,
		`{"ip":"203.0.113.10","data":{"http":{"status":"success"},"tls":{"status":"success"}}}
{"ip":"203.0.113.11","data":{"http":{"status":"success"},"tls":{"status":"success"}}}`,
		``,
	}
	for _, raw := range cases {
		if _, err := Parse([]byte(raw), expect); !errors.Is(err, ErrRejected) {
			t.Fatalf("err = %v raw = %s", err, raw)
		}
	}
	timedOut := []byte(`{"ip":"203.0.113.10","data":{"http":{"status":"connection-timeout"},"tls":{"status":"io-timeout"}}}`)
	report, err := Parse(timedOut, expect)
	if err != nil || ResultStatus(report.Modules) != "no_response" {
		t.Fatalf("report = %+v err = %v", report, err)
	}
}

func TestRunStopsOversizedOutputAndKeepsStderrPrefix(t *testing.T) {
	dir, err := os.MkdirTemp(".", ".zgrab-test-")
	if err != nil {
		t.Fatal(err)
	}
	dir, err = filepath.Abs(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	script := filepath.Join(dir, "zgrab2")
	body := "#!/bin/sh\nprintf '%s' 'too-long' >&2\nhead -c 300000 /dev/zero\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VESPER_ZGRAB2", script)
	_, raw, err := Run(context.Background(), netip.MustParseAddr("203.0.113.10"), 80, "")
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatal(err)
	}
	if len(raw) > maxOutputBytes {
		t.Fatalf("kept %d bytes", len(raw))
	}

	reject := filepath.Join(dir, "reject")
	rejectBody := "#!/bin/sh\nprintf '%s' 'dial refused' >&2\nprintf '%s\\n' 'not-json'\n"
	if err := os.WriteFile(reject, []byte(rejectBody), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VESPER_ZGRAB2", reject)
	_, _, err = Run(context.Background(), netip.MustParseAddr("203.0.113.10"), 80, "")
	if err == nil || !errors.Is(err, ErrRejected) || !strings.Contains(err.Error(), "dial refused") {
		t.Fatal(err)
	}
}
