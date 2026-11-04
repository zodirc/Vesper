package activedetect

import (
	"net/netip"
	"os"
	"strings"
	"testing"
)

func mustIP(t *testing.T, value string) netip.Addr {
	t.Helper()
	addr, err := netip.ParseAddr(value)
	if err != nil {
		t.Fatal(err)
	}
	return addr
}

func TestAdmitAcceptsABoundedHTTPTemplate(t *testing.T) {
	got, err := Admit([]byte(exampleTemplate))
	if err != nil {
		t.Fatal(err)
	}
	if got.Key != "example-check" || got.Name != "Example" || got.Severity != "high" || got.CVE != "CVE-2024-0001" || got.RequestBound != 2 || got.Digest == "" {
		t.Fatalf("template = %+v", got)
	}
}

func TestAdmitRejectsUnboundedOrNonHTTPTemplates(t *testing.T) {
	cases := []string{
		"id: x\ninfo:\n  name: X\ncode:\n  - engine: sh\n",
		"id: x\ninfo:\n  name: X\nhttp:\n  - method: GET\n    path:\n      - \"{{BaseURL}}/{{interactsh-url}}\"\n",
		"id: x\ninfo:\n  name: X\nhttp:\n  - raw:\n      - \"GET / HTTP/1.1\"\n",
		"id: x\ninfo:\n  name: X\nhttp:\n  - method: GET\n    path:\n      - \"http://other.example/\"\n",
		"id: x\ninfo:\n  name: X\nhttp:\n  - method: GET\n    payloads:\n      q:\n        - a\n    path:\n      - \"{{BaseURL}}/{{q}}\"\n",
		"id: bad id\ninfo:\n  name: X\nhttp:\n  - path:\n      - \"{{BaseURL}}/a\"\n",
	}
	for _, body := range cases {
		if _, err := Admit([]byte(body)); err == nil {
			t.Fatalf("accepted %s", body)
		}
	}
}

func TestCommandLineUsesOnlyTheAuthorizedTarget(t *testing.T) {
	args, err := CommandLine("/usr/bin/nuclei", "/tmp/example-check.yaml", mustIP(t, "127.0.0.1"), 8080, "app.example", 25)
	if err != nil {
		t.Fatal(err)
	}
	text := strings.Join(args, "\n")
	for _, want := range []string{"/usr/bin/nuclei", "-t", "/tmp/example-check.yaml", "-u", "http://127.0.0.1:8080/", "-disable-redirects", "-no-interactsh", "-retries", "0", "-rate-limit", "25", "Host: app.example"} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %s in %s", want, text)
		}
	}
	if strings.Contains(text, "config") || strings.Contains(text, "-proxy") {
		t.Fatalf("args = %s", text)
	}
}

func TestParseOutputRejectsADifferentHost(t *testing.T) {
	output := []byte("{\"template-id\":\"example-check\",\"matcher-status\":true,\"matched-at\":\"http://192.0.2.9:8080/admin\"}\n")
	got, err := ParseOutput(output, "example-check", mustIP(t, "127.0.0.1"), 8080, "app.example")
	if err != nil || got.Status != "conflict" {
		t.Fatalf("verdict = %+v err = %v", got, err)
	}
	valid := []byte("{\"template-id\":\"example-check\",\"matcher-status\":true,\"matched-at\":\"http://127.0.0.1:8080/admin\"}\n")
	got, err = ParseOutput(valid, "example-check", mustIP(t, "127.0.0.1"), 8080, "app.example")
	if err != nil || got.Status != "confirmed" || got.MatchedAt == "" {
		t.Fatalf("verdict = %+v err = %v", got, err)
	}
	none, err := ParseOutput(nil, "example-check", mustIP(t, "127.0.0.1"), 8080, "")
	if err != nil || none.Status != "unknown" {
		t.Fatalf("none = %+v err = %v", none, err)
	}
}

func TestRulesetDropsUnlistedDestinations(t *testing.T) {
	policy := Policy{AllowedIP: mustIP(t, "203.0.113.10"), AllowedPort: 80}
	inside := namespaceOutputRuleset("abc", policy)
	if !strings.Contains(inside, "policy drop") || !strings.Contains(inside, "203.0.113.10") || strings.Contains(inside, "masquerade") {
		t.Fatalf("namespace rules = %s", inside)
	}
	host := hostRuleset("abc", policy, mustIP(t, "172.31.255.2"))
	if !strings.Contains(host, "203.0.113.10") || !strings.Contains(host, "drop") {
		t.Fatalf("host rules = %s", host)
	}
}

func TestIsolationStaysUnverifiedWithoutRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root may be able to prove isolation")
	}
	if Availability() != "not_verified" {
		t.Fatalf("availability = %s", Availability())
	}
}

const exampleTemplate = `id: example-check
info:
  name: Example
  severity: high
  classification:
    cve-id: CVE-2024-0001
http:
  - method:
      - GET
      - POST
    path:
      - "{{BaseURL}}/health"
    matchers:
      - type: word
        words:
          - ok
`
