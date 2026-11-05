package collect

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadProcessesKeepsCommandAndTruncatesTheCommandLine(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "12"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "12", "comm"), []byte("nginx\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cmdline := append([]byte("nginx\x00-g\x00"), bytesOf('a', cmdlineLimit+8)...)
	if err := os.WriteFile(filepath.Join(root, "12", "cmdline"), cmdline, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "12", "stat"), []byte("12 (ng)inx) S 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "self"), 0o755); err != nil {
		t.Fatal(err)
	}
	records, unreadable, err := ReadProcesses(root)
	if err != nil {
		t.Fatal(err)
	}
	if unreadable != 0 || len(records) != 1 || records[0]["pid"] != 12 || records[0]["command"] != "nginx" || records[0]["state"] != "S" || records[0]["cmdline_truncated"] != true {
		t.Fatalf("records = %+v unreadable = %d", records, unreadable)
	}
	if got := records[0]["cmdline"].(string); len(got) != cmdlineLimit || got[:8] != "nginx -g" {
		t.Fatalf("cmdline = %q", got)
	}
}

func TestServicePackageAndFirewallParsers(t *testing.T) {
	services := ParseServiceList("UNIT LOAD ACTIVE SUB DESCRIPTION\nsshd.service loaded active running OpenSSH\nbroken\n")
	if len(services) != 1 || services[0]["name"] != "sshd.service" || services[0]["active"] != "active" || services[0]["sub"] != "running" {
		t.Fatalf("services = %+v", services)
	}
	packages := ParseDpkgStatus("Package: nginx\nStatus: install ok installed\nVersion: 1.24.0-1\nArchitecture: amd64\n\nPackage: old\nStatus: deinstall ok config-files\nVersion: 1\n")
	if len(packages) != 1 || packages[0]["name"] != "nginx" || packages[0]["version"] != "1.24.0-1" || packages[0]["source"] != "dpkg" {
		t.Fatalf("packages = %+v", packages)
	}
	sourced := ParseDpkgStatus("Package: libssl3\nStatus: install ok installed\nSource: openssl (3.0.11-1)\nVersion: 3.0.11-1\nArchitecture: amd64\n")
	if len(sourced) != 1 || sourced[0]["source_package"] != "openssl" {
		t.Fatalf("source package = %+v", sourced)
	}
	rpm, err := ParseRPMQuery("bash\t0\t5.1.8\t9.el8\tx86_64\n\nbad line\n")
	if err == nil || rpm != nil {
		t.Fatalf("rpm = %+v err = %v", rpm, err)
	}
	rpm, err = ParseRPMQuery("bash\t0\t5.1.8\t9.el8\tx86_64\n")
	if err != nil || len(rpm) != 1 || rpm[0]["version"] != "5.1.8" || rpm[0]["source"] != "rpm" {
		t.Fatalf("rpm = %+v err = %v", rpm, err)
	}
	text, truncated := BoundText(string(bytesOf('x', textLimit+1)))
	if !truncated || len(text) != textLimit {
		t.Fatalf("bound = %d %v", len(text), truncated)
	}
}

func bytesOf(value byte, count int) []byte {
	out := make([]byte, count)
	for i := range out {
		out[i] = value
	}
	return out
}
