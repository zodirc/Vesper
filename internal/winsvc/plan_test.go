package winsvc

import (
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestPlanEnvironmentWritesAbsolutePathsAndRequiredValues(t *testing.T) {
	exe := filepath.Join(t.TempDir(), "vesperd")
	cwd := t.TempDir()
	values := map[string]string{
		"VESPER_ADMIN_USER":     "admin",
		"VESPER_ADMIN_PASSWORD": "secret",
		"VESPER_DATABASE_URL":   "postgres://db.internal/vesper",
		"VESPER_EVIDENCE_DIR":   "var/evidence",
		"VESPER_MIGRATION":      filepath.Join(cwd, "migrations"),
		"VESPER_NUCLEI":         filepath.Join(cwd, "nuclei"),
		"PATH":                  "/tmp/bin",
		"VESPER_ISOLATE_PROVE":  "1",
	}
	lines, err := PlanEnvironment(func(key string) string { return values[key] }, cwd, exe)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := filepath.Abs(filepath.Join(cwd, "var", "evidence"))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"VESPER_ADMIN_USER=admin",
		"VESPER_ADMIN_PASSWORD=secret",
		"VESPER_DATABASE_URL=postgres://db.internal/vesper",
		"VESPER_EVIDENCE_DIR=" + evidence,
		"VESPER_MIGRATION=" + filepath.Join(cwd, "migrations"),
		"VESPER_NUCLEI=" + filepath.Join(cwd, "nuclei"),
	}
	if len(lines) != len(want) {
		t.Fatalf("lines = %#v", lines)
	}
	for i := range want {
		if lines[i] != want[i] {
			t.Fatalf("line %d = %s, want %s", i, lines[i], want[i])
		}
	}
}

func TestPlanEnvironmentUsesExecutableDirectoryByDefault(t *testing.T) {
	root := t.TempDir()
	exe := filepath.Join(root, "bin", "vesperd")
	lines, err := PlanEnvironment(func(key string) string {
		switch key {
		case "VESPER_ADMIN_USER":
			return "admin"
		case "VESPER_ADMIN_PASSWORD":
			return "secret"
		case "VESPER_DATABASE_URL":
			return "postgres://db.internal/vesper"
		default:
			return ""
		}
	}, root, exe)
	if err != nil {
		t.Fatal(err)
	}
	if lines[3] != "VESPER_EVIDENCE_DIR="+filepath.Join(root, "bin", "var", "evidence") {
		t.Fatalf("evidence = %s", lines[3])
	}
	if lines[4] != "VESPER_MIGRATION="+filepath.Join(root, "bin", "migrations") {
		t.Fatalf("migration = %s", lines[4])
	}
}

func TestPlanEnvironmentRejectsIncompleteOrUnsafeValues(t *testing.T) {
	exe := filepath.Join(t.TempDir(), "vesperd")
	base := map[string]string{
		"VESPER_ADMIN_USER":     "admin",
		"VESPER_ADMIN_PASSWORD": "secret",
		"VESPER_DATABASE_URL":   "postgres://db.internal/vesper",
	}
	cases := []struct {
		name string
		key  string
		val  string
	}{
		{name: "missing password", key: "VESPER_ADMIN_PASSWORD", val: ""},
		{name: "newline", key: "VESPER_ADMIN_PASSWORD", val: "sec\nret"},
		{name: "nul", key: "VESPER_DATABASE_URL", val: "postgres\x00://db"},
		{name: "relative nuclei", key: "VESPER_NUCLEI", val: "nuclei"},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			values := map[string]string{}
			for key, value := range base {
				values[key] = value
			}
			values[item.key] = item.val
			if _, err := PlanEnvironment(func(key string) string { return values[key] }, t.TempDir(), exe); !errors.Is(err, ErrConfig) {
				t.Fatalf("err = %v", err)
			}
		})
	}
	if _, err := PlanEnvironment(func(string) string { return "x" }, t.TempDir(), "vesperd"); !errors.Is(err, ErrConfig) {
		t.Fatalf("relative executable err = %v", err)
	}
}

func TestRedactRemovesSecrets(t *testing.T) {
	got := Redact("dial postgres://db.internal/vesper failed for secret", []string{"", "secret", "postgres://db.internal/vesper"})
	if got != "dial *** failed for ***" {
		t.Fatalf("redacted = %s", got)
	}
	secrets := Secrets(func(key string) string {
		if key == "VESPER_ADMIN_PASSWORD" {
			return "secret"
		}
		return ""
	})
	if len(secrets) != 1 || secrets[0] != "secret" {
		t.Fatalf("secrets = %#v", secrets)
	}
}

func TestCommandsAndHostStub(t *testing.T) {
	if !KnownCommand("install") || !KnownCommand("uninstall") || !KnownCommand("start") || !KnownCommand("stop") || KnownCommand("run") {
		t.Fatal("command set mismatch")
	}
	if service, err := RunningAsService(); service || err != nil {
		t.Fatalf("service = %v err = %v", service, err)
	}
	if _, err := Execute("install"); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("execute err = %v", err)
	}
	if err := Run(nil); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("run err = %v", err)
	}
	if delays := RecoveryDelays(); len(delays) != 3 || delays[0] != 5*time.Second || delays[1] != 30*time.Second || delays[2] != 60*time.Second || RecoveryReset != 24*time.Hour {
		t.Fatalf("recovery = %v reset = %s", RecoveryDelays(), RecoveryReset)
	}
}
