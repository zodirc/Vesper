package control

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestZGrabUsesFixedCommandAndKeepsNativeProbes(t *testing.T) {
	now := time.Date(2026, 11, 5, 4, 0, 0, 0, time.UTC)
	svc, err := New(t.TempDir(), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	dir, err := os.MkdirTemp(".", ".zgrab-test-")
	if err != nil {
		t.Fatal(err)
	}
	dir, err = filepath.Abs(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	argsPath := filepath.Join(dir, "args")
	script := filepath.Join(dir, "zgrab2")
	body := "#!/bin/sh\nprintf '%s\\n' \"$@\" > " + argsPath + "\ncat >/dev/null\nprintf '%s\\n' '{\"ip\":\"127.0.0.1\",\"data\":{\"http\":{\"status\":\"success\",\"result\":{\"response\":{\"status_code\":200}}},\"tls\":{\"status\":\"success\",\"result\":{\"handshake_log\":{\"server_hello\":{\"version\":{\"name\":\"TLSv1.2\"}}}}}}}'\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VESPER_ZGRAB2", script)
	grantID := approveTCPGrant(t, svc, "127.0.0.1", port, now)
	run, err := svc.CreateScan(context.Background(), ScanInput{Name: "zgrab", Target: "127.0.0.1", Type: "ip", Ports: []int{port}, GrantID: grantID})
	if err != nil {
		t.Fatal(err)
	}
	finishRun(t, svc)
	args, err := os.ReadFile(argsPath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(args)
	if !strings.Contains(text, "--max-redirects=0") || !strings.Contains(text, "--no-http2") || strings.Contains(text, "heartbleed") || strings.Contains(text, "smtp") {
		t.Fatalf("args = %s", text)
	}
	var sawGrab, sawHTTP bool
	for _, item := range svc.Observations(run.ID) {
		if item.Type == "zgrab2" && item.ResultStatus == "observed" && item.Value["http_status"] == 200 && item.Value["tls_version"] == "TLSv1.2" && item.SourceKind == "network" {
			sawGrab = true
			if len(item.EvidenceIDs) != 1 {
				t.Fatalf("evidence = %+v", item.EvidenceIDs)
			}
		}
		if item.Type == "protocol_response" && item.Value["probe"] == "http" {
			sawHTTP = true
		}
	}
	if !sawGrab || !sawHTTP {
		t.Fatalf("observations = %+v", svc.Observations(run.ID))
	}
	for _, record := range svc.evidenceRows {
		if record.SourceModule == "zgrab2" && (record.EvidenceType != "tool_output" || record.IntegrityStatus != "verified" || record.Sensitivity != "internal") {
			t.Fatalf("evidence = %+v", record)
		}
	}
}

func TestZGrabMissingExecutorDoesNotDial(t *testing.T) {
	now := time.Date(2026, 11, 5, 4, 30, 0, 0, time.UTC)
	svc, err := New(t.TempDir(), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	t.Setenv("VESPER_ZGRAB2", filepath.Join(t.TempDir(), "missing-zgrab2"))
	grantID := approveTCPGrant(t, svc, "127.0.0.1", port, now)
	run, err := svc.CreateScan(context.Background(), ScanInput{Name: "zgrab-missing", Target: "127.0.0.1", Type: "ip", Ports: []int{port}, GrantID: grantID})
	if err != nil {
		t.Fatal(err)
	}
	finishRun(t, svc)
	var saw bool
	for _, item := range svc.Observations(run.ID) {
		if item.Type == "zgrab2" && item.ResultStatus == "unsupported" && item.Value["reason"] == "executor_missing" && len(item.EvidenceIDs) == 0 {
			saw = true
		}
	}
	if !saw {
		t.Fatalf("observations = %+v", svc.Observations(run.ID))
	}
	for _, record := range svc.evidenceRows {
		if record.SourceModule == "zgrab2" {
			t.Fatalf("missing executor stored evidence %+v", record)
		}
	}
}
