package control

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/zodirc/Vesper/internal/activedetect"
	"github.com/zodirc/Vesper/internal/id"
	"github.com/zodirc/Vesper/internal/scope"
)

const activeTemplateYAML = `id: example-check
info:
  name: Example
  severity: high
  classification:
    cve-id: CVE-2024-0001
http:
  - method: GET
    path:
      - "{{BaseURL}}/health"
`

func TestActiveTemplateRequiresReviewBeforeAScanUsesIt(t *testing.T) {
	svc := activeService(t)
	if _, err := svc.ImportActiveTemplate(context.Background(), []byte("id: x\ninfo:\n  name: X\ncode:\n  - engine: sh\n")); err == nil {
		t.Fatal("code template was accepted")
	}
	item, err := svc.ImportActiveTemplate(context.Background(), []byte(activeTemplateYAML))
	if err != nil {
		t.Fatal(err)
	}
	if item.Status != "validated" || item.Enabled || item.RequestBound != 1 || item.CVE != "CVE-2024-0001" {
		t.Fatalf("template = %+v", item)
	}
	run := activeScan(t, svc, false)
	if activeUnits(t, svc, run) != 0 {
		t.Fatal("unpublished template created an active-detection unit")
	}
}

func TestActiveDetectionSkipsWhenIsolationIsNotProven(t *testing.T) {
	svc := activeService(t)
	item, err := svc.ImportActiveTemplate(context.Background(), []byte(activeTemplateYAML))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.PublishActiveTemplate(context.Background(), item.ID); err != nil {
		t.Fatal(err)
	}
	called := false
	previous := runActiveDetection
	runActiveDetection = func(context.Context, activedetect.Policy, string, int, []activedetect.Template) ([]byte, error) {
		called = true
		return nil, errors.New("executor should not start")
	}
	t.Cleanup(func() { runActiveDetection = previous })
	run := activeScan(t, svc, true)
	if activeUnits(t, svc, run) != 1 {
		t.Fatalf("units = %d", activeUnits(t, svc, run))
	}
	if called {
		t.Fatal("executor started without isolation")
	}
	var skipped bool
	for _, item := range svc.detections {
		if item.Executor == "nuclei" && item.ResultStatus == "skipped" && item.VulnerabilityID == "CVE-2024-0001" {
			skipped = true
		}
	}
	if !skipped || len(svc.Findings()) != 0 {
		t.Fatalf("detections = %+v findings = %+v", svc.detections, svc.Findings())
	}
}

func TestValidatedNucleiMatchBecomesAFinding(t *testing.T) {
	svc := activeService(t)
	item, err := svc.ImportActiveTemplate(context.Background(), []byte(activeTemplateYAML))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.PublishActiveTemplate(context.Background(), item.ID); err != nil {
		t.Fatal(err)
	}
	previousReady := activeReady
	previousRun := runActiveDetection
	activeReady = func() error { return nil }
	t.Cleanup(func() {
		activeReady = previousReady
		runActiveDetection = previousRun
	})
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	runActiveDetection = func(context.Context, activedetect.Policy, string, int, []activedetect.Template) ([]byte, error) {
		return []byte(`{"template-id":"example-check","matcher-status":true,"matched-at":"http://127.0.0.1:` + itoa(port) + `/health"}` + "\n"), nil
	}
	go serveHTTP(listener)
	run := scanPort(t, svc, port, true)
	var confirmed bool
	for _, detection := range svc.detections {
		if detection.Executor == "nuclei" && detection.ResultStatus == "confirmed" && detection.Severity == "high" && len(detection.EvidenceIDs) == 1 {
			confirmed = true
		}
	}
	findings := svc.Findings()
	if !confirmed || len(findings) != 1 || findings[0].Title != "Example" || findings[0].Severity != "high" || findings[0].VulnerabilityID != "CVE-2024-0001" {
		t.Fatalf("detections = %+v findings = %+v run = %s", svc.detections, findings, run)
	}
	if svc.evidenceRows[len(svc.evidenceRows)-1].EvidenceType != "tool_output" || svc.evidenceRows[len(svc.evidenceRows)-1].IntegrityStatus != "verified" {
		t.Fatalf("evidence = %+v", svc.evidenceRows)
	}
}

func TestDisableStopsLaterScansButVerificationCanStillSelectTheTemplate(t *testing.T) {
	svc := activeService(t)
	item, err := svc.ImportActiveTemplate(context.Background(), []byte(activeTemplateYAML))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.PublishActiveTemplate(context.Background(), item.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.DisableActiveTemplate(context.Background(), item.ID); err != nil {
		t.Fatal(err)
	}
	run := activeScan(t, svc, true)
	if activeUnits(t, svc, run) != 0 {
		t.Fatal("disabled template was selected by a new scan")
	}
	svc.mu.Lock()
	denied, deniedErr := svc.selectActiveTemplates(scope.Grant{}, true, item.ID)
	allowed, allowedErr := svc.selectActiveTemplates(scope.Grant{AllowedOperations: []string{scope.OpActiveCheck}}, true, item.ID)
	svc.mu.Unlock()
	if deniedErr == nil || len(denied) != 0 {
		t.Fatalf("denied = %+v err = %v", denied, deniedErr)
	}
	var failure planFailure
	if !errors.As(deniedErr, &failure) || failure.summary != "operation_denied" {
		t.Fatalf("err = %v", deniedErr)
	}
	if allowedErr != nil || len(allowed) != 1 || allowed[0].Key != "example-check" {
		t.Fatalf("allowed = %+v err = %v", allowed, allowedErr)
	}
}

func TestClosedPortDoesNotScheduleActiveDetection(t *testing.T) {
	svc := activeService(t)
	item, err := svc.ImportActiveTemplate(context.Background(), []byte(activeTemplateYAML))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.PublishActiveTemplate(context.Background(), item.ID); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	run := scanPort(t, svc, port, true)
	if activeUnits(t, svc, run) != 0 {
		t.Fatal("active detection was scheduled without an HTTP observation")
	}
}

func TestInfoSeverityStaysOffTheFinding(t *testing.T) {
	if findingSeverity("info") != "" || findingSeverity("high") != "high" || findingSeverity("") != "" {
		t.Fatalf("info = %q high = %q", findingSeverity("info"), findingSeverity("high"))
	}
}

func TestNucleiOutputForAnotherHostDoesNotCreateAFinding(t *testing.T) {
	svc := activeService(t)
	item, err := svc.ImportActiveTemplate(context.Background(), []byte(activeTemplateYAML))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.PublishActiveTemplate(context.Background(), item.ID); err != nil {
		t.Fatal(err)
	}
	previousReady := activeReady
	previousRun := runActiveDetection
	activeReady = func() error { return nil }
	runActiveDetection = func(context.Context, activedetect.Policy, string, int, []activedetect.Template) ([]byte, error) {
		return []byte("{\"template-id\":\"example-check\",\"matcher-status\":true,\"matched-at\":\"http://192.0.2.9:80/health\"}\n"), nil
	}
	t.Cleanup(func() {
		activeReady = previousReady
		runActiveDetection = previousRun
	})
	run := activeScan(t, svc, true)
	if len(svc.Findings()) != 0 {
		t.Fatalf("findings = %+v", svc.Findings())
	}
	var conflict bool
	for _, detection := range svc.detections {
		if detection.Executor == "nuclei" && detection.ResultStatus == "conflict" {
			conflict = true
		}
	}
	if !conflict {
		t.Fatalf("detections = %+v run = %s", svc.detections, run)
	}
}

func activeService(t *testing.T) *Service {
	t.Helper()
	now := time.Date(2026, 11, 4, 1, 0, 0, 0, time.UTC)
	svc, err := New(t.TempDir(), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func activeScan(t *testing.T, svc *Service, allow bool) id.ID {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go serveHTTP(listener)
	return scanPort(t, svc, listener.Addr().(*net.TCPAddr).Port, allow)
}

func scanPort(t *testing.T, svc *Service, port int, allow bool) id.ID {
	t.Helper()
	operations := []string{scope.OpDiscovery, scope.OpConnect, scope.OpProtocolProbe}
	if allow {
		operations = append(operations, scope.OpActiveCheck)
	}
	now := time.Date(2026, 11, 4, 1, 0, 0, 0, time.UTC)
	grant, err := svc.CreateGrant(GrantInput{
		Name: "lab", SubjectType: "user", Selectors: []SelectorInput{{Kind: "ip", Value: "127.0.0.1"}},
		Transports: []string{"tcp"}, Ports: []scope.PortRange{{Start: port, End: port}}, Operations: operations,
		ObservationPointIDs: []id.ID{svc.ObservationPointID()}, ValidFrom: now.Add(-time.Minute),
		MaxTargets: 4, MaxAddresses: 4, MaxConnections: 40, MaxRequests: 40, MaxConcurrency: 4,
		MaxRatePerSecond: 1000, MaxRuntimeSeconds: 60, MaxEvidenceBytes: 1 << 20,
	}, id.MustNew())
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.ApproveGrant(grant.ID, id.MustNew()); err != nil {
		t.Fatal(err)
	}
	run, err := svc.CreateScan(context.Background(), ScanInput{Name: "local", Target: "127.0.0.1", Type: "ip", Ports: []int{port}, GrantID: grant.ID})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 30; i++ {
		worked, err := svc.ExecuteAvailable(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if !worked {
			break
		}
	}
	got, err := svc.Run(run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "completed" && got.Status != "completed_with_errors" {
		t.Fatalf("status = %s failure = %s", got.Status, got.FailureSummary)
	}
	return run.ID
}

func activeUnits(t *testing.T, svc *Service, runID id.ID) int {
	t.Helper()
	_, units, err := svc.tasks.Snapshot(runID)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, unit := range units {
		if unit.UnitType == "active_detection" {
			count++
		}
	}
	return count
}

func serveHTTP(listener net.Listener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			buf := make([]byte, 1024)
			_, _ = c.Read(buf)
			_, _ = io.WriteString(c, "HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok")
		}(conn)
	}
}

func itoa(value int) string {
	if value == 0 {
		return "0"
	}
	var digits []byte
	for value > 0 {
		digits = append([]byte{byte('0' + value%10)}, digits...)
		value /= 10
	}
	return string(digits)
}
