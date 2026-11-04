package control

import (
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/zodirc/Vesper/internal/assess"
	"github.com/zodirc/Vesper/internal/id"
	"github.com/zodirc/Vesper/internal/scope"
)

func TestRestartRestoresRunAndFinding(t *testing.T) {
	dsn := os.Getenv("VESPER_TEST_DSN")
	if dsn == "" {
		t.Skip("VESPER_TEST_DSN is not set")
	}
	resetDatabase(t, dsn)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				_, _ = c.Read(buf)
				_, _ = io.WriteString(c, "HTTP/1.0 200 OK\r\nServer: nginx/1.24.0\r\nContent-Length: 2\r\n\r\nok")
			}(conn)
		}
	}()
	port := listener.Addr().(*net.TCPAddr).Port
	now := time.Date(2026, 11, 3, 1, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	migration := filepath.Join("..", "..", "migrations")
	evidence := t.TempDir()
	ctx := context.Background()
	first, err := Open(ctx, evidence, dsn, migration, clock)
	if err != nil {
		t.Fatal(err)
	}
	actor := id.MustNew()
	grant, err := first.CreateGrant(GrantInput{
		Name: "lab", SubjectType: "user",
		Selectors:  []SelectorInput{{Kind: "ip", Value: "127.0.0.1"}},
		Transports: []string{"tcp"}, Ports: []scope.PortRange{{Start: port, End: port}},
		Operations:          []string{scope.OpDiscovery, scope.OpConnect, scope.OpProtocolProbe, scope.OpConfigCheck},
		ObservationPointIDs: []id.ID{first.ObservationPointID()}, ValidFrom: now.Add(-time.Minute),
		MaxTargets: 4, MaxAddresses: 4, MaxConnections: 50, MaxRequests: 50, MaxConcurrency: 4,
		MaxRatePerSecond: 1000, MaxRuntimeSeconds: 60, MaxEvidenceBytes: 1 << 20,
	}, actor)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.ApproveGrant(grant.ID, actor); err != nil {
		t.Fatal(err)
	}
	if _, err := first.AddProduct("generic", "nginx", "generic:nginx", "nginx"); err != nil {
		t.Fatal(err)
	}
	if err := first.AddStatement(assess.Statement{
		VulnerabilityID: "CVE-2026-0001", Ecosystem: "generic", ProductKey: "generic:nginx",
		Ranges: []assess.Range{{Ecosystem: "generic", Start: "1.0.0", StartInclusive: true, End: "1.25.0", EndInclusive: true}},
	}); err != nil {
		t.Fatal(err)
	}
	run, err := first.CreateScan(ctx, ScanInput{Name: "local", Target: "127.0.0.1", Type: "ip", Ports: []int{port}, GrantID: grant.ID})
	if err != nil {
		t.Fatal(err)
	}
	first.Close()

	second, err := Open(ctx, evidence, dsn, migration, clock)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := second.Run(run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if restored.Status != "running" {
		t.Fatalf("restored status = %s", restored.Status)
	}
	if restored.IntelSnapshotID.IsZero() || restored.IntelSnapshotID != run.IntelSnapshotID {
		t.Fatalf("restored snapshot = %s, created snapshot = %s", restored.IntelSnapshotID, run.IntelSnapshotID)
	}
	if second.ObservationPointID() != first.ObservationPointID() {
		t.Fatalf("observation point changed across restart")
	}
	for i := 0; i < 20; i++ {
		worked, err := second.ExecuteAvailable(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if !worked {
			break
		}
	}
	finished, err := second.Run(run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if finished.Status != "completed" && finished.Status != "completed_with_errors" {
		t.Fatalf("status = %s failure=%s", finished.Status, finished.FailureSummary)
	}
	findings := second.Findings()
	if len(findings) != 1 || findings[0].VulnerabilityID != "CVE-2026-0001" {
		t.Fatalf("findings = %+v", findings)
	}
	second.Close()

	third, err := Open(ctx, evidence, dsn, migration, clock)
	if err != nil {
		t.Fatal(err)
	}
	defer third.Close()
	again, err := third.Run(run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if again.Status != finished.Status {
		t.Fatalf("reloaded status = %s, want %s", again.Status, finished.Status)
	}
	if len(third.Findings()) != 1 {
		t.Fatalf("reloaded findings = %+v", third.Findings())
	}
	var sawOpen bool
	for _, item := range third.Observations(run.ID) {
		state, _ := item.Value["state"].(string)
		if item.Type == "port_state" && state == "open" {
			sawOpen = true
		}
	}
	if !sawOpen {
		t.Fatal("reloaded observations do not include the open port")
	}
}

func TestPersistedBudgetDoesNotShrinkAcrossRestart(t *testing.T) {
	dsn := os.Getenv("VESPER_TEST_DSN")
	if dsn == "" {
		t.Skip("VESPER_TEST_DSN is not set")
	}
	resetDatabase(t, dsn)
	now := time.Date(2026, 11, 3, 1, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	ctx := context.Background()
	migration := filepath.Join("..", "..", "migrations")
	first, err := Open(ctx, t.TempDir(), dsn, migration, clock)
	if err != nil {
		t.Fatal(err)
	}
	actor := id.MustNew()
	grant, err := first.CreateGrant(GrantInput{
		Name: "budget", SubjectType: "user",
		Selectors:  []SelectorInput{{Kind: "ip", Value: "203.0.113.10"}},
		Transports: []string{"tcp"}, Ports: []scope.PortRange{{Start: 9, End: 9}},
		Operations: []string{scope.OpConnect}, ObservationPointIDs: []id.ID{first.ObservationPointID()},
		ValidFrom: now.Add(-time.Minute), MaxTargets: 2, MaxAddresses: 2, MaxConnections: 4,
		MaxRequests: 4, MaxConcurrency: 1, MaxRatePerSecond: 1000, MaxRuntimeSeconds: 60, MaxEvidenceBytes: 1000,
	}, actor)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.ApproveGrant(grant.ID, actor); err != nil {
		t.Fatal(err)
	}
	run, err := first.CreateScan(ctx, ScanInput{Name: "budget", Target: "203.0.113.10", Type: "ip", Ports: []int{9}, GrantID: grant.ID})
	if err != nil {
		t.Fatal(err)
	}
	account := first.accounts[run.ID]
	if account == nil {
		t.Fatal("budget ledger missing")
	}
	if err := account.AcquireConnection(ctx, now); err != nil {
		t.Fatal(err)
	}
	if err := first.persistBudget(ctx, run.ID); err != nil {
		t.Fatal(err)
	}
	account.RestoreUsage(scope.Usage{Started: now})
	if err := first.persistBudget(ctx, run.ID); err != nil {
		t.Fatal(err)
	}
	first.Close()
	second, err := Open(ctx, t.TempDir(), dsn, migration, clock)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	restored := second.accounts[run.ID]
	if restored == nil || restored.ExportUsage().Connections != 1 {
		t.Fatalf("restored budget = %+v", restored)
	}
}

func resetDatabase(t *testing.T, dsn string) {
	t.Helper()
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if _, err := pool.Exec(ctx, `DROP SCHEMA IF EXISTS public CASCADE`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `CREATE SCHEMA public`); err != nil {
		t.Fatal(err)
	}
}
