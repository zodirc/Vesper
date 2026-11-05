package control

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zodirc/Vesper/internal/assess"
	"github.com/zodirc/Vesper/internal/id"
	"github.com/zodirc/Vesper/internal/task"
)

func TestScheduledScanCatchesUpOnceAndSkipsOverlap(t *testing.T) {
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
				_, _ = io.Copy(io.Discard, c)
			}(conn)
		}
	}()
	port := listener.Addr().(*net.TCPAddr).Port
	current := time.Date(2026, 11, 5, 4, 0, 0, 0, time.UTC)
	svc, err := New(t.TempDir(), func() time.Time { return current })
	if err != nil {
		t.Fatal(err)
	}
	grantID := approveTCPGrant(t, svc, "127.0.0.1", port, current)
	missed := current.Add(-48 * time.Hour)
	schedule, err := svc.CreateSchedule(context.Background(), ScheduleInput{
		Name: "daily", TriggerType: "scheduled", IntervalSeconds: 3600, NextRunAt: &missed,
		GrantID: grantID, Target: "127.0.0.1", Type: "ip", Ports: []int{port},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ExecuteAvailable(context.Background()); err != nil {
		t.Fatal(err)
	}
	runs := runsByTrigger(svc, "scheduled")
	if len(runs) != 1 {
		t.Fatalf("runs after catch-up = %d", len(runs))
	}
	if runs[0].TriggerType != "scheduled" || !strings.Contains(string(runs[0].Plan), schedule.ID.String()) {
		t.Fatalf("run = %+v plan = %s", runs[0].TriggerType, runs[0].Plan)
	}
	stored := scheduleByID(t, svc, schedule.ID)
	if !stored.NextRunAt.Equal(current.Add(time.Hour)) || stored.LastResult != "created" || stored.LastRunID != runs[0].ID {
		t.Fatalf("schedule after catch-up = %+v", stored)
	}
	if _, err := svc.ExecuteAvailable(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(runsByTrigger(svc, "scheduled")) != 1 {
		t.Fatal("same tick created another run")
	}
	current = current.Add(time.Hour)
	if _, err := svc.ExecuteAvailable(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(runsByTrigger(svc, "scheduled")) != 1 {
		t.Fatal("overlap created another run")
	}
	if scheduleByID(t, svc, schedule.ID).LastResult != "overlap" {
		t.Fatalf("overlap result = %s", scheduleByID(t, svc, schedule.ID).LastResult)
	}
	for i := 0; i < 30; i++ {
		run, err := svc.Run(runs[0].ID)
		if err != nil {
			t.Fatal(err)
		}
		if run.Status == task.RunCompleted || run.Status == task.RunCompletedWithErrors || run.Status == task.RunFailed || run.Status == task.RunCancelled {
			break
		}
		if _, err := svc.ExecuteAvailable(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	current = scheduleByID(t, svc, schedule.ID).NextRunAt
	if _, err := svc.ExecuteAvailable(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(runsByTrigger(svc, "scheduled")) != 2 {
		t.Fatalf("second interval runs = %d", len(runsByTrigger(svc, "scheduled")))
	}
	if _, err := svc.DisableSchedule(context.Background(), schedule.ID); err != nil {
		t.Fatal(err)
	}
	current = scheduleByID(t, svc, schedule.ID).NextRunAt
	if _, err := svc.ExecuteAvailable(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(runsByTrigger(svc, "scheduled")) != 2 {
		t.Fatal("disabled schedule fired")
	}
}

func TestReassessmentScheduleRecordsRunWithoutCollection(t *testing.T) {
	current := time.Date(2026, 11, 5, 5, 0, 0, 0, time.UTC)
	svc, err := New(t.TempDir(), func() time.Time { return current })
	if err != nil {
		t.Fatal(err)
	}
	grantID := approveTCPGrant(t, svc, "127.0.0.1", 9, current)
	if err := svc.AddStatement(assess.Statement{
		VulnerabilityID: "CVE-2026-9001", Ecosystem: "generic", ProductKey: "generic:none", Severity: "low",
		Ranges: []assess.Range{{Ecosystem: "generic", Start: "1.0.0", StartInclusive: true, End: "2.0.0", EndInclusive: false}},
	}); err != nil {
		t.Fatal(err)
	}
	before := len(svc.observations)
	schedule, err := svc.CreateSchedule(context.Background(), ScheduleInput{
		Name: "rejudge", TriggerType: "reassessment", IntervalSeconds: 60, GrantID: grantID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreateSchedule(context.Background(), ScheduleInput{
		Name: "rejudge", TriggerType: "reassessment", IntervalSeconds: 60, GrantID: grantID, Target: "127.0.0.1", Type: "ip",
	}); err == nil {
		t.Fatal("reassessment accepted a target")
	}
	if _, err := svc.ExecuteAvailable(context.Background()); err != nil {
		t.Fatal(err)
	}
	runs := runsByTrigger(svc, "reassessment")
	if len(runs) != 1 || runs[0].Status != task.RunCompleted || len(runs[0].TargetIDs) != 0 {
		t.Fatalf("run = %+v targets = %d", runs[0].Status, len(runs[0].TargetIDs))
	}
	if !strings.Contains(string(runs[0].Plan), `"reassessment_added":0`) || !strings.Contains(string(runs[0].Plan), schedule.ID.String()) {
		t.Fatalf("plan = %s", runs[0].Plan)
	}
	_, units, err := svc.tasks.Snapshot(runs[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(units) != 0 {
		t.Fatalf("units = %d", len(units))
	}
	if len(svc.observations) != before {
		t.Fatalf("observations = %d, want %d", len(svc.observations), before)
	}
	if _, err := svc.ExecuteAvailable(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(runsByTrigger(svc, "reassessment")) != 1 {
		t.Fatal("same tick created another reassessment")
	}
	current = current.Add(time.Minute)
	if _, err := svc.ExecuteAvailable(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(runsByTrigger(svc, "reassessment")) != 2 {
		t.Fatal("second interval did not reassess")
	}
}

func TestScheduleRejectsInvalidIntervalAndInactiveGrant(t *testing.T) {
	current := time.Date(2026, 11, 5, 6, 0, 0, 0, time.UTC)
	svc, err := New(t.TempDir(), func() time.Time { return current })
	if err != nil {
		t.Fatal(err)
	}
	grantID := approveTCPGrant(t, svc, "127.0.0.1", 9, current)
	if _, err := svc.CreateSchedule(context.Background(), ScheduleInput{
		Name: "bad", TriggerType: "scheduled", IntervalSeconds: 0, GrantID: grantID, Target: "127.0.0.1", Type: "ip", Ports: []int{9},
	}); err == nil {
		t.Fatal("zero interval accepted")
	}
	schedule, err := svc.CreateSchedule(context.Background(), ScheduleInput{
		Name: "later", TriggerType: "scheduled", IntervalSeconds: 3600, GrantID: grantID,
		Target: "127.0.0.1", Type: "ip", Ports: []int{9},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.RevokeGrant(grantID, id.MustNew(), "stop"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ExecuteAvailable(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(runsByTrigger(svc, "scheduled")) != 0 {
		t.Fatal("revoked grant created a scan")
	}
	stored := scheduleByID(t, svc, schedule.ID)
	if stored.LastResult != "grant_not_active" || !stored.NextRunAt.Equal(current.Add(time.Hour)) {
		t.Fatalf("schedule = %+v", stored)
	}
	if _, err := svc.CreateSchedule(context.Background(), ScheduleInput{
		Name: "again", TriggerType: "scheduled", IntervalSeconds: 60, GrantID: grantID, Target: "127.0.0.1", Type: "ip", Ports: []int{9},
	}); err == nil {
		t.Fatal("revoked grant accepted a new schedule")
	}
}

func TestScheduleSurvivesRestart(t *testing.T) {
	dsn := os.Getenv("VESPER_TEST_DSN")
	if dsn == "" {
		t.Skip("VESPER_TEST_DSN is not set")
	}
	resetDatabase(t, dsn)
	current := time.Date(2026, 11, 5, 7, 0, 0, 0, time.UTC)
	clock := func() time.Time { return current }
	migration := filepath.Join("..", "..", "migrations")
	first, err := Open(context.Background(), t.TempDir(), dsn, migration, clock)
	if err != nil {
		t.Fatal(err)
	}
	grantID := approveTCPGrant(t, first, "127.0.0.1", 9, current)
	later := current.Add(24 * time.Hour)
	created, err := first.CreateSchedule(context.Background(), ScheduleInput{
		Name: "kept", TriggerType: "reassessment", IntervalSeconds: 86400, NextRunAt: &later, GrantID: grantID,
	})
	if err != nil {
		t.Fatal(err)
	}
	first.Close()
	second, err := Open(context.Background(), t.TempDir(), dsn, migration, clock)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	stored := scheduleByID(t, second, created.ID)
	if stored.Name != "kept" || stored.TriggerType != "reassessment" || stored.Status != "enabled" || !stored.NextRunAt.Equal(later) {
		raw, _ := json.Marshal(stored)
		t.Fatalf("restored = %s", raw)
	}
}

func runsByTrigger(svc *Service, trigger string) []task.Run {
	var out []task.Run
	for _, run := range svc.Runs() {
		if run.TriggerType == trigger {
			out = append(out, run)
		}
	}
	return out
}

func scheduleByID(t *testing.T, svc *Service, scheduleID id.ID) Schedule {
	t.Helper()
	for _, item := range svc.Schedules() {
		if item.ID == scheduleID {
			return item
		}
	}
	t.Fatalf("schedule %s missing", scheduleID)
	return Schedule{}
}
