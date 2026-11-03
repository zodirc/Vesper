package task

import (
	"testing"
	"time"

	"github.com/zodirc/Vesper/internal/id"
)

func TestRenewRejectsExpiredLease(t *testing.T) {
	engine := NewEngine(time.Second)
	now := time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC)
	runID := id.MustNew()
	if err := engine.CreateRun(Run{ID: runID, CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := engine.AddUnit(Unit{ScanRunID: runID, TargetID: id.MustNew(), ObservationPointID: id.MustNew(), UnitType: "port_scan", StageKey: "port_scan", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	point := engine.units[engine.order[runID][0]].ObservationPointID
	if err := engine.MarkRunning(runID, now); err != nil {
		t.Fatal(err)
	}
	worker := Worker{ID: id.MustNew(), ObservationPointID: point, Status: "online"}
	lease, err := engine.Claim(now, worker)
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.Start(lease, now); err != nil {
		t.Fatal(err)
	}
	renewed := now.Add(500 * time.Millisecond)
	if err := engine.Renew(lease, renewed); err != nil {
		t.Fatal(err)
	}
	if engine.attempts[lease.AttemptID].HeartbeatAt == nil || !engine.attempts[lease.AttemptID].HeartbeatAt.Equal(renewed.UTC()) {
		t.Fatalf("heartbeat = %v", engine.attempts[lease.AttemptID].HeartbeatAt)
	}
	if err := engine.Renew(lease, now.Add(2*time.Second)); err != ErrLeaseLost {
		t.Fatalf("renew err = %v", err)
	}
}

func TestExpiredLeaseCannotSubmitAndNextClaimUsesHigherToken(t *testing.T) {
	engine := NewEngine(time.Second)
	now := time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC)
	runID := id.MustNew()
	if err := engine.CreateRun(Run{ID: runID, CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := engine.AddUnit(Unit{ScanRunID: runID, TargetID: id.MustNew(), ObservationPointID: id.MustNew(), UnitType: "port_scan", StageKey: "port_scan", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	point := engine.units[engine.order[runID][0]].ObservationPointID
	if err := engine.MarkRunning(runID, now); err != nil {
		t.Fatal(err)
	}
	worker := Worker{ID: id.MustNew(), ObservationPointID: point, Status: "online"}
	lease, err := engine.Claim(now, worker)
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.Start(lease, now); err != nil {
		t.Fatal(err)
	}
	engine.Expire(now.Add(2 * time.Second))
	if err := engine.Succeed(lease, now.Add(2*time.Second)); err != ErrLeaseLost {
		t.Fatalf("succeed err = %v", err)
	}
	next, err := engine.Claim(now.Add(2*time.Second), worker)
	if err != nil {
		t.Fatal(err)
	}
	if next.FencingToken <= lease.FencingToken {
		t.Fatalf("token %d not greater than %d", next.FencingToken, lease.FencingToken)
	}
}

func TestDependencyCycleIsRejected(t *testing.T) {
	engine := NewEngine(time.Second)
	now := time.Now().UTC()
	runID := id.MustNew()
	if err := engine.CreateRun(Run{ID: runID, CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	first := id.MustNew()
	second := id.MustNew()
	point := id.MustNew()
	target := id.MustNew()
	if err := engine.AddUnit(Unit{ID: first, ScanRunID: runID, TargetID: target, ObservationPointID: point, StageKey: "a", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := engine.AddUnit(Unit{ID: second, ScanRunID: runID, TargetID: target, ObservationPointID: point, StageKey: "b", DependsOn: []id.ID{first}, CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	err := engine.AddUnit(Unit{ScanRunID: runID, TargetID: target, ObservationPointID: point, StageKey: "c", DependsOn: []id.ID{second}, CreatedAt: now})
	if err != nil {
		t.Fatal(err)
	}
	engine.units[first].DependsOn = []id.ID{second}
	if !cycle(engine.units, first) {
		t.Fatal("expected cycle")
	}
}
