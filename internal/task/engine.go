// Package task 维护 ScanRun、ScanUnit 和 StageAttempt 的状态迁移、租约和 fencing token。
// Package task maintains state transitions, leases, and fencing tokens for ScanRun, ScanUnit, and StageAttempt.
//
// 领取、递增 fencing token 和创建尝试在同一临界区内完成。终态单元不能重新打开。
// Claiming, incrementing the fencing token, and creating the attempt happen in one critical section. A terminal unit cannot be reopened.
package task

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/zodirc/Vesper/internal/id"
)

const (
	RunPending             = "pending"
	RunPlanning            = "planning"
	RunRunning             = "running"
	RunCancelling          = "cancelling"
	RunCompleted           = "completed"
	RunCompletedWithErrors = "completed_with_errors"
	RunFailed              = "failed"
	RunCancelled           = "cancelled"

	UnitQueued    = "queued"
	UnitLeased    = "leased"
	UnitRunning   = "running"
	UnitRetryWait = "retry_wait"
	UnitSucceeded = "succeeded"
	UnitFailed    = "failed"
	UnitCancelled = "cancelled"
	UnitSkipped   = "skipped"

	AttemptClaimed   = "claimed"
	AttemptRunning   = "running"
	AttemptSucceeded = "succeeded"
	AttemptRetryable = "retryable_error"
	AttemptFatal     = "fatal_error"
	AttemptCancelled = "cancelled"
	AttemptLeaseLost = "lease_lost"
)

var (
	// ErrNone 表示当前没有可领取的单元。
	// ErrNone means no unit is currently claimable.
	ErrNone = errors.New("no claimable unit")
	// ErrLeaseLost 表示租约或 fencing token 已经失效。
	// ErrLeaseLost means the lease or fencing token is no longer current.
	ErrLeaseLost = errors.New("lease lost")
	// ErrNotFound 表示运行或单元不存在。
	// ErrNotFound means the run or unit does not exist.
	ErrNotFound = errors.New("task object not found")
	// ErrConflict 表示状态迁移不被允许。
	// ErrConflict means the state transition is not allowed.
	ErrConflict = errors.New("invalid task transition")
	// ErrDuplicateStage 表示同一运行里已经存在相同阶段键。
	// ErrDuplicateStage means the same run already contains the stage key.
	ErrDuplicateStage = errors.New("duplicate stage")
)

// Run 是一次扫描运行的调度状态。
// Run is the scheduling state of one scan run.
type Run struct {
	ID           id.ID
	Name         string
	TargetIDs    []id.ID
	ScopeGrantID id.ID
	ScopeDigest  string
	// TriggerType 是运行触发方式：manual、scheduled、reassessment、verification。
	// TriggerType is how the run was triggered: manual, scheduled, reassessment, or verification.
	TriggerType string
	// EffectiveBudget 是创建时冻结的预算上限，不随执行消耗变化。
	// EffectiveBudget is the budget ceiling frozen at creation and does not change with consumption.
	EffectiveBudget        json.RawMessage
	ProbeProfileVersion    string
	FingerprintPackVersion string
	RulePackVersion        string
	ProductCatalogVersion  string
	// IntelSnapshotID 是创建运行时冻结的情报快照。后续导入不改变这次运行的评估输入。
	// IntelSnapshotID is the intelligence snapshot frozen when the run is created. A later import does not change this run's assessment input.
	IntelSnapshotID     id.ID
	ObservationPointIDs []id.ID
	Status              string
	ProgressTotal       int64
	ProgressDone        int64
	ProgressFailed      int64
	ProgressSkipped     int64
	FailureSummary      string
	CreatedAt           time.Time
	StartedAt           *time.Time
	FinishedAt          *time.Time
	CancelRequestedAt   *time.Time
	// Plan 保存规划输入，供 planning 中断后继续生成单元。创建任务时写入的观察点环境在后续更新允许地址时保留。
	// Plan stores the planning input so unit creation can continue after planning is interrupted. The observation-point environment written at task creation is kept when allowed addresses are updated later.
	Plan json.RawMessage
}

// Unit 是一次可领取的执行单元。
// Unit is one claimable execution unit.
type Unit struct {
	ID                   id.ID
	ScanRunID            id.ID
	TargetID             id.ID
	ObservationPointID   id.ID
	UnitType             string
	StageKey             string
	DependsOn            []id.ID
	RequiredCapabilities []string
	Input                json.RawMessage
	Status               string
	Priority             int
	AttemptCount         int
	MaxAttempts          int
	NotBefore            *time.Time
	LeaseID              id.ID
	LeaseOwnerID         id.ID
	LeaseExpiresAt       *time.Time
	FencingToken         int64
	TerminalReason       string
	ResultSummary        json.RawMessage
	CreatedAt            time.Time
	UpdatedAt            time.Time
}

// Attempt 是单元的一次执行尝试。
// Attempt is one execution attempt of a unit.
type Attempt struct {
	ID            id.ID
	ScanUnitID    id.ID
	AttemptNo     int
	WorkerID      id.ID
	LeaseID       id.ID
	FencingToken  int64
	Status        string
	StartedAt     *time.Time
	HeartbeatAt   *time.Time
	FinishedAt    *time.Time
	ErrorCode     string
	ErrorMessage  string
	ResourceUsage json.RawMessage
	ResultDigest  string
	CreatedAt     time.Time
}

// Lease 是领取成功后交给执行端的不可变凭证。
// Lease is the immutable credential returned to the executor after a successful claim.
type Lease struct {
	RunID              id.ID
	UnitID             id.ID
	AttemptID          id.ID
	LeaseID            id.ID
	FencingToken       int64
	WorkerID           id.ID
	UnitType           string
	StageKey           string
	TargetID           id.ID
	ObservationPointID id.ID
	Input              json.RawMessage
	ExpiresAt          time.Time
}

// Worker 是可以领取单元的执行节点。
// Worker is an execution node that can claim units.
type Worker struct {
	ID                 id.ID
	ObservationPointID id.ID
	Capabilities       map[string]struct{}
	Status             string
}

// Engine 在单进程临界区内实现领取和状态迁移。
// Engine implements claim and state transitions inside a single-process critical section.
type Engine struct {
	LeaseTTL time.Duration
	runs     map[id.ID]*Run
	units    map[id.ID]*Unit
	attempts map[id.ID]*Attempt
	order    map[id.ID][]id.ID
}

// NewEngine 创建空的任务引擎。
// NewEngine creates an empty task engine.
func NewEngine(leaseTTL time.Duration) *Engine {
	if leaseTTL <= 0 {
		leaseTTL = 30 * time.Second
	}
	return &Engine{
		LeaseTTL: leaseTTL,
		runs:     map[id.ID]*Run{},
		units:    map[id.ID]*Unit{},
		attempts: map[id.ID]*Attempt{},
		order:    map[id.ID][]id.ID{},
	}
}

// SetPlan 替换运行的计划快照。调用方必须已经持有服务锁。
// SetPlan replaces the run's plan snapshot. The caller must already hold the service lock.
func (e *Engine) SetPlan(runID id.ID, plan json.RawMessage) error {
	run, ok := e.runs[runID]
	if !ok {
		return ErrNotFound
	}
	run.Plan = append(json.RawMessage(nil), plan...)
	return nil
}

// CreateRun 保存处于 planning 状态的运行。
// CreateRun stores a run in the planning state.
func (e *Engine) CreateRun(run Run) error {
	if run.ID.IsZero() {
		return fmt.Errorf("create run: missing id")
	}
	run.Status = RunPlanning
	copied := run
	copied.Plan = append(json.RawMessage(nil), run.Plan...)
	copied.EffectiveBudget = append(json.RawMessage(nil), run.EffectiveBudget...)
	copied.TargetIDs = append([]id.ID(nil), run.TargetIDs...)
	copied.ObservationPointIDs = append([]id.ID(nil), run.ObservationPointIDs...)
	e.runs[run.ID] = &copied
	return nil
}

// CompleteWithoutUnits 把一次还没有单元的规划运行标为完成。
// CompleteWithoutUnits marks a planning run that has no units as completed.
//
// 再评估不拨号，因此没有扫描单元。开始和结束时间都取调用方给出的时刻。
// Reassessment does not dial, so it has no scan units. Both the start and finish times are the caller's timestamp.
func (e *Engine) CompleteWithoutUnits(runID id.ID, now time.Time) error {
	run, ok := e.runs[runID]
	if !ok {
		return ErrNotFound
	}
	if run.Status != RunPlanning {
		return ErrConflict
	}
	if len(e.order[runID]) != 0 {
		return fmt.Errorf("complete run %s: units already exist", runID)
	}
	stamp := now.UTC()
	run.Status = RunCompleted
	run.StartedAt = &stamp
	run.FinishedAt = &stamp
	return nil
}

// AddUnit 向同一次运行追加单元，并拒绝重复阶段键和依赖环。
// AddUnit appends a unit to the same run and rejects a duplicate stage key or a dependency cycle.
func (e *Engine) AddUnit(unit Unit) error {
	run, ok := e.runs[unit.ScanRunID]
	if !ok {
		return ErrNotFound
	}
	if run.Status != RunPlanning && run.Status != RunRunning {
		return ErrConflict
	}
	for _, existing := range e.order[unit.ScanRunID] {
		other := e.units[existing]
		if other.StageKey == unit.StageKey && other.TargetID == unit.TargetID && other.ObservationPointID == unit.ObservationPointID {
			return fmt.Errorf("add unit %s: %w", unit.StageKey, ErrDuplicateStage)
		}
	}
	for _, dep := range unit.DependsOn {
		parent, found := e.units[dep]
		if !found || parent.ScanRunID != unit.ScanRunID {
			return fmt.Errorf("add unit %s: dependency is outside the run", unit.StageKey)
		}
	}
	if unit.ID.IsZero() {
		var err error
		unit.ID, err = id.New()
		if err != nil {
			return err
		}
	}
	if unit.MaxAttempts <= 0 {
		unit.MaxAttempts = 3
	}
	unit.Status = UnitQueued
	unit.FencingToken = 0
	copied := unit
	e.units[unit.ID] = &copied
	e.order[unit.ScanRunID] = append(e.order[unit.ScanRunID], unit.ID)
	if cycle(e.units, unit.ID) {
		delete(e.units, unit.ID)
		e.order[unit.ScanRunID] = e.order[unit.ScanRunID][:len(e.order[unit.ScanRunID])-1]
		return fmt.Errorf("add unit %s: dependency cycle", unit.StageKey)
	}
	return nil
}

// MarkRunning 在计划生成完成后进入 running。
// MarkRunning enters running after planning completes.
func (e *Engine) MarkRunning(runID id.ID, now time.Time) error {
	run, ok := e.runs[runID]
	if !ok {
		return ErrNotFound
	}
	if run.Status != RunPlanning {
		return ErrConflict
	}
	run.Status = RunRunning
	stamp := now.UTC()
	run.StartedAt = &stamp
	e.recalculate(runID, now)
	return nil
}

// FailRun 把无法继续计划的运行标记为 failed。
// FailRun marks a run that cannot continue planning as failed.
func (e *Engine) FailRun(runID id.ID, summary string, now time.Time) error {
	run, ok := e.runs[runID]
	if !ok {
		return ErrNotFound
	}
	run.Status = RunFailed
	run.FailureSummary = summary
	stamp := now.UTC()
	run.FinishedAt = &stamp
	return nil
}

// Claim 领取一个依赖已成功、能力匹配且到达可执行时间的单元。
// Claim leases one unit whose dependencies have succeeded, whose capabilities match, and whose executable time has arrived.
func (e *Engine) Claim(now time.Time, worker Worker) (Lease, error) {
	if worker.Status != "online" {
		return Lease{}, ErrNone
	}
	now = now.UTC()
	e.skipBlocked(now)
	var selected *Unit
	for _, run := range e.runs {
		if run.Status != RunRunning {
			continue
		}
		for _, unitID := range e.order[run.ID] {
			unit := e.units[unitID]
			if !e.claimable(unit, now, worker) {
				continue
			}
			if selected == nil || unit.Priority < selected.Priority || (unit.Priority == selected.Priority && unit.CreatedAt.Before(selected.CreatedAt)) {
				selected = unit
			}
		}
	}
	if selected == nil {
		return Lease{}, ErrNone
	}
	leaseID, err := id.New()
	if err != nil {
		return Lease{}, err
	}
	attemptID, err := id.New()
	if err != nil {
		return Lease{}, err
	}
	selected.AttemptCount++
	selected.FencingToken++
	selected.Status = UnitLeased
	selected.LeaseID = leaseID
	selected.LeaseOwnerID = worker.ID
	expires := now.Add(e.LeaseTTL)
	selected.LeaseExpiresAt = &expires
	selected.UpdatedAt = now
	attempt := &Attempt{
		ID: attemptID, ScanUnitID: selected.ID, AttemptNo: selected.AttemptCount, WorkerID: worker.ID,
		LeaseID: leaseID, FencingToken: selected.FencingToken, Status: AttemptClaimed, CreatedAt: now,
	}
	e.attempts[attemptID] = attempt
	return Lease{
		RunID: selected.ScanRunID, UnitID: selected.ID, AttemptID: attemptID, LeaseID: leaseID,
		FencingToken: selected.FencingToken, WorkerID: worker.ID, UnitType: selected.UnitType,
		StageKey: selected.StageKey, TargetID: selected.TargetID, ObservationPointID: selected.ObservationPointID,
		Input: append(json.RawMessage(nil), selected.Input...), ExpiresAt: expires,
	}, nil
}

// Renew 在租约和 fencing token 仍然有效时延长租约。过期后不能再发起外部操作。
// Renew extends the lease while the lease and fencing token are still current. An expired lease cannot start another external operation.
func (e *Engine) Renew(lease Lease, now time.Time) error {
	unit, attempt, err := e.current(lease, now)
	if err != nil {
		return err
	}
	if unit.Status != UnitRunning && unit.Status != UnitLeased {
		return ErrConflict
	}
	now = now.UTC()
	expires := now.Add(e.LeaseTTL)
	unit.LeaseExpiresAt = &expires
	unit.UpdatedAt = now
	heartbeat := now
	attempt.HeartbeatAt = &heartbeat
	return nil
}

// Start 确认执行端已经开始处理租约。
// Start confirms that the executor has started processing the lease.
func (e *Engine) Start(lease Lease, now time.Time) error {
	unit, attempt, err := e.current(lease, now)
	if err != nil {
		return err
	}
	if unit.Status != UnitLeased {
		return ErrConflict
	}
	unit.Status = UnitRunning
	unit.UpdatedAt = now.UTC()
	stamp := now.UTC()
	attempt.Status = AttemptRunning
	attempt.StartedAt = &stamp
	return nil
}

// RecordOutcome 在租约仍然有效时写入本次尝试的实际消耗、逻辑结果摘要和单元当前结果摘要。
// RecordOutcome records this attempt's measured consumption, logical result digest, and the unit's current result summary while the lease is still valid.
//
// 连接数、请求数和证据字节数必须是本次尝试已经计入预算账本的差值。没有观察时 result_digest 为空，result_summary 仍记录观察数量。
// Connection, request, and evidence-byte counts must be the budget-ledger delta already charged to this attempt. result_digest stays empty when the attempt produced no observation, while result_summary still records the observation count.
func (e *Engine) RecordOutcome(lease Lease, connections, requests, evidenceBytes int64, summary json.RawMessage, digest string, now time.Time) error {
	unit, attempt, err := e.current(lease, now)
	if err != nil {
		return err
	}
	duration := int64(0)
	if attempt.StartedAt != nil {
		duration = now.UTC().Sub(attempt.StartedAt.UTC()).Milliseconds()
		if duration < 0 {
			duration = 0
		}
	}
	raw, err := json.Marshal(struct {
		Connections   int64 `json:"connections"`
		Requests      int64 `json:"requests"`
		EvidenceBytes int64 `json:"evidence_bytes"`
		DurationMS    int64 `json:"duration_ms"`
	}{connections, requests, evidenceBytes, duration})
	if err != nil {
		return err
	}
	attempt.ResourceUsage = raw
	attempt.ResultDigest = digest
	unit.ResultSummary = append(json.RawMessage(nil), summary...)
	return nil
}

// Succeed 在租约仍然有效时把单元标记为 succeeded。
// Succeed marks the unit succeeded while the lease is still valid.
func (e *Engine) Succeed(lease Lease, now time.Time) error {
	unit, attempt, err := e.current(lease, now)
	if err != nil {
		return err
	}
	if unit.Status != UnitRunning && unit.Status != UnitLeased {
		return ErrConflict
	}
	now = now.UTC()
	unit.Status = UnitSucceeded
	unit.LeaseID = id.ID{}
	unit.LeaseOwnerID = id.ID{}
	unit.LeaseExpiresAt = nil
	unit.UpdatedAt = now
	attempt.Status = AttemptSucceeded
	attempt.FinishedAt = &now
	e.recalculate(unit.ScanRunID, now)
	return nil
}

// Fail 记录一次失败。可重试失败在次数未耗尽时进入 retry_wait，否则进入 failed。
// Fail records one failure. A retryable failure enters retry_wait until attempts are exhausted, then enters failed.
func (e *Engine) Fail(lease Lease, retryable bool, code, message string, now time.Time) error {
	unit, attempt, err := e.current(lease, now)
	if err != nil {
		return err
	}
	now = now.UTC()
	attempt.ErrorCode = code
	attempt.ErrorMessage = message
	attempt.FinishedAt = &now
	unit.LeaseID = id.ID{}
	unit.LeaseOwnerID = id.ID{}
	unit.LeaseExpiresAt = nil
	unit.UpdatedAt = now
	if retryable && unit.AttemptCount < unit.MaxAttempts {
		unit.Status = UnitRetryWait
		wait := time.Second << (unit.AttemptCount - 1)
		if wait > 30*time.Second {
			wait = 30 * time.Second
		}
		next := now.Add(wait)
		unit.NotBefore = &next
		attempt.Status = AttemptRetryable
	} else {
		unit.Status = UnitFailed
		unit.TerminalReason = code
		attempt.Status = AttemptFatal
	}
	e.recalculate(unit.ScanRunID, now)
	return nil
}

// Expire 回收过期租约。旧凭证随后不能再提交结果。
// Expire reclaims expired leases. The old credential can no longer submit a result.
func (e *Engine) Expire(now time.Time) int {
	now = now.UTC()
	count := 0
	for _, unit := range e.units {
		if unit.LeaseExpiresAt == nil || unit.LeaseExpiresAt.After(now) {
			continue
		}
		if unit.Status != UnitLeased && unit.Status != UnitRunning {
			continue
		}
		for _, attempt := range e.attempts {
			if attempt.ScanUnitID == unit.ID && attempt.LeaseID == unit.LeaseID && attempt.FinishedAt == nil {
				attempt.Status = AttemptLeaseLost
				stamp := now
				attempt.FinishedAt = &stamp
			}
		}
		unit.LeaseID = id.ID{}
		unit.LeaseOwnerID = id.ID{}
		unit.LeaseExpiresAt = nil
		unit.UpdatedAt = now
		if unit.AttemptCount < unit.MaxAttempts {
			unit.Status = UnitRetryWait
			next := now
			unit.NotBefore = &next
		} else {
			unit.Status = UnitFailed
			unit.TerminalReason = "lease_lost"
		}
		count++
		e.recalculate(unit.ScanRunID, now)
	}
	return count
}

// Cancel 请求取消运行，并立即终态化尚未领取的单元。
// Cancel requests run cancellation and immediately finalizes units that have not been leased.
func (e *Engine) Cancel(runID id.ID, now time.Time) error {
	run, ok := e.runs[runID]
	if !ok {
		return ErrNotFound
	}
	if run.Status == RunCompleted || run.Status == RunCompletedWithErrors || run.Status == RunFailed || run.Status == RunCancelled {
		return ErrConflict
	}
	now = now.UTC()
	run.Status = RunCancelling
	run.CancelRequestedAt = &now
	for _, unitID := range e.order[runID] {
		unit := e.units[unitID]
		if unit.Status == UnitQueued || unit.Status == UnitRetryWait {
			unit.Status = UnitCancelled
			unit.TerminalReason = "cancelled"
			unit.UpdatedAt = now
		}
	}
	e.recalculate(runID, now)
	return nil
}

// MarkSkipped 把尚未执行的单元标记为 skipped。
// MarkSkipped marks a unit that has not executed as skipped.
func (e *Engine) MarkSkipped(unitID id.ID, reason string, now time.Time) error {
	unit, ok := e.units[unitID]
	if !ok {
		return ErrNotFound
	}
	if unit.Status != UnitQueued && unit.Status != UnitRetryWait {
		return ErrConflict
	}
	unit.Status = UnitSkipped
	unit.TerminalReason = reason
	unit.UpdatedAt = now.UTC()
	e.recalculate(unit.ScanRunID, now)
	return nil
}

// Snapshot 返回运行及其单元的副本。
// Snapshot returns copies of the run and its units.
func (e *Engine) Snapshot(runID id.ID) (Run, []Unit, error) {
	run, ok := e.runs[runID]
	if !ok {
		return Run{}, nil, ErrNotFound
	}
	copied := *run
	copied.Plan = append(json.RawMessage(nil), run.Plan...)
	copied.EffectiveBudget = append(json.RawMessage(nil), run.EffectiveBudget...)
	copied.TargetIDs = append([]id.ID(nil), run.TargetIDs...)
	copied.ObservationPointIDs = append([]id.ID(nil), run.ObservationPointIDs...)
	units := make([]Unit, 0, len(e.order[runID]))
	for _, unitID := range e.order[runID] {
		copied := *e.units[unitID]
		copied.ResultSummary = append(json.RawMessage(nil), e.units[unitID].ResultSummary...)
		units = append(units, copied)
	}
	return copied, units, nil
}

// Export 返回运行、单元和尝试的副本，供持久化写入。
// Export returns copies of runs, units, and attempts for durable storage.
func (e *Engine) Export() ([]Run, []Unit, []Attempt) {
	runs := make([]Run, 0, len(e.runs))
	for _, run := range e.runs {
		copied := *run
		copied.Plan = append(json.RawMessage(nil), run.Plan...)
		copied.EffectiveBudget = append(json.RawMessage(nil), run.EffectiveBudget...)
		copied.TargetIDs = append([]id.ID(nil), run.TargetIDs...)
		copied.ObservationPointIDs = append([]id.ID(nil), run.ObservationPointIDs...)
		runs = append(runs, copied)
	}
	units := make([]Unit, 0, len(e.units))
	for _, unit := range e.units {
		copied := *unit
		copied.DependsOn = append([]id.ID(nil), unit.DependsOn...)
		copied.RequiredCapabilities = append([]string(nil), unit.RequiredCapabilities...)
		copied.Input = append(json.RawMessage(nil), unit.Input...)
		copied.ResultSummary = append(json.RawMessage(nil), unit.ResultSummary...)
		units = append(units, copied)
	}
	attempts := make([]Attempt, 0, len(e.attempts))
	for _, attempt := range e.attempts {
		copied := *attempt
		copied.ResourceUsage = append(json.RawMessage(nil), attempt.ResourceUsage...)
		attempts = append(attempts, copied)
	}
	return runs, units, attempts
}

// Replace 用已持久化的任务状态替换内存副本。
// Replace substitutes the in-memory copy with persisted task state.
//
// 调用方必须已经持有服务锁。已有标识和状态原样保留，不会重新规划。
// The caller must already hold the service lock. Existing identifiers and statuses are kept and are not replanned.
func (e *Engine) Replace(runs []Run, units []Unit, attempts []Attempt) {
	e.runs = map[id.ID]*Run{}
	e.units = map[id.ID]*Unit{}
	e.attempts = map[id.ID]*Attempt{}
	e.order = map[id.ID][]id.ID{}
	for _, run := range runs {
		copied := run
		copied.Plan = append(json.RawMessage(nil), run.Plan...)
		copied.EffectiveBudget = append(json.RawMessage(nil), run.EffectiveBudget...)
		copied.TargetIDs = append([]id.ID(nil), run.TargetIDs...)
		copied.ObservationPointIDs = append([]id.ID(nil), run.ObservationPointIDs...)
		e.runs[run.ID] = &copied
	}
	sorted := append([]Unit(nil), units...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].CreatedAt.Equal(sorted[j].CreatedAt) {
			return sorted[i].ID.String() < sorted[j].ID.String()
		}
		return sorted[i].CreatedAt.Before(sorted[j].CreatedAt)
	})
	for _, unit := range sorted {
		copied := unit
		copied.DependsOn = append([]id.ID(nil), unit.DependsOn...)
		copied.RequiredCapabilities = append([]string(nil), unit.RequiredCapabilities...)
		copied.Input = append(json.RawMessage(nil), unit.Input...)
		copied.ResultSummary = append(json.RawMessage(nil), unit.ResultSummary...)
		e.units[unit.ID] = &copied
		e.order[unit.ScanRunID] = append(e.order[unit.ScanRunID], unit.ID)
	}
	for _, attempt := range attempts {
		copied := attempt
		copied.ResourceUsage = append(json.RawMessage(nil), attempt.ResourceUsage...)
		e.attempts[attempt.ID] = &copied
	}
}

func (e *Engine) current(lease Lease, now time.Time) (*Unit, *Attempt, error) {
	unit, ok := e.units[lease.UnitID]
	if !ok {
		return nil, nil, ErrNotFound
	}
	attempt, ok := e.attempts[lease.AttemptID]
	if !ok {
		return nil, nil, ErrNotFound
	}
	if unit.LeaseID != lease.LeaseID || unit.FencingToken != lease.FencingToken || unit.LeaseExpiresAt == nil || !unit.LeaseExpiresAt.After(now.UTC()) {
		return nil, nil, ErrLeaseLost
	}
	if attempt.FencingToken != lease.FencingToken || attempt.LeaseID != lease.LeaseID {
		return nil, nil, ErrLeaseLost
	}
	return unit, attempt, nil
}

func (e *Engine) claimable(unit *Unit, now time.Time, worker Worker) bool {
	if unit.ObservationPointID != worker.ObservationPointID {
		return false
	}
	switch unit.Status {
	case UnitQueued:
	case UnitRetryWait:
		if unit.NotBefore != nil && unit.NotBefore.After(now) {
			return false
		}
	default:
		return false
	}
	for _, capability := range unit.RequiredCapabilities {
		if _, ok := worker.Capabilities[capability]; !ok {
			return false
		}
	}
	for _, dep := range unit.DependsOn {
		parent := e.units[dep]
		if parent == nil || parent.Status != UnitSucceeded {
			return false
		}
	}
	return true
}

func (e *Engine) skipBlocked(now time.Time) {
	for _, unit := range e.units {
		if unit.Status != UnitQueued && unit.Status != UnitRetryWait {
			continue
		}
		blocked := false
		for _, depID := range unit.DependsOn {
			parent := e.units[depID]
			switch parent.Status {
			case UnitSucceeded:
			case UnitFailed, UnitCancelled, UnitSkipped:
				blocked = true
			default:
				blocked = false
				goto next
			}
		}
		if blocked {
			unit.Status = UnitSkipped
			unit.TerminalReason = "dependency_unsuccessful"
			unit.UpdatedAt = now
		}
	next:
	}
}

func (e *Engine) recalculate(runID id.ID, now time.Time) {
	run, ok := e.runs[runID]
	if !ok {
		return
	}
	var total, done, failed, skipped int64
	active := false
	for _, unitID := range e.order[runID] {
		unit := e.units[unitID]
		total++
		switch unit.Status {
		case UnitSucceeded, UnitFailed, UnitCancelled, UnitSkipped:
			done++
		default:
			active = true
		}
		if unit.Status == UnitFailed {
			failed++
		}
		if unit.Status == UnitSkipped {
			skipped++
		}
	}
	run.ProgressTotal = total
	run.ProgressDone = done
	run.ProgressFailed = failed
	run.ProgressSkipped = skipped
	if run.Status == RunPlanning || run.Status == RunPending || run.Status == RunFailed || run.Status == RunCancelled || run.Status == RunCompleted || run.Status == RunCompletedWithErrors {
		return
	}
	if active {
		if run.Status == RunCancelling {
			return
		}
		run.Status = RunRunning
		return
	}
	stamp := now.UTC()
	run.FinishedAt = &stamp
	switch {
	case run.Status == RunCancelling:
		run.Status = RunCancelled
	case failed > 0 || skipped > 0:
		run.Status = RunCompletedWithErrors
	default:
		run.Status = RunCompleted
	}
}

func cycle(units map[id.ID]*Unit, start id.ID) bool {
	visiting := map[id.ID]bool{}
	var walk func(id.ID) bool
	walk = func(current id.ID) bool {
		if visiting[current] {
			return true
		}
		visiting[current] = true
		unit := units[current]
		for _, dep := range unit.DependsOn {
			if walk(dep) {
				return true
			}
		}
		visiting[current] = false
		return false
	}
	return walk(start)
}
