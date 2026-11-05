package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/zodirc/Vesper/internal/asset"
	"github.com/zodirc/Vesper/internal/id"
	"github.com/zodirc/Vesper/internal/scope"
	"github.com/zodirc/Vesper/internal/task"
)

const (
	scheduleEnabled  = "enabled"
	scheduleDisabled = "disabled"
	// maxScheduleIntervalSeconds 是 10 年的秒数。更长的间隔会溢出时间加法。
	// maxScheduleIntervalSeconds is ten years in seconds. A longer interval overflows time addition.
	maxScheduleIntervalSeconds int64 = 10 * 365 * 24 * 60 * 60
	maxScheduleName                  = 200
	maxScheduleResult                = 180
)

// ErrScheduleNotFound 表示周期不存在。
// ErrScheduleNotFound means the schedule does not exist.
var ErrScheduleNotFound = errors.New("schedule not found")

var errIntelSnapshotMissing = errors.New("intel_snapshot_missing")

// ScheduleInput 是登记一个周期的输入。
// ScheduleInput is the input for registering one schedule.
//
// trigger_type 只能是 scheduled 或 reassessment。间隔是固定秒数。next_run_at 为空时用当前时间，下一次控制循环即可触发。
// trigger_type is scheduled or reassessment. The interval is a fixed number of seconds. An empty next_run_at uses the current time, so the next control loop can fire it.
type ScheduleInput struct {
	Name            string     `json:"name"`
	TriggerType     string     `json:"trigger_type"`
	IntervalSeconds int64      `json:"interval_seconds"`
	NextRunAt       *time.Time `json:"next_run_at,omitempty"`
	GrantID         id.ID      `json:"grant_id"`
	Target          string     `json:"target,omitempty"`
	Type            string     `json:"type,omitempty"`
	Transport       string     `json:"transport,omitempty"`
	Ports           []int      `json:"ports,omitempty"`
	Port            *int       `json:"port,omitempty"`
}

// Schedule 是一条持久化的周期。每次触发都新建运行，不复用上一次的目标或预算。
// Schedule is one persisted cadence. Each fire creates a new run and does not reuse the previous target set or budget.
type Schedule struct {
	ID              id.ID     `json:"id"`
	Name            string    `json:"name"`
	TriggerType     string    `json:"trigger_type"`
	Status          string    `json:"status"`
	IntervalSeconds int64     `json:"interval_seconds"`
	NextRunAt       time.Time `json:"next_run_at"`
	GrantID         id.ID     `json:"grant_id"`
	TargetType      string    `json:"target_type,omitempty"`
	TargetValue     string    `json:"target,omitempty"`
	Transport       string    `json:"transport,omitempty"`
	Port            *int      `json:"port,omitempty"`
	Ports           []int     `json:"ports,omitempty"`
	LastRunID       id.ID     `json:"last_run_id,omitempty"`
	LastResult      string    `json:"last_result,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// CreateSchedule 登记一个启用的周期。授权必须已经生效。
// CreateSchedule registers an enabled schedule. The grant must already be active.
//
// scheduled 保存和手工扫描相同的目标输入。reassessment 不接受目标或端口，触发时只重判已有事实。
// scheduled stores the same target input as a manual scan. reassessment accepts no target or port and only re-judges existing facts when it fires.
func (s *Service) CreateSchedule(ctx context.Context, input ScheduleInput) (Schedule, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	item, err := s.prepareSchedule(input)
	if err != nil {
		return Schedule{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.commitState(ctx, func() error {
		grant, ok := s.grants[item.GrantID]
		if !ok {
			return fmt.Errorf("create schedule: grant not found")
		}
		if grant.Status != scope.StatusActive {
			return fmt.Errorf("create schedule: grant status %s", grant.Status)
		}
		if s.schedules == nil {
			s.schedules = map[id.ID]Schedule{}
		}
		s.schedules[item.ID] = item
		return nil
	}); err != nil {
		return Schedule{}, err
	}
	return item, nil
}

// DisableSchedule 停用周期。已创建的运行继续执行，之后不再触发。
// DisableSchedule disables a schedule. A run already created continues, and later ticks do not fire.
func (s *Service) DisableSchedule(ctx context.Context, scheduleID id.ID) (Schedule, error) {
	return s.setScheduleStatus(ctx, scheduleID, scheduleDisabled)
}

// EnableSchedule 重新启用周期。下次时间仍落在过去时，下一次控制循环只补跑一次。
// EnableSchedule enables a schedule again. When the next time is still in the past, the next control loop catches up once.
func (s *Service) EnableSchedule(ctx context.Context, scheduleID id.ID) (Schedule, error) {
	return s.setScheduleStatus(ctx, scheduleID, scheduleEnabled)
}

// Schedules 返回周期副本，按下次时间和标识排序。
// Schedules returns schedule copies ordered by the next time and then the identifier.
func (s *Service) Schedules() []Schedule {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Schedule, 0, len(s.schedules))
	for _, item := range s.schedules {
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].NextRunAt.Equal(out[j].NextRunAt) {
			return out[i].NextRunAt.Before(out[j].NextRunAt)
		}
		return out[i].ID.String() < out[j].ID.String()
	})
	return out
}

func (s *Service) prepareSchedule(input ScheduleInput) (Schedule, error) {
	name := strings.TrimSpace(input.Name)
	if name == "" || len(name) > maxScheduleName {
		return Schedule{}, fmt.Errorf("create schedule: name is empty or longer than %d", maxScheduleName)
	}
	if input.TriggerType != "scheduled" && input.TriggerType != "reassessment" {
		return Schedule{}, fmt.Errorf("create schedule: trigger %s", input.TriggerType)
	}
	if input.IntervalSeconds < 1 || input.IntervalSeconds > maxScheduleIntervalSeconds {
		return Schedule{}, fmt.Errorf("create schedule: interval %d", input.IntervalSeconds)
	}
	if input.GrantID.IsZero() {
		return Schedule{}, fmt.Errorf("create schedule: grant is missing")
	}
	now := s.now().UTC()
	next := now
	if input.NextRunAt != nil {
		next = input.NextRunAt.UTC()
	}
	scheduleID, err := id.New()
	if err != nil {
		return Schedule{}, err
	}
	item := Schedule{
		ID: scheduleID, Name: name, TriggerType: input.TriggerType, Status: scheduleEnabled,
		IntervalSeconds: input.IntervalSeconds, NextRunAt: next, GrantID: input.GrantID,
		CreatedAt: now, UpdatedAt: now,
	}
	if input.TriggerType == "reassessment" {
		if strings.TrimSpace(input.Target) != "" || input.Type != "" || input.Transport != "" || len(input.Ports) > 0 || input.Port != nil {
			return Schedule{}, fmt.Errorf("create schedule: reassessment does not take a target")
		}
		return item, nil
	}
	target, err := asset.ParseTarget(input.Type, input.Target, input.Transport, input.Port, now)
	if err != nil {
		return Schedule{}, fmt.Errorf("create schedule: %w", err)
	}
	transport, err := scanTransport(input.Transport, target.Transport)
	if err != nil {
		return Schedule{}, fmt.Errorf("create schedule: %w", err)
	}
	ports := append([]int(nil), input.Ports...)
	if target.Port != nil {
		ports = []int{*target.Port}
	}
	if len(ports) == 0 {
		return Schedule{}, fmt.Errorf("create schedule: no ports")
	}
	item.TargetType = input.Type
	item.TargetValue = input.Target
	item.Transport = transport
	item.Ports = ports
	if input.Port != nil {
		port := *input.Port
		item.Port = &port
	}
	return item, nil
}

func (s *Service) setScheduleStatus(ctx context.Context, scheduleID id.ID, status string) (Schedule, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var item Schedule
	err := s.commitState(ctx, func() error {
		current, ok := s.schedules[scheduleID]
		if !ok {
			return ErrScheduleNotFound
		}
		current.Status = status
		current.UpdatedAt = s.now().UTC()
		s.schedules[scheduleID] = current
		item = current
		return nil
	})
	return item, err
}

func (s *Service) fireDueSchedules(ctx context.Context) error {
	s.mu.Lock()
	now := s.now().UTC()
	due := make([]id.ID, 0)
	for _, item := range s.schedules {
		if item.Status == scheduleEnabled && !now.Before(item.NextRunAt) {
			due = append(due, item.ID)
		}
	}
	s.mu.Unlock()
	if len(due) == 0 {
		return nil
	}
	sort.Slice(due, func(i, j int) bool { return due[i].String() < due[j].String() })
	for _, scheduleID := range due {
		if err := s.fireSchedule(ctx, scheduleID); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) fireSchedule(ctx context.Context, scheduleID id.ID) error {
	s.mu.Lock()
	if s.firing == nil {
		s.firing = map[id.ID]struct{}{}
	}
	if _, busy := s.firing[scheduleID]; busy {
		s.mu.Unlock()
		return nil
	}
	s.firing[scheduleID] = struct{}{}
	var item Schedule
	decision := "stale"
	err := s.commitState(ctx, func() error {
		if err := s.expireGrants(); err != nil {
			return err
		}
		current, ok := s.schedules[scheduleID]
		if !ok || current.Status != scheduleEnabled || s.now().UTC().Before(current.NextRunAt) {
			decision = "stale"
			return nil
		}
		item = current
		grant, found := s.grants[current.GrantID]
		reason := ""
		if !found || grant.Status != scope.StatusActive {
			reason = "grant_not_active"
		} else if s.scheduleBusy(scheduleID) {
			reason = "overlap"
		}
		if reason == "" {
			decision = "go"
			return nil
		}
		s.advanceSchedule(scheduleID, id.ID{}, reason)
		decision = "skipped"
		return nil
	})
	if err != nil || decision != "go" {
		delete(s.firing, scheduleID)
		s.mu.Unlock()
		return err
	}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.firing, scheduleID)
		s.mu.Unlock()
	}()

	var runID id.ID
	var fireErr error
	if item.TriggerType == "reassessment" {
		runID, fireErr = s.fireReassessment(ctx, item)
	} else {
		runID, fireErr = s.fireCollection(ctx, item)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	reason := "created"
	if fireErr != nil {
		reason = fireErr.Error()
	}
	return s.commitState(ctx, func() error {
		if _, ok := s.schedules[scheduleID]; !ok {
			return nil
		}
		recorded := id.ID{}
		if fireErr == nil || !runID.IsZero() {
			recorded = runID
		}
		if fireErr != nil && runID.IsZero() {
			recorded = id.ID{}
		}
		s.advanceSchedule(scheduleID, recorded, reason)
		return nil
	})
}

func (s *Service) advanceSchedule(scheduleID, runID id.ID, reason string) {
	current, ok := s.schedules[scheduleID]
	if !ok {
		return
	}
	now := s.now().UTC()
	current.NextRunAt = now.Add(time.Duration(current.IntervalSeconds) * time.Second)
	current.UpdatedAt = now
	current.LastResult = trimScheduleResult(reason)
	if !runID.IsZero() {
		current.LastRunID = runID
	}
	s.schedules[scheduleID] = current
}

func (s *Service) fireCollection(ctx context.Context, item Schedule) (id.ID, error) {
	now := s.now().UTC()
	target, err := asset.ParseTarget(item.TargetType, item.TargetValue, item.Transport, item.Port, now)
	if err != nil {
		return id.ID{}, err
	}
	ports := append([]int(nil), item.Ports...)
	if target.Port != nil {
		ports = []int{*target.Port}
	}
	run, err := s.startScan(ctx, preparedScan{
		Name: item.Name, Target: target, Transport: item.Transport, Ports: ports, GrantID: item.GrantID,
		Trigger: "scheduled", ScheduleID: item.ID,
	}, now)
	if err != nil {
		return run.ID, err
	}
	return run.ID, nil
}

func (s *Service) fireReassessment(ctx context.Context, item Schedule) (id.ID, error) {
	s.mu.Lock()
	snapshot := s.latestSnapshotID()
	s.mu.Unlock()
	if snapshot.IsZero() {
		return id.ID{}, errIntelSnapshotMissing
	}
	result, err := s.Reassess(ctx, snapshot, ReassessOptions{
		MaxAge: time.Duration(item.IntervalSeconds) * time.Second, GrantID: item.GrantID,
	})
	if err != nil {
		return id.ID{}, err
	}
	return s.recordReassessmentRun(ctx, item, snapshot, result)
}

func (s *Service) recordReassessmentRun(ctx context.Context, item Schedule, snapshot id.ID, result ReassessResult) (id.ID, error) {
	runID, err := id.New()
	if err != nil {
		return id.ID{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	err = s.commitState(ctx, func() error {
		grant, ok := s.grants[item.GrantID]
		if !ok {
			return fmt.Errorf("record reassessment: grant not found")
		}
		digest, err := grant.Digest()
		if err != nil {
			return err
		}
		count := result.Detections
		scans := result.Supplemental
		uncovered := result.Uncovered
		body, err := json.Marshal(planBody{
			ScheduleID: item.ID.String(), ReassessmentAdded: &count,
			SupplementalScans: &scans, SupplementalUncovered: &uncovered,
		})
		if err != nil {
			return err
		}
		budget, err := budgetSnapshot(grant)
		if err != nil {
			return err
		}
		now := s.now().UTC()
		run := versionedRun(task.Run{
			ID: runID, Name: item.Name, TargetIDs: []id.ID{}, ScopeGrantID: grant.ID, ScopeDigest: digest,
			TriggerType: "reassessment", EffectiveBudget: budget, IntelSnapshotID: snapshot,
			ObservationPointIDs: []id.ID{s.pointID}, CreatedAt: now, Plan: body,
		})
		if err := s.tasks.CreateRun(run); err != nil {
			return err
		}
		if err := s.tasks.CompleteWithoutUnits(runID, now); err != nil {
			return err
		}
		s.frozen[runID] = grant
		s.accounts[runID] = scope.NewAccount(scope.FromGrant(grant), now)
		return nil
	})
	if err != nil {
		return id.ID{}, err
	}
	return runID, nil
}

func (s *Service) scheduleBusy(scheduleID id.ID) bool {
	runs, _, _ := s.tasks.Export()
	for _, run := range runs {
		if scheduleIDFromPlan(run.Plan) != scheduleID {
			continue
		}
		switch run.Status {
		case task.RunCompleted, task.RunCompletedWithErrors, task.RunFailed, task.RunCancelled:
		default:
			return true
		}
	}
	return false
}

func scheduleIDFromPlan(raw json.RawMessage) id.ID {
	var body planBody
	if err := json.Unmarshal(raw, &body); err != nil || body.ScheduleID == "" {
		return id.ID{}
	}
	parsed, err := id.Parse(body.ScheduleID)
	if err != nil {
		return id.ID{}
	}
	return parsed
}

func trimScheduleResult(reason string) string {
	reason = strings.TrimSpace(reason)
	if len(reason) <= maxScheduleResult {
		return reason
	}
	return reason[:maxScheduleResult]
}
