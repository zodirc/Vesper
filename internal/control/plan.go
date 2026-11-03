package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/zodirc/Vesper/internal/asset"
	"github.com/zodirc/Vesper/internal/id"
	"github.com/zodirc/Vesper/internal/scope"
	"github.com/zodirc/Vesper/internal/task"
)

type planBody struct {
	Ports     []int    `json:"ports"`
	Transport string   `json:"transport"`
	Hostname  string   `json:"hostname"`
	Allowed   []string `json:"allowed_addresses,omitempty"`
}

type planFailure struct {
	summary string
}

func (e planFailure) Error() string { return e.summary }

// budgetSnapshot 保存创建扫描时的授权预算上限。当前没有单独的任务预算策略，因此快照就是授权上限。
// budgetSnapshot stores the grant budget ceiling at scan creation. There is no separate task budget policy, so the snapshot is the grant ceiling.
func budgetSnapshot(grant scope.Grant) ([]byte, error) {
	payload := struct {
		MaxTargets        int64   `json:"max_targets"`
		MaxAddresses      int64   `json:"max_addresses"`
		MaxConnections    int64   `json:"max_connections"`
		MaxRequests       int64   `json:"max_requests"`
		MaxConcurrency    int     `json:"max_concurrency"`
		MaxRatePerSecond  float64 `json:"max_rate_per_second"`
		MaxRuntimeSeconds int64   `json:"max_runtime_seconds"`
		MaxEvidenceBytes  int64   `json:"max_evidence_bytes"`
	}{
		MaxTargets: grant.MaxTargets, MaxAddresses: grant.MaxAddresses, MaxConnections: grant.MaxConnections,
		MaxRequests: grant.MaxRequests, MaxConcurrency: grant.MaxConcurrency, MaxRatePerSecond: grant.MaxRatePerSecond,
		MaxRuntimeSeconds: int64(grant.MaxRuntime / time.Second), MaxEvidenceBytes: grant.MaxEvidenceBytes,
	}
	return json.Marshal(payload)
}

// CreateScan 先提交 planning 运行，再解析地址并生成执行单元。
// CreateScan first commits a planning run, then resolves addresses and creates execution units.
//
// 域名解析被取消或超时时，运行保持 planning，后续领取可以继续。已经判定的计划失败会把该运行标为 failed。
// When hostname resolution is canceled or times out, the run stays planning and a later claim can continue it. A decided planning failure marks that run failed.
func (s *Service) CreateScan(ctx context.Context, input ScanInput) (task.Run, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	now := s.now().UTC()
	target, err := asset.ParseTarget(input.Type, input.Target, input.Transport, input.Port, now)
	if err != nil {
		return task.Run{}, err
	}
	runID, err := id.New()
	if err != nil {
		return task.Run{}, err
	}
	s.mu.Lock()
	err = s.commitState(ctx, func() error {
		grant, ok := s.grants[input.GrantID]
		if !ok {
			return fmt.Errorf("create scan: grant not found")
		}
		if grant.Status != scope.StatusActive {
			return fmt.Errorf("create scan: grant status %s", grant.Status)
		}
		ports := append([]int(nil), input.Ports...)
		if target.Port != nil {
			ports = []int{*target.Port}
		}
		if len(ports) == 0 {
			return fmt.Errorf("create scan: no ports")
		}
		digest, err := grant.Digest()
		if err != nil {
			return err
		}
		body, err := json.Marshal(planBody{Ports: ports, Transport: "tcp", Hostname: target.Hostname})
		if err != nil {
			return err
		}
		budget, err := budgetSnapshot(grant)
		if err != nil {
			return err
		}
		s.catalog.AddTarget(target)
		run := versionedRun(task.Run{
			ID: runID, Name: input.Name, TargetIDs: []id.ID{target.ID}, ScopeGrantID: grant.ID, ScopeDigest: digest,
			TriggerType: "manual", EffectiveBudget: budget, IntelSnapshotID: s.latestSnapshotID(),
			ObservationPointIDs: []id.ID{s.pointID}, CreatedAt: now, Plan: body,
		})
		if err := s.tasks.CreateRun(run); err != nil {
			return err
		}
		s.frozen[runID] = grant
		return nil
	})
	s.mu.Unlock()
	if err != nil {
		return task.Run{}, err
	}
	if err := s.finishPlanning(ctx, runID, now); err != nil {
		var failed planFailure
		if errors.As(err, &failed) {
			return s.failPlanning(runID, failed.Error(), now)
		}
		s.mu.Lock()
		run, _, snapErr := s.tasks.Snapshot(runID)
		s.mu.Unlock()
		if snapErr != nil {
			return task.Run{}, err
		}
		return run, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	run, _, err := s.tasks.Snapshot(runID)
	return run, err
}

func (s *Service) resumePlanning(ctx context.Context) error {
	s.mu.Lock()
	runs, _, _ := s.tasks.Export()
	var pending []id.ID
	for _, run := range runs {
		if run.Status == task.RunPlanning {
			pending = append(pending, run.ID)
		}
	}
	s.mu.Unlock()
	now := s.now().UTC()
	for _, runID := range pending {
		err := s.finishPlanning(ctx, runID, now)
		var failed planFailure
		if errors.As(err, &failed) {
			if _, failErr := s.failPlanning(runID, failed.Error(), now); failErr != nil {
				return failErr
			}
			continue
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) finishPlanning(ctx context.Context, runID id.ID, now time.Time) error {
	s.mu.Lock()
	run, _, err := s.tasks.Snapshot(runID)
	if err != nil {
		s.mu.Unlock()
		return err
	}
	if run.Status != task.RunPlanning {
		s.mu.Unlock()
		return nil
	}
	if len(run.TargetIDs) != 1 {
		s.mu.Unlock()
		return fmt.Errorf("planning: target missing")
	}
	target, ok := s.catalog.Targets[run.TargetIDs[0]]
	grant, granted := s.frozen[runID]
	planBytes := append([]byte(nil), run.Plan...)
	s.mu.Unlock()
	if !ok || !granted {
		return fmt.Errorf("planning: target or grant missing")
	}
	var plan planBody
	if err := json.Unmarshal(planBytes, &plan); err != nil {
		return fmt.Errorf("planning: %w", err)
	}
	if plan.Transport == "" {
		plan.Transport = "tcp"
	}
	if len(plan.Ports) == 0 {
		return planFailure{summary: "no ports"}
	}
	addresses, err := s.planAddresses(ctx, runID, target, grant, plan, now)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.commitState(ctx, func() error {
		return s.installPlan(runID, target, addresses, plan, now)
	})
}

func (s *Service) planAddresses(ctx context.Context, runID id.ID, target asset.Target, grant scope.Grant, plan planBody, now time.Time) ([]netip.Addr, error) {
	addresses, err := asset.Expand(target, grant.MaxAddresses)
	if err != nil {
		return nil, planFailure{summary: err.Error()}
	}
	if target.TargetType == "hostname" {
		resolution, resolveErr := s.resolver(ctx, target.Hostname)
		if resolveErr != nil {
			if ctx.Err() != nil || errors.Is(resolveErr, context.Canceled) || errors.Is(resolveErr, context.DeadlineExceeded) {
				return nil, resolveErr
			}
			return nil, planFailure{summary: resolveErr.Error()}
		}
		if err := s.recordResolution(runID, target.Hostname, resolution, now); err != nil {
			return nil, err
		}
		addresses = resolution.Addresses
	}
	var allowed []netip.Addr
	for _, addr := range addresses {
		decision := grant.Check(scope.CheckInput{
			IP: addr, Hostname: target.Hostname, ResolvedFromGrant: target.TargetType == "hostname",
			Port: plan.Ports[0], Transport: plan.Transport, Operation: scope.OpConnect, ObservationPointID: s.pointID, Now: now,
		})
		if decision.Allowed {
			allowed = append(allowed, addr.Unmap())
			continue
		}
		if err := s.recordDenial(runID, target, addr, decision.Code, now); err != nil {
			return nil, err
		}
	}
	if len(allowed) == 0 {
		return nil, planFailure{summary: "no address passed scope check"}
	}
	for _, port := range plan.Ports {
		decision := grant.Check(scope.CheckInput{
			IP: allowed[0], Port: port, Transport: plan.Transport, Operation: scope.OpConnect,
			ObservationPointID: s.pointID, Now: now, Hostname: target.Hostname, ResolvedFromGrant: target.TargetType == "hostname",
		})
		if !decision.Allowed {
			return nil, planFailure{summary: decision.Code}
		}
	}
	return allowed, nil
}

// recordResolution 保存一次域名解析实际返回的记录。不写入 TTL，因为当前解析器没有提供 TTL。
// recordResolution stores the records one hostname resolution actually returned. It does not write a TTL because the current resolver does not provide one.
func (s *Service) recordResolution(runID id.ID, host string, resolution Resolution, now time.Time) error {
	records := make([]map[string]string, 0, len(resolution.Addresses))
	for _, addr := range resolution.Addresses {
		unmapped := addr.Unmap()
		kind := "A"
		if unmapped.Is6() {
			kind = "AAAA"
		}
		records = append(records, map[string]string{"type": kind, "address": unmapped.String()})
	}
	value := map[string]any{
		"hostname":   host,
		"queried_at": now.UTC().Format(time.RFC3339Nano),
		"records":    records,
	}
	if resolution.CanonicalName != "" {
		value["canonical_name"] = resolution.CanonicalName
	}
	if resolution.CanonicalError != "" {
		value["canonical_name_error"] = resolution.CanonicalError
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.appendObservation(Observation{
		ScanRunID: runID, ObservationPointID: s.pointID, Type: "dns_resolution", SubjectKey: "hostname:" + host,
		ObservedAt: now, CollectedAt: now, ResultStatus: "observed", ValueSchemaVersion: "1", Value: value, SourceKind: "network",
	})
	return s.flush(context.Background())
}

func (s *Service) installPlan(runID id.ID, target asset.Target, addresses []netip.Addr, plan planBody, now time.Time) error {
	current, _, err := s.tasks.Snapshot(runID)
	if err != nil {
		return err
	}
	if current.Status != task.RunPlanning {
		return nil
	}
	live, ok := s.grants[current.ScopeGrantID]
	if !ok || live.Status != scope.StatusActive {
		return planFailure{summary: "grant_not_active"}
	}
	grant, ok := s.frozen[runID]
	if !ok {
		return planFailure{summary: "grant snapshot missing"}
	}
	account := s.accounts[runID]
	if account == nil {
		account = scope.NewAccount(scope.FromGrant(grant), now)
	}
	if account.ExportUsage().Targets == 0 {
		if err := account.TryTarget(); err != nil {
			return planFailure{summary: err.Error()}
		}
		for range addresses {
			if err := account.TryAddress(); err != nil {
				return planFailure{summary: err.Error()}
			}
		}
	}
	s.accounts[runID] = account
	plan.Allowed = make([]string, 0, len(addresses))
	for _, addr := range addresses {
		plan.Allowed = append(plan.Allowed, addr.String())
	}
	body, err := json.Marshal(plan)
	if err != nil {
		return err
	}
	if err := s.tasks.SetPlan(runID, body); err != nil {
		return err
	}
	for _, addr := range addresses {
		payload, err := json.Marshal(map[string]any{"address": addr.String(), "ports": plan.Ports, "transport": plan.Transport, "hostname": plan.Hostname})
		if err != nil {
			return err
		}
		discovery := task.Unit{ScanRunID: runID, TargetID: target.ID, ObservationPointID: s.pointID, UnitType: "host_discovery", StageKey: "host_discovery:" + addr.String(), RequiredCapabilities: []string{"tcp_connect"}, Input: payload, Priority: 0, CreatedAt: now}
		if err := s.tasks.AddUnit(discovery); err != nil && !errors.Is(err, task.ErrDuplicateStage) {
			return err
		}
		portScan := task.Unit{ScanRunID: runID, TargetID: target.ID, ObservationPointID: s.pointID, UnitType: "port_scan", StageKey: "port_scan:" + addr.String(), RequiredCapabilities: []string{"tcp_connect"}, Input: payload, Priority: 1, CreatedAt: now}
		if err := s.tasks.AddUnit(portScan); err != nil && !errors.Is(err, task.ErrDuplicateStage) {
			return err
		}
	}
	collectPayload, err := json.Marshal(map[string]any{"operations": []string{"collect_os_info", "collect_interfaces", "collect_listening_sockets"}})
	if err != nil {
		return err
	}
	collectUnit := task.Unit{ScanRunID: runID, TargetID: target.ID, ObservationPointID: s.pointID, UnitType: "host_collect", StageKey: "host_collect", RequiredCapabilities: []string{"host_collect"}, Input: collectPayload, Priority: 1, CreatedAt: now}
	if err := s.tasks.AddUnit(collectUnit); err != nil && !errors.Is(err, task.ErrDuplicateStage) {
		return err
	}
	if !containsOperation(grant, scope.OpConfigCheck) {
		_, units, _ := s.tasks.Snapshot(runID)
		for _, unit := range units {
			if unit.UnitType == "host_collect" && (unit.Status == task.UnitQueued || unit.Status == task.UnitRetryWait) {
				_ = s.tasks.MarkSkipped(unit.ID, "operation_denied", now)
			}
		}
	}
	if err := s.tasks.MarkRunning(runID, now); err != nil {
		current, _, snapErr := s.tasks.Snapshot(runID)
		if snapErr == nil && current.Status == task.RunRunning {
			return nil
		}
		return err
	}
	return nil
}

func (s *Service) failPlanning(runID id.ID, summary string, now time.Time) (task.Run, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.commitState(context.Background(), func() error {
		current, _, err := s.tasks.Snapshot(runID)
		if err != nil {
			return err
		}
		if current.Status != task.RunPlanning {
			return nil
		}
		return s.tasks.FailRun(runID, summary, now)
	}); err != nil {
		return task.Run{}, err
	}
	run, _, err := s.tasks.Snapshot(runID)
	return run, err
}
