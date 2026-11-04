package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/zodirc/Vesper/internal/asset"
	"github.com/zodirc/Vesper/internal/collect"
	"github.com/zodirc/Vesper/internal/id"
	"github.com/zodirc/Vesper/internal/rule"
	"github.com/zodirc/Vesper/internal/scope"
	"github.com/zodirc/Vesper/internal/task"
)

type planBody struct {
	Ports            []int                   `json:"ports"`
	Transport        string                  `json:"transport"`
	Hostname         string                  `json:"hostname"`
	Allowed          []string                `json:"allowed_addresses,omitempty"`
	FindingID        string                  `json:"finding_id,omitempty"`
	OccurrenceID     string                  `json:"occurrence_id,omitempty"`
	ConditionDigest  string                  `json:"condition_digest,omitempty"`
	VulnerabilityID  string                  `json:"vulnerability_id,omitempty"`
	Environment      *observationEnvironment `json:"observation_environment,omitempty"`
	ActiveTemplates  []frozenTemplate        `json:"active_templates,omitempty"`
	NmapFingerprints []string                `json:"nmap_fingerprints,omitempty"`
	ConfigRules      []string                `json:"config_rules,omitempty"`
}

type preparedScan struct {
	Name            string
	Target          asset.Target
	Transport       string
	Ports           []int
	GrantID         id.ID
	Trigger         string
	FindingID       id.ID
	OccurrenceID    id.ID
	Condition       string
	VulnerabilityID string
	RuleID          id.ID
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
	transport, err := scanTransport(input.Transport, target.Transport)
	if err != nil {
		return task.Run{}, err
	}
	ports := append([]int(nil), input.Ports...)
	if target.Port != nil {
		ports = []int{*target.Port}
	}
	if len(ports) == 0 {
		return task.Run{}, fmt.Errorf("create scan: no ports")
	}
	return s.startScan(ctx, preparedScan{
		Name: input.Name, Target: target, Transport: transport, Ports: ports, GrantID: input.GrantID, Trigger: "manual",
	}, now)
}

// CreateVerification 从 Finding 和最近一次发生记录创建复核扫描。
// CreateVerification creates a verification scan from a finding and its latest occurrence.
//
// grantID 在创建时重新校验并冻结到新运行，预算账本也是新的。端点类 Finding 只复测该端点的地址、传输协议和端口，不创建主机采集。
// 配置类 Finding 采集该规则的主操作，以及适用条件点名的采集操作。计划快照写入 finding、occurrence、条件摘要和漏洞标识，因为 ScanRun 没有单独的 Finding 列。
// grantID is checked again at creation and frozen into the new run. The budget ledger is also new. An endpoint finding retests only that endpoint's address, transport, and port, and does not create host collection.
// A configuration finding collects the rule's primary operation and the operations named by its applicability conditions. The plan snapshot records the finding, occurrence, condition digest, and vulnerability identifier because ScanRun has no separate finding column.
//
// 扫描不可达、无响应、规则不支持或证据不足都不会关闭 Finding。调用方仍要用符合复核条件的检测结果单独写入 resolve。
// An unreachable target, no response, an unsupported rule, or insufficient evidence does not close the finding. The caller still records resolve separately with a detection that meets the verification rule.
//
// Finding 不存在时返回 ErrFindingNotFound。没有发生记录、端点或可复测操作时返回 ErrVerificationUnavailable，并且不创建运行。
// It returns ErrFindingNotFound when the finding does not exist. It returns ErrVerificationUnavailable and creates no run when the occurrence, endpoint, or retest operation is missing.
func (s *Service) CreateVerification(ctx context.Context, findingID, grantID id.ID) (task.Run, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	now := s.now().UTC()
	s.mu.Lock()
	finding := s.findingByID(findingID)
	if finding == nil {
		s.mu.Unlock()
		return task.Run{}, ErrFindingNotFound
	}
	occurrence := latestOccurrence(s.occurrences, finding.ID)
	if occurrence == nil {
		s.mu.Unlock()
		return task.Run{}, ErrVerificationUnavailable
	}
	findingCopy := *finding
	occurrenceCopy := *occurrence
	endpoint, hasEndpoint := s.catalog.Endpoints[finding.EndpointID]
	operations := verificationOperations(s.packs, findingCopy.RuleID, findingCopy.VulnerabilityID)
	s.mu.Unlock()
	if findingCopy.FindingType == "misconfiguration" || findingCopy.EndpointID.IsZero() {
		if len(operations) == 0 {
			return task.Run{}, ErrVerificationUnavailable
		}
		return s.startCollectVerification(ctx, findingCopy, occurrenceCopy, operations, grantID, now)
	}
	if !hasEndpoint || endpoint.Port < 1 || (endpoint.Transport != "tcp" && endpoint.Transport != "udp") {
		return task.Run{}, ErrVerificationUnavailable
	}
	port := endpoint.Port
	target, err := asset.ParseTarget("endpoint", endpoint.Address.String(), endpoint.Transport, &port, now)
	if err != nil {
		return task.Run{}, err
	}
	return s.startScan(ctx, preparedScan{
		Name: "verification:" + findingCopy.VulnerabilityID, Target: target, Transport: endpoint.Transport, Ports: []int{endpoint.Port},
		GrantID: grantID, Trigger: "verification", FindingID: findingCopy.ID, OccurrenceID: occurrenceCopy.ID,
		Condition: occurrenceCopy.ConditionDigest, VulnerabilityID: findingCopy.VulnerabilityID, RuleID: findingCopy.RuleID,
	}, now)
}

func (s *Service) startScan(ctx context.Context, prepared preparedScan, now time.Time) (task.Run, error) {
	runID, err := id.New()
	if err != nil {
		return task.Run{}, err
	}
	environment := s.currentEnvironment(now)
	s.mu.Lock()
	err = s.commitState(ctx, func() error {
		grant, ok := s.grants[prepared.GrantID]
		if !ok {
			return fmt.Errorf("create scan: grant not found")
		}
		if grant.Status != scope.StatusActive {
			return fmt.Errorf("create scan: grant status %s", grant.Status)
		}
		digest, err := grant.Digest()
		if err != nil {
			return err
		}
		templates, err := s.selectActiveTemplates(grant, !prepared.FindingID.IsZero(), prepared.RuleID)
		if err != nil {
			return err
		}
		nmapPacks := s.publishedNmapFingerprints()
		configPacks := s.publishedConfigPacks()
		body, err := json.Marshal(planBody{
			Ports: prepared.Ports, Transport: prepared.Transport, Hostname: prepared.Target.Hostname,
			FindingID: prepared.FindingID.String(), OccurrenceID: prepared.OccurrenceID.String(),
			ConditionDigest: prepared.Condition, VulnerabilityID: prepared.VulnerabilityID, Environment: &environment,
			ActiveTemplates: templates, NmapFingerprints: nmapPacks, ConfigRules: configPacks,
		})
		if err != nil {
			return err
		}
		if prepared.FindingID.IsZero() {
			body, err = json.Marshal(planBody{
				Ports: prepared.Ports, Transport: prepared.Transport, Hostname: prepared.Target.Hostname,
				Environment: &environment, ActiveTemplates: templates, NmapFingerprints: nmapPacks, ConfigRules: configPacks,
			})
			if err != nil {
				return err
			}
		}
		budget, err := budgetSnapshot(grant)
		if err != nil {
			return err
		}
		s.catalog.AddTarget(prepared.Target)
		run := versionedRun(task.Run{
			ID: runID, Name: prepared.Name, TargetIDs: []id.ID{prepared.Target.ID}, ScopeGrantID: grant.ID, ScopeDigest: digest,
			TriggerType: prepared.Trigger, EffectiveBudget: budget, IntelSnapshotID: s.latestSnapshotID(),
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
	operation, err := planOperation(grant, plan.Transport)
	if err != nil {
		return nil, err
	}
	var allowed []netip.Addr
	for _, addr := range addresses {
		decision := grant.Check(scope.CheckInput{
			IP: addr, Hostname: target.Hostname, ResolvedFromGrant: target.TargetType == "hostname",
			Port: plan.Ports[0], Transport: plan.Transport, Operation: operation, ObservationPointID: s.pointID, Now: now,
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
			IP: allowed[0], Port: port, Transport: plan.Transport, Operation: operation,
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
		if plan.Transport == "udp" {
			probe := task.Unit{ScanRunID: runID, TargetID: target.ID, ObservationPointID: s.pointID, UnitType: "udp_probe", StageKey: "udp_probe:" + addr.String(), RequiredCapabilities: []string{"udp_dns"}, Input: payload, Priority: 1, CreatedAt: now}
			if _, err := s.ensureUnit(probe); err != nil {
				return err
			}
			continue
		}
		portScan := task.Unit{ScanRunID: runID, TargetID: target.ID, ObservationPointID: s.pointID, UnitType: "port_scan", StageKey: "port_scan:" + addr.String(), RequiredCapabilities: []string{"tcp_connect"}, Input: payload, Priority: 1, CreatedAt: now}
		portID, err := s.ensureUnit(portScan)
		if err != nil {
			return err
		}
		discovery := task.Unit{ScanRunID: runID, TargetID: target.ID, ObservationPointID: s.pointID, UnitType: "host_discovery", StageKey: "host_discovery:" + addr.String(), RequiredCapabilities: []string{"tcp_connect"}, Input: payload, Priority: 2, CreatedAt: now}
		if containsOperation(grant, scope.OpConnect) {
			discovery.DependsOn = []id.ID{portID}
		}
		if _, err := s.ensureUnit(discovery); err != nil {
			return err
		}
	}
	if plan.FindingID == "" {
		collectPayload, err := json.Marshal(map[string]any{"operations": collect.Operations})
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
					if err := s.tasks.MarkSkipped(unit.ID, "operation_denied", now); err != nil {
						return err
					}
				}
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

// ensureUnit 追加执行单元。相同阶段键已经存在时返回已有单元标识。
// ensureUnit appends an execution unit. When the same stage key already exists, it returns the existing unit identifier.
func (s *Service) ensureUnit(unit task.Unit) (id.ID, error) {
	if unit.ID.IsZero() {
		var err error
		unit.ID, err = id.New()
		if err != nil {
			return id.ID{}, err
		}
	}
	err := s.tasks.AddUnit(unit)
	if err == nil {
		return unit.ID, nil
	}
	if !errors.Is(err, task.ErrDuplicateStage) {
		return id.ID{}, err
	}
	_, units, snapErr := s.tasks.Snapshot(unit.ScanRunID)
	if snapErr != nil {
		return id.ID{}, snapErr
	}
	for _, existing := range units {
		if existing.StageKey == unit.StageKey && existing.TargetID == unit.TargetID && existing.ObservationPointID == unit.ObservationPointID {
			return existing.ID, nil
		}
	}
	return id.ID{}, err
}

func verificationOperations(packs []rule.Pack, ruleID id.ID, ruleKey string) []string {
	var fallback []string
	for _, pack := range packs {
		if pack.Type != "config" || (pack.Status != "published" && pack.Status != "deprecated") {
			continue
		}
		for _, item := range pack.Configs {
			if !ruleID.IsZero() && item.ID == ruleID {
				return item.ReadOperations()
			}
			if item.Key == ruleKey && item.Operation != "" && len(fallback) == 0 {
				fallback = item.ReadOperations()
			}
		}
	}
	return fallback
}

// startCollectVerification 为配置 Finding 创建主机采集。采集范围是规则的主操作和适用条件点名的操作。它不经过端口规划，也不拨号。
// startCollectVerification creates host collection for a configuration finding. The collection covers the rule's primary operation and the operations named by its applicability conditions. It does not pass through port planning and does not dial.
func (s *Service) startCollectVerification(ctx context.Context, finding Finding, occurrence Occurrence, operations []string, grantID id.ID, now time.Time) (task.Run, error) {
	runID, err := id.New()
	if err != nil {
		return task.Run{}, err
	}
	targetID, err := id.New()
	if err != nil {
		return task.Run{}, err
	}
	environment := s.currentEnvironment(now)
	s.mu.Lock()
	err = s.commitState(ctx, func() error {
		grant, ok := s.grants[grantID]
		if !ok {
			return fmt.Errorf("create scan: grant not found")
		}
		if grant.Status != scope.StatusActive {
			return fmt.Errorf("create scan: grant status %s", grant.Status)
		}
		if !containsOperation(grant, scope.OpConfigCheck) {
			return planFailure{summary: "operation_denied"}
		}
		allowedPoint := false
		for _, pointID := range grant.ObservationPointIDs {
			if pointID == s.pointID {
				allowedPoint = true
				break
			}
		}
		if !allowedPoint {
			return planFailure{summary: "observation_point_denied"}
		}
		digest, err := grant.Digest()
		if err != nil {
			return err
		}
		configPacks := addUnique(s.publishedConfigPacks(), s.configPackVersion(finding.RuleID))
		body, err := json.Marshal(planBody{
			FindingID: finding.ID.String(), OccurrenceID: occurrence.ID.String(),
			ConditionDigest: occurrence.ConditionDigest, VulnerabilityID: finding.VulnerabilityID, Environment: &environment,
			ConfigRules: configPacks,
		})
		if err != nil {
			return err
		}
		budget, err := budgetSnapshot(grant)
		if err != nil {
			return err
		}
		target := asset.Target{ID: targetID, TargetType: "asset", RawValue: finding.AssetID.String(), NormalizedValue: finding.AssetID.String(), CreatedAt: now}
		s.catalog.AddTarget(target)
		run := versionedRun(task.Run{
			ID: runID, Name: "verification:" + finding.VulnerabilityID, TargetIDs: []id.ID{target.ID}, ScopeGrantID: grant.ID, ScopeDigest: digest,
			TriggerType: "verification", EffectiveBudget: budget, IntelSnapshotID: s.latestSnapshotID(),
			ObservationPointIDs: []id.ID{s.pointID}, CreatedAt: now, Plan: body,
		})
		if err := s.tasks.CreateRun(run); err != nil {
			return err
		}
		s.frozen[runID] = grant
		account := scope.NewAccount(scope.FromGrant(grant), now)
		if err := account.TryTarget(); err != nil {
			return planFailure{summary: err.Error()}
		}
		s.accounts[runID] = account
		payload, err := json.Marshal(map[string]any{"operations": operations})
		if err != nil {
			return err
		}
		if _, err := s.ensureUnit(task.Unit{
			ScanRunID: runID, TargetID: target.ID, ObservationPointID: s.pointID, UnitType: "host_collect", StageKey: "host_collect",
			RequiredCapabilities: []string{"host_collect"}, Input: payload, Priority: 1, CreatedAt: now,
		}); err != nil {
			return err
		}
		return s.tasks.MarkRunning(runID, now)
	})
	s.mu.Unlock()
	if err != nil {
		var failed planFailure
		if errors.As(err, &failed) {
			s.mu.Lock()
			_, _, snapErr := s.tasks.Snapshot(runID)
			s.mu.Unlock()
			if snapErr == nil {
				return s.failPlanning(runID, failed.Error(), now)
			}
		}
		return task.Run{}, err
	}
	s.mu.Lock()
	run, _, err := s.tasks.Snapshot(runID)
	s.mu.Unlock()
	return run, err
}

func scanTransport(requested, targetTransport string) (string, error) {
	transport := strings.ToLower(strings.TrimSpace(requested))
	if transport == "" {
		transport = strings.ToLower(strings.TrimSpace(targetTransport))
	}
	if transport == "" {
		transport = "tcp"
	}
	if transport != "tcp" && transport != "udp" {
		return "", fmt.Errorf("create scan: transport %s", transport)
	}
	return transport, nil
}

func planOperation(grant scope.Grant, transport string) (string, error) {
	if transport == "udp" {
		if !containsOperation(grant, scope.OpProtocolProbe) {
			return "", planFailure{summary: "operation_denied"}
		}
		return scope.OpProtocolProbe, nil
	}
	if transport != "tcp" {
		return "", planFailure{summary: "transport_denied"}
	}
	if containsOperation(grant, scope.OpConnect) {
		return scope.OpConnect, nil
	}
	if containsOperation(grant, scope.OpDiscovery) {
		return scope.OpDiscovery, nil
	}
	return "", planFailure{summary: "operation_denied"}
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
