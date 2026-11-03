package control

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/zodirc/Vesper/internal/assess"
	"github.com/zodirc/Vesper/internal/collect"
	"github.com/zodirc/Vesper/internal/id"
	"github.com/zodirc/Vesper/internal/identity"
	"github.com/zodirc/Vesper/internal/probe/httpprobe"
	"github.com/zodirc/Vesper/internal/probe/sshprobe"
	"github.com/zodirc/Vesper/internal/probe/tcp"
	"github.com/zodirc/Vesper/internal/probe/tlsprobe"
	"github.com/zodirc/Vesper/internal/rule"
	"github.com/zodirc/Vesper/internal/scope"
	"github.com/zodirc/Vesper/internal/task"
	"github.com/zodirc/Vesper/pkg/probesdk"
)

type addressInput struct {
	Address  string `json:"address"`
	Ports    []int  `json:"ports"`
	Hostname string `json:"hostname"`
}

type probeInput struct {
	Address  string `json:"address"`
	Port     int    `json:"port"`
	Probe    string `json:"probe"`
	Hostname string `json:"hostname"`
}

type collectInput struct {
	Operations []string `json:"operations"`
}

// ExecuteAvailable 领取并执行一个单元。没有可执行单元时返回 false。
// ExecuteAvailable claims and executes one unit. It returns false when no unit is executable.
//
// 过期、领取、启动和结果提交都在同一个数据库事务里锁定任务行后更新。网络收发发生在事务之外。
// Expiry, claim, start, and result submission each lock the task rows and update them in one database transaction. Network transfer happens outside the transaction.
func (s *Service) ExecuteAvailable(ctx context.Context) (bool, error) {
	if err := s.resumePlanning(ctx); err != nil {
		return false, err
	}
	s.mu.Lock()
	var lease task.Lease
	var account *scope.Account
	claimed := false
	worked := false
	err := s.commitState(ctx, func() error {
		s.releaseUnauthorized(s.now())
		s.tasks.Expire(s.now())
		var claimErr error
		lease, claimErr = s.tasks.Claim(s.now(), s.worker)
		if errors.Is(claimErr, task.ErrNone) {
			return nil
		}
		if claimErr != nil {
			return claimErr
		}
		if err := s.tasks.Start(lease, s.now()); err != nil {
			return err
		}
		account = s.accounts[lease.RunID]
		if account == nil {
			worked = true
			return s.tasks.Fail(lease, false, "budget_missing", "budget ledger missing", s.now())
		}
		if s.baselines == nil {
			s.baselines = map[id.ID]scope.Usage{}
		}
		s.baselines[lease.AttemptID] = account.ExportUsage()
		claimed = true
		return nil
	})
	s.mu.Unlock()
	if err != nil {
		return false, err
	}
	if !claimed {
		return worked, nil
	}

	execErr := s.executeLease(ctx, lease, account)
	s.mu.Lock()
	defer s.mu.Unlock()
	if execErr != nil {
		retryable := retryableExecution(execErr)
		return true, s.commitState(ctx, func() error {
			if err := s.recordAttemptOutcome(lease, s.now()); err != nil {
				return err
			}
			return s.tasks.Fail(lease, retryable, "execution_error", execErr.Error(), s.now())
		})
	}
	return true, s.commitState(ctx, func() error {
		if err := s.recordAttemptOutcome(lease, s.now()); err != nil {
			return err
		}
		return s.tasks.Succeed(lease, s.now())
	})
}

// retryableExecution 按设计区分可重试错误。预算耗尽、授权拒绝、取消、不支持和输入错误不重试。
// retryableExecution separates retryable errors as designed. Budget exhaustion, authorization denial, cancellation, unsupported work, and bad input are not retried.
func retryableExecution(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	var probeErr *probesdk.Error
	if errors.As(err, &probeErr) {
		switch probeErr.Class {
		case probesdk.ClassTimeout, probesdk.ClassEvidence:
			return true
		default:
			return false
		}
	}
	var syntax *json.SyntaxError
	var typeErr *json.UnmarshalTypeError
	if errors.As(err, &syntax) || errors.As(err, &typeErr) {
		return false
	}
	return true
}

// recordAttemptOutcome 用预算账本差值写入本次尝试的消耗，并用该尝试产生的观察生成结果摘要。
// recordAttemptOutcome writes this attempt's consumption from the budget-ledger delta and builds the result summary from observations produced by that attempt.
func (s *Service) recordAttemptOutcome(lease task.Lease, now time.Time) error {
	baseline, ok := s.baselines[lease.AttemptID]
	if !ok {
		return nil
	}
	delete(s.baselines, lease.AttemptID)
	account := s.accounts[lease.RunID]
	if account == nil {
		return nil
	}
	current := account.ExportUsage()
	connections := current.Connections - baseline.Connections
	requests := current.Requests - baseline.Requests
	evidenceBytes := current.Evidence - baseline.Evidence
	if connections < 0 || requests < 0 || evidenceBytes < 0 {
		return fmt.Errorf("attempt usage baseline is ahead of the budget ledger")
	}
	summary, digest, err := s.attemptResult(lease.AttemptID)
	if err != nil {
		return err
	}
	return s.tasks.RecordOutcome(lease, connections, requests, evidenceBytes, summary, digest, now)
}

func (s *Service) attemptResult(attemptID id.ID) (json.RawMessage, string, error) {
	byStatus := map[string]int{}
	byType := map[string]int{}
	var parts []string
	for _, item := range s.observations {
		if item.StageAttemptID != attemptID {
			continue
		}
		byStatus[item.ResultStatus]++
		byType[item.Type]++
		parts = append(parts, item.Type+"|"+item.SubjectKey+"|"+item.ContentDigest)
	}
	summary, err := json.Marshal(struct {
		Observations int            `json:"observations"`
		ByStatus     map[string]int `json:"by_status,omitempty"`
		ByType       map[string]int `json:"by_type,omitempty"`
	}{len(parts), byStatus, byType})
	if err != nil {
		return nil, "", err
	}
	if len(parts) == 0 {
		return summary, "", nil
	}
	sort.Strings(parts)
	sum := sha256.Sum256([]byte(strings.Join(parts, "\n")))
	return summary, hex.EncodeToString(sum[:]), nil
}

func (s *Service) releaseUnauthorized(now time.Time) {
	runs, units, _ := s.tasks.Export()
	byRun := map[id.ID]task.Run{}
	for _, run := range runs {
		byRun[run.ID] = run
	}
	for _, unit := range units {
		if unit.Status != task.UnitQueued && unit.Status != task.UnitRetryWait {
			continue
		}
		run, ok := byRun[unit.ScanRunID]
		if !ok || run.Status != task.RunRunning {
			continue
		}
		if reason := s.claimDenial(run, unit); reason != "" {
			_ = s.tasks.MarkSkipped(unit.ID, reason, now)
		}
	}
}

func (s *Service) claimDenial(run task.Run, unit task.Unit) string {
	grant, ok := s.frozen[run.ID]
	if !ok {
		return "grant_snapshot_missing"
	}
	live, ok := s.grants[grant.ID]
	if !ok || live.Status != scope.StatusActive {
		return "grant_not_active"
	}
	allowedPoint := false
	for _, pointID := range grant.ObservationPointIDs {
		if pointID == unit.ObservationPointID {
			allowedPoint = true
			break
		}
	}
	if !allowedPoint {
		return "observation_point_denied"
	}
	if !containsOperation(grant, operationForUnit(unit.UnitType)) {
		return "operation_denied"
	}
	return ""
}

func operationForUnit(unitType string) string {
	switch unitType {
	case "host_discovery":
		return scope.OpDiscovery
	case "port_scan":
		return scope.OpConnect
	case "protocol_probe":
		return scope.OpProtocolProbe
	case "host_collect":
		return scope.OpConfigCheck
	case "active_detection":
		return scope.OpActiveCheck
	default:
		return ""
	}
}

// Cancel 取消扫描运行。已经完成的观察保留，取消之后不再创建新的执行单元。
// Cancel cancels a scan run. Observations that already completed are kept, and no new execution unit is created after cancellation.
func (s *Service) Cancel(runID id.ID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.commitState(context.Background(), func() error {
		return s.tasks.Cancel(runID, s.now())
	})
}

// Run 返回扫描运行副本。
// Run returns a copy of the scan run.
func (s *Service) Run(runID id.ID) (task.Run, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	run, _, err := s.tasks.Snapshot(runID)
	return run, err
}

// Observations 返回某次运行的观察副本。
// Observations returns copies of observations for one run.
func (s *Service) Observations(runID id.ID) []Observation {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Observation
	for _, item := range s.observations {
		if item.ScanRunID == runID {
			out = append(out, item)
		}
	}
	return out
}

// Hypotheses 返回识别候选副本。
// Hypotheses returns copies of identification candidates.
func (s *Service) Hypotheses() []identity.Hypothesis {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]identity.Hypothesis(nil), s.hypotheses...)
}

// Findings 返回当前风险视图副本。
// Findings returns copies of the current risk view.
func (s *Service) Findings() []Finding {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Finding, 0, len(s.findings))
	for _, item := range s.findings {
		out = append(out, *item)
	}
	return out
}

func (s *Service) executeLease(ctx context.Context, lease task.Lease, account *scope.Account) error {
	s.mu.Lock()
	err := s.commitState(ctx, func() error {
		return s.tasks.Renew(lease, s.now())
	})
	s.mu.Unlock()
	if err != nil {
		return err
	}
	switch lease.UnitType {
	case "host_discovery", "port_scan":
		return s.executePorts(ctx, lease, account, lease.UnitType == "host_discovery")
	case "protocol_probe":
		return s.executeProbe(ctx, lease, account)
	case "host_collect":
		return s.executeCollect(ctx, lease)
	case "active_detection":
		decision := rule.ActiveDetection(false)
		return &probesdk.Error{Class: probesdk.ClassUnsupported, Message: decision.Summary}
	default:
		return &probesdk.Error{Class: probesdk.ClassUnsupported, Message: "unit type " + lease.UnitType}
	}
}

func (s *Service) executePorts(ctx context.Context, lease task.Lease, account *scope.Account, discovery bool) error {
	var input addressInput
	if err := json.Unmarshal(lease.Input, &input); err != nil {
		return err
	}
	addr, err := netip.ParseAddr(input.Address)
	if err != nil {
		return err
	}
	s.mu.Lock()
	concurrency := s.frozen[lease.RunID].MaxConcurrency
	s.mu.Unlock()
	if concurrency < 1 {
		return &probesdk.Error{Class: probesdk.ClassExecution, Message: "grant concurrency is not configured"}
	}
	results := tcp.Scan(ctx, s.dialer(lease, account), addr, input.Ports, concurrency, s.now)
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.commitState(ctx, func() error {
		if discovery {
			s.appendObservation(Observation{
				ScanRunID: lease.RunID, ScanUnitID: lease.UnitID, StageAttemptID: lease.AttemptID,
				ObservationPointID: lease.ObservationPointID, Type: "host_reachability", SubjectKey: "ip:" + addr.String(),
				ObservedAt: s.now(), CollectedAt: s.now(), ResultStatus: reachStatus(tcp.Reachability(results)),
				ValueSchemaVersion: "1", Value: map[string]any{"method": "tcp_connect", "state": tcp.Reachability(results), "address": addr.String()},
				SourceKind: "network",
			})
			return nil
		}
		run, _, err := s.tasks.Snapshot(lease.RunID)
		if err != nil {
			return err
		}
		createProbes := run.Status == task.RunRunning
		for _, result := range results {
			endpoint := s.catalog.ObserveEndpoint(addr, "tcp", result.Port, endpointState(result.State), result.ObservedAt)
			endpointID := endpoint.ID
			s.appendObservation(Observation{
				ScanRunID: lease.RunID, ScanUnitID: lease.UnitID, StageAttemptID: lease.AttemptID, EndpointID: &endpointID,
				ObservationPointID: lease.ObservationPointID, Type: "port_state", SubjectKey: fmt.Sprintf("tcp:%s:%d", addr.String(), result.Port),
				ObservedAt: result.ObservedAt, CollectedAt: s.now(), ResultStatus: portResultStatus(result.State),
				ValueSchemaVersion: "1", Value: map[string]any{"state": result.State, "port": result.Port, "address": addr.String()},
				SourceKind: "network",
			})
			if result.State != "open" || !createProbes {
				continue
			}
			for _, probe := range []string{"http", "tls", "ssh"} {
				payload, err := json.Marshal(probeInput{Address: addr.String(), Port: result.Port, Probe: probe, Hostname: input.Hostname})
				if err != nil {
					return err
				}
				unit := task.Unit{
					ScanRunID: lease.RunID, TargetID: lease.TargetID, ObservationPointID: lease.ObservationPointID,
					UnitType: "protocol_probe", StageKey: fmt.Sprintf("protocol_probe:%s:%s:%d", probe, addr.String(), result.Port),
					DependsOn: []id.ID{lease.UnitID}, RequiredCapabilities: []string{"protocol_" + probe}, Input: payload, Priority: 2, CreatedAt: s.now(),
				}
				if err := s.tasks.AddUnit(unit); err != nil && !errors.Is(err, task.ErrDuplicateStage) {
					return err
				}
			}
		}
		return nil
	})
}

func (s *Service) executeProbe(ctx context.Context, lease task.Lease, account *scope.Account) error {
	var input probeInput
	if err := json.Unmarshal(lease.Input, &input); err != nil {
		return err
	}
	addr, err := netip.ParseAddr(input.Address)
	if err != nil {
		return err
	}
	dial := s.dialer(lease, account)
	switch input.Probe {
	case "http":
		result, probeErr := httpprobe.Probe(ctx, dial, account, addr, input.Port, input.Hostname, 4096, s.now)
		value := map[string]any{"status_code": result.StatusCode, "headers": result.Headers}
		state := result.State
		if result.StatusCode > 0 {
			value["protocol"] = "http"
		} else if state == "open" {
			state = "error"
		}
		return s.finishProbe(ctx, lease, addr, input.Port, input.Hostname, "http", value, result.Raw, state, probeErr)
	case "tls":
		result, probeErr := tlsprobe.Probe(ctx, dial, account, addr, input.Port, input.Hostname, s.now)
		var cert []byte
		if len(result.PeerCerts) > 0 {
			cert = result.PeerCerts[0]
		}
		value := map[string]any{"version": result.Version, "subject": result.Subject, "issuer": result.Issuer}
		state := result.State
		if state == "open" {
			value["protocol"] = "tls"
		}
		return s.finishProbe(ctx, lease, addr, input.Port, input.Hostname, "tls", value, cert, state, probeErr)
	case "ssh":
		result, probeErr := sshprobe.Probe(ctx, dial, account, addr, input.Port, s.now)
		value := map[string]any{"banner": result.Banner}
		state := result.State
		if result.IsSSH {
			value["protocol"] = "ssh"
		} else if state == "open" {
			state = "error"
		}
		return s.finishProbe(ctx, lease, addr, input.Port, input.Hostname, "ssh", value, result.Raw, state, probeErr)
	default:
		return &probesdk.Error{Class: probesdk.ClassUnsupported, Message: "probe " + input.Probe}
	}
}

func (s *Service) finishProbe(ctx context.Context, lease task.Lease, addr netip.Addr, port int, hostname, protocol string, value map[string]any, raw []byte, state string, probeErr error) error {
	var evidenceIDs []id.ID
	var record *EvidenceRecord
	if len(raw) > 0 {
		if err := s.accounts[lease.RunID].TryEvidence(int64(len(raw))); err != nil {
			return &probesdk.Error{Class: probesdk.ClassBudget, Message: err.Error()}
		}
		object, err := s.evidence.Put(s.now(), raw)
		if err != nil {
			return &probesdk.Error{Class: probesdk.ClassEvidence, Message: err.Error()}
		}
		evidenceID, err := id.New()
		if err != nil {
			return err
		}
		storedAt := s.now()
		evidenceType := "raw_response"
		if protocol == "tls" {
			evidenceType = "tls_certificate"
		}
		// 设计要求证据带有敏感级，但没有规定协议响应属于哪一级。探测内容按 internal 保存。
		// The design requires an evidence sensitivity and does not assign protocol responses to one level. Probe content is stored as internal.
		contentType, contentEncoding := evidenceContent(protocol)
		record = &EvidenceRecord{
			ID: evidenceID, EvidenceType: evidenceType, StorageKey: object.StorageKey, SizeBytes: object.SizeBytes,
			DigestAlgorithm: object.DigestAlgorithm, ContentDigest: object.ContentDigest, ContentType: contentType, ContentEncoding: contentEncoding,
			SourceModule: protocol + "probe", SourceAttemptID: lease.AttemptID, IntegrityStatus: "verified", Sensitivity: "internal",
			CapturedAt: storedAt, StoredAt: &storedAt,
		}
		evidenceIDs = []id.ID{evidenceID}
	}
	if record != nil && value != nil {
		value["evidence_digest"] = record.ContentDigest
	}
	status := "observed"
	if state != "open" {
		status = "error"
		if state == "no_response" || state == "not_scanned" || state == "unsupported" {
			status = state
		}
	}
	if probeErr != nil && state == "open" {
		status = "partial"
	}
	if value == nil {
		value = map[string]any{}
	}
	value["probe"] = protocol
	value["probe_version"] = "builtin-1"
	value["address"] = addr.String()
	value["connected_address"] = addr.String()
	value["port"] = port
	value["transport"] = "tcp"
	value["request_rounds"] = 1
	value["response_bytes"] = len(raw)
	if hostname != "" {
		value["hostname"] = hostname
	}
	if probeErr != nil {
		value["error"] = probeErr.Error()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if record != nil {
		s.evidenceRows = append(s.evidenceRows, *record)
	}
	endpoint := s.catalog.ObserveEndpoint(addr, "tcp", port, "open", s.now())
	endpointID := endpoint.ID
	_, created := s.appendObservation(Observation{
		ScanRunID: lease.RunID, ScanUnitID: lease.UnitID, StageAttemptID: lease.AttemptID, EndpointID: &endpointID,
		ObservationPointID: lease.ObservationPointID, Type: "protocol_response", SubjectKey: fmt.Sprintf("%s:%s:%d", protocol, addr.String(), port),
		ObservedAt: s.now(), CollectedAt: s.now(), ResultStatus: status, ValueSchemaVersion: "1", Value: value,
		EvidenceIDs: evidenceIDs, SourceKind: "network",
	})
	if created && (status == "observed" || status == "partial") {
		if err := s.identify(lease.RunID, endpointID, lease.ObservationPointID); err != nil {
			return err
		}
	}
	return s.flush(ctx)
}

func (s *Service) executeCollect(ctx context.Context, lease task.Lease) error {
	var input collectInput
	if err := json.Unmarshal(lease.Input, &input); err != nil {
		return err
	}
	results, err := collect.CollectRequested(input.Operations)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var assetID id.ID
	for _, result := range results {
		if result.MachineIDHash == "" || !assetID.IsZero() {
			continue
		}
		if machine, ok := s.catalog.ObserveMachine(result.MachineIDHash, result.PlatformFamily, result.PlatformName, result.PlatformVersion, s.now()); ok {
			assetID = machine.ID
		}
	}
	for _, result := range results {
		value := map[string]any{}
		for key, item := range result.Value {
			value[key] = item
		}
		value["collection_status"] = result.Status
		_, created := s.appendObservation(Observation{
			ScanRunID: lease.RunID, ScanUnitID: lease.UnitID, StageAttemptID: lease.AttemptID, AssetID: assetID,
			ObservationPointID: lease.ObservationPointID, Type: "host_inventory", SubjectKey: "local:" + result.Operation,
			ObservedAt: s.now(), CollectedAt: s.now(), ResultStatus: observationStatusForCollection(result.Status), ValueSchemaVersion: "1",
			Value: value, SourceKind: "local_collector",
		})
		if created && result.Operation == "collect_os_info" && !assetID.IsZero() {
			if err := s.evaluateConfig(lease, assetID); err != nil {
				return err
			}
		}
	}
	return s.flush(ctx)
}

func (s *Service) evaluateConfig(lease task.Lease, assetID id.ID) error {
	var facts []rule.Fact
	for _, item := range s.observations {
		if item.ScanRunID != lease.RunID || item.Type != "host_inventory" {
			continue
		}
		facts = append(facts, rule.Fact{ID: item.ID, Type: item.Type, Subject: item.SubjectKey, ResultStatus: item.ResultStatus, Value: item.Value})
	}
	version := rule.ConfigVersion
	if run, _, err := s.tasks.Snapshot(lease.RunID); err == nil && run.RulePackVersion != "" {
		version = run.RulePackVersion
	}
	var inputs []id.ID
	for _, fact := range facts {
		if !fact.ID.IsZero() {
			inputs = append(inputs, fact.ID)
		}
	}
	assessmentID := id.MustNew()
	for _, decision := range rule.EvaluateConfigs(rule.Configs(s.packs, version), facts) {
		matched, err := marshalCondition(decision.Matched)
		if err != nil {
			return err
		}
		unmatched, err := marshalCondition(decision.Unmatched)
		if err != nil {
			return err
		}
		detectionID := id.MustNew()
		s.detections = append(s.detections, Detection{
			ID: detectionID, AssessmentRunID: assessmentID, SubjectType: "asset", SubjectID: assetID,
			RuleID: decision.RuleID, RuleVersion: decision.RuleVersion, VulnerabilityID: decision.RuleKey,
			ResultStatus: decision.Status, Severity: decision.Severity, Summary: decision.Summary,
			Matched: matched, Unmatched: unmatched,
			InputObservationIDs: append([]id.ID(nil), inputs...), EvaluatedAt: s.now(),
		})
		if decision.Status != "confirmed" {
			continue
		}
		s.mergeFinding(id.ID{}, assetID, decision.RuleKey, detectionID, assessmentID, decision.RuleKey, "misconfiguration", decision.Severity, nil, decision.RuleID, id.ID{})
	}
	return nil
}

func marshalCondition(value map[string]any) (json.RawMessage, error) {
	if len(value) == 0 {
		return nil, nil
	}
	return json.Marshal(value)
}

func (s *Service) identify(runID, endpointID, pointID id.ID) error {
	var views []identity.ObservationView
	for _, item := range s.observations {
		if item.EndpointID != nil && *item.EndpointID == endpointID && item.Type == "protocol_response" {
			views = append(views, identity.ObservationView{ID: item.ID, Type: item.Type, Value: item.Value})
		}
	}
	version := identity.PackVersion
	if run, _, err := s.tasks.Snapshot(runID); err == nil && run.FingerprintPackVersion != "" {
		version = run.FingerprintPackVersion
	}
	found := identity.Identify(endpointID, pointID, views, rule.Fingerprints(s.packs, version), version, s.aliases, s.now())
	seen := map[string]struct{}{}
	for _, item := range s.hypotheses {
		seen[hypothesisKey(item)] = struct{}{}
	}
	for _, item := range found {
		key := hypothesisKey(item)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		s.hypotheses = append(s.hypotheses, item)
		var snapshotID id.ID
		if run, _, err := s.tasks.Snapshot(runID); err == nil {
			snapshotID = run.IntelSnapshotID
		}
		if err := s.judgeHypothesis(snapshotID, item); err != nil {
			return err
		}
	}
	return nil
}

func hypothesisKey(item identity.Hypothesis) string {
	parts := []string{item.EndpointID.String(), item.ObservationPointID.String(), item.ServiceType, item.RawProductName, item.RawVersion}
	for _, observationID := range item.SupportingObservationIDs {
		parts = append(parts, observationID.String())
	}
	return strings.Join(parts, "|")
}

// mergeFinding 合并同对象上的同一风险。severity 为空时保持空白，不用固定等级代替缺失的情报严重性。
// mergeFinding merges the same risk on one object. An empty severity stays empty and does not substitute a fixed level for missing intelligence severity.
func (s *Service) verifiedEvidence(observationIDs []id.ID) []id.ID {
	verified := map[id.ID]struct{}{}
	for _, row := range s.evidenceRows {
		if row.IntegrityStatus == "verified" {
			verified[row.ID] = struct{}{}
		}
	}
	var out []id.ID
	seen := map[id.ID]struct{}{}
	for _, observationID := range observationIDs {
		for _, item := range s.observations {
			if item.ID != observationID {
				continue
			}
			for _, evidenceID := range item.EvidenceIDs {
				if _, ok := verified[evidenceID]; !ok {
					continue
				}
				if _, ok := seen[evidenceID]; ok {
					continue
				}
				seen[evidenceID] = struct{}{}
				out = append(out, evidenceID)
			}
		}
	}
	return out
}

func (s *Service) mergeFinding(endpointID, assetID id.ID, vulnerabilityID string, detectionID, assessmentRunID id.ID, version, findingType, severity string, evidenceIDs []id.ID, ruleID, productID id.ID) {
	subject := endpointID
	if subject.IsZero() {
		subject = assetID
	}
	key := subject.String() + "|" + vulnerabilityID
	now := s.now()
	finding, ok := s.findings[key]
	if !ok {
		finding = &Finding{
			ID: id.MustNew(), FindingKey: key, FindingType: findingType, AssetID: assetID, EndpointID: endpointID,
			ProductID: productID, RuleID: ruleID, VulnerabilityID: vulnerabilityID,
			Title: vulnerabilityID, Severity: severity, Status: "open", FirstSeenAt: now, LastSeenAt: now,
		}
		s.findings[key] = finding
	} else {
		finding.LastSeenAt = now
		finding.Status = "open"
		if finding.Severity == "" {
			finding.Severity = severity
		}
		if finding.RuleID.IsZero() {
			finding.RuleID = ruleID
		}
		if finding.ProductID.IsZero() {
			finding.ProductID = productID
		}
	}
	occurrenceID := id.MustNew()
	s.occurrences = append(s.occurrences, Occurrence{
		ID: occurrenceID, FindingID: finding.ID, AssessmentRunID: assessmentRunID, DetectionID: detectionID, ObservedAt: now, Severity: severity,
		EvidenceIDs: append([]id.ID(nil), evidenceIDs...), ConditionDigest: digestOf(version + "|" + vulnerabilityID),
	})
	finding.LastOccurrenceID = occurrenceID
}

func (s *Service) appendObservation(item Observation) (Observation, bool) {
	if item.ID.IsZero() {
		item.ID = id.MustNew()
	}
	if item.SourceIdentity == "" && !s.worker.ID.IsZero() {
		item.SourceIdentity = s.worker.ID.String()
	}
	item.ContentDigest = digestOf(struct {
		Type   string
		Status string
		Value  map[string]any
	}{item.Type, item.ResultStatus, item.Value})
	key := item.ScanRunID.String() + "|" + item.ScanUnitID.String() + "|" + s.stageKey(item.ScanRunID, item.ScanUnitID) + "|" + item.Type + "|" + item.SubjectKey + "|" + item.ContentDigest
	if existing, ok := s.idempotency[key]; ok {
		for _, saved := range s.observations {
			if saved.ID == existing {
				return saved, false
			}
		}
	}
	s.idempotency[key] = item.ID
	s.observations = append(s.observations, item)
	return item, true
}

func (s *Service) stageKey(runID, unitID id.ID) string {
	if runID.IsZero() || unitID.IsZero() {
		return ""
	}
	_, units, err := s.tasks.Snapshot(runID)
	if err != nil {
		return ""
	}
	for _, unit := range units {
		if unit.ID == unitID {
			return unit.StageKey
		}
	}
	return ""
}

func (s *Service) dialer(lease task.Lease, account *scope.Account) probesdk.Dialer {
	return probesdk.Dialer{Auth: authFunc(func(ctx context.Context, ip netip.Addr, port int, transport, operation string) error {
		s.mu.Lock()
		defer s.mu.Unlock()
		if err := s.commitState(ctx, func() error {
			return s.tasks.Renew(lease, s.now())
		}); err != nil {
			return err
		}
		run, _, err := s.tasks.Snapshot(lease.RunID)
		if err != nil {
			return err
		}
		if run.Status == task.RunCancelling || run.Status == task.RunCancelled {
			return context.Canceled
		}
		grant, ok := s.frozen[lease.RunID]
		if !ok {
			return fmt.Errorf("grant snapshot missing")
		}
		live, ok := s.grants[grant.ID]
		if !ok || live.Status != scope.StatusActive {
			grant.Status = scope.StatusRevoked
		}
		decision := grant.Check(scope.CheckInput{
			IP: ip, Port: port, Transport: transport, Operation: operation, ObservationPointID: s.pointID, Now: s.now(),
		})
		if !decision.Allowed {
			return fmt.Errorf("%s", decision.Code)
		}
		return nil
	}), Budget: account, Timeout: s.DialTimeout, Now: s.now}
}

type authFunc func(context.Context, netip.Addr, int, string, string) error

func (f authFunc) Authorize(ctx context.Context, ip netip.Addr, port int, transport, operation string) error {
	return f(ctx, ip, port, transport, operation)
}

// evidenceContent 返回已存储字节的真实类型和编码。文件按原始字节发布，因此编码是 identity。
// evidenceContent returns the actual type and encoding of the stored bytes. Files are published as raw bytes, so the encoding is identity.
func evidenceContent(protocol string) (string, string) {
	switch protocol {
	case "http":
		return "application/http", "identity"
	case "tls":
		return "application/pkix-cert", "identity"
	case "ssh":
		return "text/plain", "identity"
	default:
		return "", "identity"
	}
}

// observationStatusForCollection 把采集状态映射到观察结果状态。采集状态本身写入 value.collection_status。
// observationStatusForCollection maps a collection status onto an observation result status. The collection status itself is stored in value.collection_status.
func observationStatusForCollection(status string) string {
	switch status {
	case collect.StatusCollected, collect.StatusEmpty:
		return "observed"
	case collect.StatusUnsupported:
		return "unsupported"
	case collect.StatusNotRequested:
		return "not_scanned"
	default:
		return "error"
	}
}

func reachStatus(state string) string {
	switch state {
	case "reachable":
		return "observed"
	case "no_response":
		return "no_response"
	case "unreachable":
		return "unreachable"
	case "error":
		return "error"
	default:
		return "not_scanned"
	}
}

func portResultStatus(state string) string {
	switch state {
	case "open", "closed":
		return "observed"
	case "no_response":
		return "no_response"
	case "unreachable":
		return "unreachable"
	case "unsupported":
		return "unsupported"
	case "not_scanned":
		return "not_scanned"
	default:
		return "error"
	}
}

func endpointState(state string) string {
	switch state {
	case "open", "closed", "no_response", "unreachable":
		return state
	default:
		return "unknown"
	}
}

func mapApplicability(value string) string {
	switch value {
	case assess.Affected:
		return "confirmed"
	case assess.NotAffected:
		return "not_vulnerable"
	case assess.InsufficientEvidence:
		return "insufficient_evidence"
	default:
		return "unknown"
	}
}
