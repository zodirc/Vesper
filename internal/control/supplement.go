package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"time"

	"github.com/zodirc/Vesper/internal/asset"
	"github.com/zodirc/Vesper/internal/collect"
	"github.com/zodirc/Vesper/internal/id"
	"github.com/zodirc/Vesper/internal/scope"
	"github.com/zodirc/Vesper/internal/task"
)

// ReassessOptions 选择补充采集的证据时限和授权。
// ReassessOptions selects the evidence age limit and authorization for supplemental collection.
//
// MaxAge 为 0 时，使用当前启用的 reassessment 周期里最短的间隔。没有这种周期时，只为缺失证据生成采集，不按时间把证据判为过期。
// GrantID 非零时只使用该授权。为零时，在能够覆盖目标的有效授权中选择 ValidFrom 最早的一条。
// When MaxAge is zero, the shortest interval among enabled reassessment schedules is used. With no such schedule, collection is created only for missing evidence, and age alone does not make evidence expired.
// A non-zero GrantID restricts collection to that grant. Zero selects the covering active grant with the earliest ValidFrom.
type ReassessOptions struct {
	MaxAge  time.Duration
	GrantID id.ID
}

// ReassessResult 是一次重新评估追加的检测，以及补充采集的数量。
// ReassessResult is the number of detections one reassessment appended and the supplemental collection counts.
type ReassessResult struct {
	// Detections 是这次新写入的检测结果数量。
	// Detections is the number of detection results written this time.
	Detections int
	// Supplemental 是新创建的补充采集运行数量。
	// Supplemental is the number of supplemental collection runs created.
	Supplemental int
	// Uncovered 是证据已过期或缺失，但没有可用授权或没有可采集地址的目标数量。
	// Uncovered is the number of targets whose evidence is expired or missing but which have no usable grant or no collectable address.
	Uncovered int
}

type supplementRequest struct {
	Name     string
	Kind     string
	Endpoint asset.Endpoint
	AssetID  id.ID
	GrantID  id.ID
}

// supplementalTargets 找出证据过期或缺失、并且当前风险或服务候选仍依赖它的目标。调用方必须持有 s.mu。
// supplementalTargets finds targets whose evidence is expired or missing while a current risk or service candidate still depends on it. The caller must hold s.mu.
func (s *Service) supplementalTargets(now time.Time, maxAge time.Duration, grantID id.ID) ([]supplementRequest, int) {
	now = now.UTC()
	var requests []supplementRequest
	uncovered := 0
	for _, endpointID := range s.endpointSubjects() {
		latest, _ := s.latestEndpointObservation(endpointID)
		if !s.evidenceStale(latest, now, maxAge) {
			continue
		}
		endpoint, ok := s.catalog.Endpoints[endpointID]
		if !ok || endpoint.Port < 1 || (endpoint.Transport != "tcp" && endpoint.Transport != "udp") {
			uncovered++
			continue
		}
		name := "supplemental:" + endpoint.Transport + ":" + endpoint.Address.String() + ":" + strconv.Itoa(endpoint.Port)
		if s.supplementalPending(name) {
			continue
		}
		chosen, ok := s.grantForEndpoint(endpoint, now, grantID)
		if !ok {
			uncovered++
			continue
		}
		requests = append(requests, supplementRequest{Name: name, Kind: "endpoint", Endpoint: endpoint, GrantID: chosen})
	}
	for _, assetID := range s.hostSubjects() {
		latest, local := s.latestLocalHostObservation(assetID)
		if !local {
			uncovered++
			continue
		}
		if !s.evidenceStale(latest, now, maxAge) {
			continue
		}
		name := "supplemental:host:" + assetID.String()
		if s.supplementalPending(name) {
			continue
		}
		chosen, ok := s.grantForHost(now, grantID)
		if !ok {
			uncovered++
			continue
		}
		requests = append(requests, supplementRequest{Name: name, Kind: "host", AssetID: assetID, GrantID: chosen})
	}
	sort.Slice(requests, func(i, j int) bool { return requests[i].Name < requests[j].Name })
	return requests, uncovered
}

func (s *Service) endpointSubjects() []id.ID {
	seen := map[string]id.ID{}
	for _, item := range s.hypotheses {
		if !item.EndpointID.IsZero() {
			seen[item.EndpointID.String()] = item.EndpointID
		}
	}
	for _, item := range s.findings {
		if item != nil && !item.EndpointID.IsZero() && findingNeedsEvidence(item.Status) {
			seen[item.EndpointID.String()] = item.EndpointID
		}
	}
	return sortedIDs(seen)
}

func (s *Service) hostSubjects() []id.ID {
	seen := map[string]id.ID{}
	for _, item := range s.findings {
		if item == nil || item.AssetID.IsZero() || !item.EndpointID.IsZero() || !findingNeedsEvidence(item.Status) {
			continue
		}
		seen[item.AssetID.String()] = item.AssetID
	}
	return sortedIDs(seen)
}

func sortedIDs(seen map[string]id.ID) []id.ID {
	keys := make([]string, 0, len(seen))
	for key := range seen {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]id.ID, 0, len(keys))
	for _, key := range keys {
		out = append(out, seen[key])
	}
	return out
}

func findingNeedsEvidence(status string) bool {
	switch status {
	case "open", "confirmed", "reopened":
		return true
	default:
		return false
	}
}

func (s *Service) latestEndpointObservation(endpointID id.ID) (Observation, bool) {
	var latest Observation
	found := false
	for _, item := range s.observations {
		if item.EndpointID == nil || *item.EndpointID != endpointID {
			continue
		}
		if item.ResultStatus != "observed" && item.ResultStatus != "partial" {
			continue
		}
		if !found || item.CollectedAt.After(latest.CollectedAt) {
			latest = item
			found = true
		}
	}
	return latest, found
}

func (s *Service) latestLocalHostObservation(assetID id.ID) (Observation, bool) {
	var latest Observation
	found := false
	sawLocal := false
	for _, item := range s.observations {
		if item.AssetID != assetID || item.Type != "host_inventory" || item.SourceKind != "local_collector" {
			continue
		}
		sawLocal = true
		if item.ResultStatus != "observed" && item.ResultStatus != "partial" {
			continue
		}
		if !found || item.CollectedAt.After(latest.CollectedAt) {
			latest = item
			found = true
		}
	}
	if !sawLocal {
		return Observation{}, false
	}
	return latest, true
}

func (s *Service) evidenceStale(latest Observation, now time.Time, maxAge time.Duration) bool {
	if latest.ID.IsZero() || latest.CollectedAt.IsZero() {
		return true
	}
	if !s.evidenceUsable(latest.EvidenceIDs) {
		return true
	}
	if maxAge <= 0 {
		return false
	}
	return !latest.CollectedAt.Add(maxAge).After(now)
}

func (s *Service) evidenceUsable(ids []id.ID) bool {
	for _, evidenceID := range ids {
		found := false
		for _, row := range s.evidenceRows {
			if row.ID != evidenceID {
				continue
			}
			found = true
			if row.IntegrityStatus != "verified" {
				return false
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func (s *Service) supplementalPending(name string) bool {
	runs, _, _ := s.tasks.Export()
	for _, run := range runs {
		if run.TriggerType != "supplemental" || run.Name != name {
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

func (s *Service) grantForEndpoint(endpoint asset.Endpoint, now time.Time, preferred id.ID) (id.ID, bool) {
	for _, grant := range s.candidateGrants(preferred) {
		operation, err := planOperation(grant, endpoint.Transport)
		if err != nil {
			continue
		}
		decision := grant.Check(scope.CheckInput{
			IP: endpoint.Address, Port: endpoint.Port, Transport: endpoint.Transport, Operation: operation,
			ObservationPointID: s.pointID, Now: now,
		})
		if decision.Allowed {
			return grant.ID, true
		}
	}
	return id.ID{}, false
}

func (s *Service) grantForHost(now time.Time, preferred id.ID) (id.ID, bool) {
	for _, grant := range s.candidateGrants(preferred) {
		if !containsOperation(grant, scope.OpConfigCheck) {
			continue
		}
		if !grantCoversPoint(grant, s.pointID, now) {
			continue
		}
		return grant.ID, true
	}
	return id.ID{}, false
}

func (s *Service) candidateGrants(preferred id.ID) []scope.Grant {
	if !preferred.IsZero() {
		grant, ok := s.grants[preferred]
		if !ok {
			return nil
		}
		return []scope.Grant{grant}
	}
	grants := make([]scope.Grant, 0, len(s.grants))
	for _, grant := range s.grants {
		grants = append(grants, grant)
	}
	sort.Slice(grants, func(i, j int) bool {
		if !grants[i].ValidFrom.Equal(grants[j].ValidFrom) {
			return grants[i].ValidFrom.Before(grants[j].ValidFrom)
		}
		return grants[i].ID.String() < grants[j].ID.String()
	})
	return grants
}

func grantCoversPoint(grant scope.Grant, point id.ID, now time.Time) bool {
	if grant.Status != scope.StatusActive || now.Before(grant.ValidFrom.UTC()) {
		return false
	}
	if grant.ValidUntil != nil && !now.Before(grant.ValidUntil.UTC()) {
		return false
	}
	for _, item := range grant.ObservationPointIDs {
		if item == point {
			return true
		}
	}
	return false
}

func (s *Service) evidenceMaxAge() time.Duration {
	var shortest int64
	for _, item := range s.schedules {
		if item.TriggerType != "reassessment" || item.Status != scheduleEnabled || item.IntervalSeconds < 1 {
			continue
		}
		if shortest == 0 || item.IntervalSeconds < shortest {
			shortest = item.IntervalSeconds
		}
	}
	return time.Duration(shortest) * time.Second
}

func (s *Service) createSupplemental(ctx context.Context, requests []supplementRequest) (int, int, error) {
	created := 0
	uncovered := 0
	now := s.now().UTC()
	for _, item := range requests {
		var err error
		switch item.Kind {
		case "endpoint":
			_, err = s.startSupplementalEndpoint(ctx, item, now)
		case "host":
			_, err = s.startSupplementalHost(ctx, item, now)
		default:
			err = fmt.Errorf("supplemental collection: subject %s", item.Kind)
		}
		if err != nil {
			return created, uncovered, err
		}
		created++
	}
	return created, uncovered, nil
}

func (s *Service) startSupplementalEndpoint(ctx context.Context, item supplementRequest, now time.Time) (task.Run, error) {
	port := item.Endpoint.Port
	target, err := asset.ParseTarget("endpoint", item.Endpoint.Address.String(), item.Endpoint.Transport, &port, now)
	if err != nil {
		return task.Run{}, err
	}
	return s.startScan(ctx, preparedScan{
		Name: item.Name, Target: target, Transport: item.Endpoint.Transport, Ports: []int{port},
		GrantID: item.GrantID, Trigger: "supplemental",
	}, now)
}

func (s *Service) startSupplementalHost(ctx context.Context, item supplementRequest, now time.Time) (task.Run, error) {
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
		grant, ok := s.grants[item.GrantID]
		if !ok {
			return fmt.Errorf("create scan: grant not found")
		}
		if !grantCoversPoint(grant, s.pointID, now) || !containsOperation(grant, scope.OpConfigCheck) {
			return planFailure{summary: "operation_denied"}
		}
		digest, err := grant.Digest()
		if err != nil {
			return err
		}
		body, err := json.Marshal(planBody{
			Environment: &environment, ConfigRules: s.publishedConfigPacks(),
			SupplementalSubject: "host:" + item.AssetID.String(),
		})
		if err != nil {
			return err
		}
		budget, err := budgetSnapshot(grant)
		if err != nil {
			return err
		}
		target := asset.Target{ID: targetID, TargetType: "asset", RawValue: item.AssetID.String(), NormalizedValue: item.AssetID.String(), CreatedAt: now}
		s.catalog.AddTarget(target)
		run := versionedRun(task.Run{
			ID: runID, Name: item.Name, TargetIDs: []id.ID{target.ID}, ScopeGrantID: grant.ID, ScopeDigest: digest,
			TriggerType: "supplemental", EffectiveBudget: budget, IntelSnapshotID: s.latestSnapshotID(),
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
		payload, err := json.Marshal(map[string]any{"operations": collect.Operations})
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
			return s.failPlanning(runID, failed.Error(), now)
		}
		return task.Run{}, err
	}
	s.mu.Lock()
	run, _, err := s.tasks.Snapshot(runID)
	s.mu.Unlock()
	return run, err
}
