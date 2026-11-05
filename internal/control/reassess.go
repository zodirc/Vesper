package control

import (
	"sort"

	"github.com/zodirc/Vesper/internal/id"
	"github.com/zodirc/Vesper/internal/identity"
	"github.com/zodirc/Vesper/internal/rule"
)

// reidentify 用当前内置指纹和已发布的 Nmap 指纹重读已有端点观察，只追加新的服务候选，然后按选定快照判断。
// reidentify rereads stored endpoint observations with the current builtin fingerprints and published Nmap fingerprints, appends only new service candidates, and judges them with the selected snapshot.
func (s *Service) reidentify(snapshotID id.ID) error {
	points := map[string]id.ID{}
	var endpoints []id.ID
	for _, item := range s.observations {
		if item.EndpointID == nil || item.EndpointID.IsZero() {
			continue
		}
		key := item.EndpointID.String()
		if _, ok := points[key]; ok {
			continue
		}
		point := item.ObservationPointID
		if point.IsZero() {
			point = s.pointID
		}
		points[key] = point
		endpoints = append(endpoints, *item.EndpointID)
	}
	sort.Slice(endpoints, func(i, j int) bool { return endpoints[i].String() < endpoints[j].String() })
	rules := rule.Fingerprints(s.packs, identity.PackVersion)
	for _, extra := range s.publishedNmapFingerprints() {
		rules = append(rules, rule.FrozenFingerprints(s.packs, extra)...)
	}
	for _, endpointID := range endpoints {
		var views []identity.ObservationView
		for _, item := range s.observations {
			if item.EndpointID != nil && *item.EndpointID == endpointID {
				views = append(views, identity.ObservationView{ID: item.ID, Type: item.Type, Value: item.Value})
			}
		}
		for i := range views {
			response, err := s.observationResponse(views[i].ID)
			if err != nil {
				return err
			}
			views[i].Response = response
		}
		found := identity.Identify(endpointID, points[endpointID.String()], views, rules, identity.PackVersion, s.aliases, s.now())
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
			if err := s.judgeHypothesis(snapshotID, item); err != nil {
				return err
			}
		}
	}
	return nil
}

// reevaluateConfigs 用当前已发布的配置规则判断每个资产最新的主机观察。旧观察和旧检测结果不改写。
// reevaluateConfigs judges each asset's latest host observations with the currently published configuration rules. Old observations and detection results are not rewritten.
func (s *Service) reevaluateConfigs(snapshotID id.ID) error {
	latest := map[string]Observation{}
	for _, item := range s.observations {
		status, _ := item.Value["collection_status"].(string)
		if item.Type != "host_inventory" || item.ResultStatus != "observed" || item.AssetID.IsZero() || status == "" {
			continue
		}
		key := item.AssetID.String() + "|" + item.SubjectKey
		previous, ok := latest[key]
		if !ok || item.CollectedAt.After(previous.CollectedAt) {
			latest[key] = item
		}
	}
	byAsset := map[string][]rule.Fact{}
	var assets []string
	for _, item := range latest {
		key := item.AssetID.String()
		if _, ok := byAsset[key]; !ok {
			assets = append(assets, key)
		}
		byAsset[key] = append(byAsset[key], rule.Fact{
			ID: item.ID, Type: item.Type, Subject: item.SubjectKey, ResultStatus: item.ResultStatus, Value: item.Value,
		})
	}
	sort.Strings(assets)
	rules := rule.Configs(s.packs, rule.ConfigVersion)
	for _, extra := range s.publishedConfigPacks() {
		rules = append(rules, rule.FrozenConfigs(s.packs, extra)...)
	}
	for _, assetKey := range assets {
		facts := byAsset[assetKey]
		sort.Slice(facts, func(i, j int) bool { return facts[i].ID.String() < facts[j].ID.String() })
		var assetID id.ID
		var inputs []id.ID
		for _, fact := range facts {
			if !fact.ID.IsZero() {
				inputs = append(inputs, fact.ID)
			}
			for _, item := range latest {
				if item.ID == fact.ID {
					assetID = item.AssetID
				}
			}
		}
		assessmentID, err := id.New()
		if err != nil {
			return err
		}
		for _, decision := range rule.EvaluateConfigs(rules, facts) {
			matched, err := marshalCondition(decision.Matched)
			if err != nil {
				return err
			}
			unmatched, err := marshalCondition(decision.Unmatched)
			if err != nil {
				return err
			}
			detection := Detection{
				AssessmentRunID: assessmentID, IntelSnapshotID: snapshotID, SubjectType: "asset", SubjectID: assetID,
				RuleID: decision.RuleID, RuleVersion: decision.RuleVersion, VulnerabilityID: decision.RuleKey,
				ResultStatus: decision.Status, Severity: decision.Severity, Summary: decision.Summary,
				Matched: matched, Unmatched: unmatched,
				InputObservationIDs: append([]id.ID(nil), inputs...), EvaluatedAt: s.now(),
			}
			if s.duplicateDetection(detection) {
				continue
			}
			detectionID, err := id.New()
			if err != nil {
				return err
			}
			detection.ID = detectionID
			s.detections = append(s.detections, detection)
			if decision.Status != "confirmed" {
				continue
			}
			s.mergeFinding(id.ID{}, assetID, decision.RuleKey, detectionID, assessmentID, decision.RuleKey, "misconfiguration", decision.Severity, nil, decision.RuleID, id.ID{})
			if decision.Title != "" {
				if finding := s.findings[assetID.String()+"|"+decision.RuleKey]; finding != nil {
					finding.Title = decision.Title
				}
			}
		}
	}
	return nil
}

// duplicateDetection 判断同一快照是否已经记录了同一主体、同一规则和同一输入上的相同结论。
// duplicateDetection reports whether the same snapshot already recorded the same conclusion for the same subject, rule, and inputs.
func (s *Service) duplicateDetection(item Detection) bool {
	for _, existing := range s.detections {
		if existing.IntelSnapshotID != item.IntelSnapshotID || existing.SubjectType != item.SubjectType || existing.SubjectID != item.SubjectID || existing.EndpointID != item.EndpointID || existing.VulnerabilityID != item.VulnerabilityID || existing.RuleID != item.RuleID || existing.RuleVersion != item.RuleVersion || existing.ResultStatus != item.ResultStatus || existing.Summary != item.Summary {
			continue
		}
		if !sameIDSet(existing.InputObservationIDs, item.InputObservationIDs) || !sameIDSet(existing.EvidenceIDs, item.EvidenceIDs) {
			continue
		}
		return true
	}
	return false
}

func sameIDSet(left, right []id.ID) bool {
	if len(left) != len(right) {
		return false
	}
	a := append([]id.ID(nil), left...)
	b := append([]id.ID(nil), right...)
	sort.Slice(a, func(i, j int) bool { return a[i].String() < a[j].String() })
	sort.Slice(b, func(i, j int) bool { return b[i].String() < b[j].String() })
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
