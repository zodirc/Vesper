// Package identity 只根据已有观察生成服务候选，不发起网络连接，也不用端口号补齐产品。
// Package identity creates service candidates only from existing observations. It does not open network connections or fill in a product from a port number.
package identity

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/zodirc/Vesper/internal/assess"
	"github.com/zodirc/Vesper/internal/id"
	"github.com/zodirc/Vesper/internal/rule"
)

const PackVersion = rule.FingerprintVersion

// ObservationView 是识别引擎读取的观察投影。
// ObservationView is the observation projection read by the identification engine.
//
// Response 是该观察已校验的原始响应。识别不从端口或未校验字节补齐产品。
// Response is the verified raw response for that observation. Identification does not fill in a product from a port or from unverified bytes.
type ObservationView struct {
	ID       id.ID
	Type     string
	Value    map[string]any
	Response []byte
}

// Hypothesis 是一条服务身份候选。
// Hypothesis is one service-identity candidate.
type Hypothesis struct {
	ID                          id.ID
	AssessmentRunID             id.ID
	EndpointID                  id.ID
	ObservationPointID          id.ID
	ServiceType                 string
	ProductIdentityID           *id.ID
	RawProductName              string
	RawVersion                  string
	NormalizedVersion           string
	Confidence                  string
	IdentityStatus              string
	SupportingObservationIDs    []id.ID
	ContradictingObservationIDs []id.ID
	FingerprintRuleIDs          []id.ID
	FingerprintPackVersion      string
	EvaluatedAt                 time.Time
}

// Alias 是外部产品名到规范产品的映射。没有唯一映射时保留原始名称，不绑定产品。
// Alias maps an external product name to a canonical product. The raw name is kept and no product is bound when the mapping is not unique.
type Alias struct {
	ID        id.ID
	ProductID id.ID
	Source    string
	AliasType string
	Ecosystem string
	Value     string
}

// Identify 用已发布指纹规则从已有观察生成候选。识别不发起网络连接，也不用端口号补齐产品。
// Identify creates candidates from existing observations with published fingerprint rules. Identification does not open network connections or fill in a product from a port number.
//
// 不同服务类型可以同时成立。同一服务出现不同的非空产品或不同的非空版本时，相关候选记为 conflict，并引用对方的支持观察。只确认协议、没有产品的观察不单独否定已经提取出的产品。
// 排除条件命中时，不从该规则提取产品；若同一服务已有候选，则把该观察记为冲突证据。
// Different service types may stand together. When one service has different non-empty products or different non-empty versions, those candidates are marked conflict and cite the other candidate's supporting observations. An observation that confirms only the protocol does not by itself negate a product already extracted.
// An exclusion match does not extract a product from that rule. If the same service already has a candidate, that observation is recorded as contradicting evidence.
//
// 原始产品名和版本始终保留。只有一个产品别名时绑定该产品，并按生态写入规范化版本。没有别名或对应多个产品时不绑定产品，状态为 unknown。第 4.14 节的身份状态没有 ambiguous，因此多个映射也记为 unknown。
// The raw product name and version are always kept. A product is bound only when one alias matches, and the normalized version is written for that ecosystem. No product is bound when there is no alias or the name maps to more than one product, and the status is unknown. Section 4.14 has no ambiguous identity status, so multiple mappings are also recorded as unknown.
//
// 同一服务、产品和版本的多次命中合并为一条候选，置信度保留数值较高的规则原文。优先级只决定同一观察内的求值顺序，不丢弃较低优先级的不同产品。rules 为空时不生成候选。
// Repeated hits for the same service, product, and version merge into one candidate, keeping the rule's original confidence text when its numeric value is higher. Priority orders evaluation within one observation and does not discard a different product from a lower-priority rule. An empty rule list produces no candidates.
func Identify(endpointID, pointID id.ID, observations []ObservationView, rules []rule.FingerprintRule, packVersion string, aliases []Alias, now time.Time) []Hypothesis {
	var found []Hypothesis
	var exclusions []exclusion
	for _, obs := range observations {
		hits := rule.MatchFingerprints(rules, rule.Fact{ID: obs.ID, Type: obs.Type, Value: obs.Value, Response: obs.Response})
		for _, hit := range hits {
			if hit.Status == "excluded" {
				exclusions = append(exclusions, exclusion{Service: hit.ServiceType, ObservationID: obs.ID, RuleID: hit.RuleID})
				continue
			}
			item := baseHypothesis(endpointID, pointID, obs, hit, rulePackVersion(rules, hit.RuleID, packVersion), now)
			if hit.Product != "" {
				productID, ecosystem, matched := resolveAlias(aliases, hit.Product)
				if matched {
					item.ProductIdentityID = &productID
					item.IdentityStatus = "candidate"
					if normalized, ok := assess.NormalizeVersion(ecosystem, hit.Version); ok {
						item.NormalizedVersion = normalized
					}
				} else {
					item.IdentityStatus = "unknown"
				}
			}
			found = append(found, item)
		}
	}
	found = mergeCompatible(found)
	markProductConflicts(found)
	applyExclusions(found, exclusions)
	if len(found) == 0 {
		return nil
	}
	assessmentID := id.MustNew()
	for i := range found {
		found[i].AssessmentRunID = assessmentID
	}
	return found
}

type exclusion struct {
	Service       string
	ObservationID id.ID
	RuleID        id.ID
}

// mergeCompatible 合并同一服务、产品和版本。该服务恰好有一个非空产品时，把只确认协议的观察并入该产品。
// mergeCompatible merges one service, product, and version. When that service has exactly one non-empty product, observations that confirm only the protocol join that product.

func mergeCompatible(items []Hypothesis) []Hypothesis {
	type productKey struct {
		service string
		product string
		version string
	}
	positions := map[productKey]int{}
	var out []Hypothesis
	var protocolOnly []Hypothesis
	for _, item := range items {
		if item.RawProductName == "" {
			protocolOnly = append(protocolOnly, item)
			continue
		}
		key := productKey{item.ServiceType, item.RawProductName, item.RawVersion}
		if pos, ok := positions[key]; ok {
			out[pos] = combineHypothesis(out[pos], item)
			continue
		}
		positions[key] = len(out)
		out = append(out, item)
	}
	productCount := map[string]int{}
	for _, item := range out {
		productCount[item.ServiceType]++
	}
	protocolPos := map[string]int{}
	for _, item := range protocolOnly {
		switch productCount[item.ServiceType] {
		case 1:
			for i := range out {
				if out[i].ServiceType == item.ServiceType {
					out[i] = combineHypothesis(out[i], item)
				}
			}
		default:
			if pos, ok := protocolPos[item.ServiceType]; ok {
				out[pos] = combineHypothesis(out[pos], item)
				continue
			}
			protocolPos[item.ServiceType] = len(out)
			out = append(out, item)
		}
	}
	return out
}

func combineHypothesis(base, extra Hypothesis) Hypothesis {
	base.SupportingObservationIDs = unionIDs(base.SupportingObservationIDs, extra.SupportingObservationIDs)
	base.FingerprintRuleIDs = unionIDs(base.FingerprintRuleIDs, extra.FingerprintRuleIDs)
	if confidenceLess(base.Confidence, extra.Confidence) {
		base.Confidence = extra.Confidence
		if extra.FingerprintPackVersion != "" {
			base.FingerprintPackVersion = extra.FingerprintPackVersion
		}
	}
	if base.RawProductName == "" && extra.RawProductName != "" {
		base.RawProductName = extra.RawProductName
		base.RawVersion = extra.RawVersion
		base.NormalizedVersion = extra.NormalizedVersion
		base.ProductIdentityID = extra.ProductIdentityID
		base.IdentityStatus = extra.IdentityStatus
		if extra.FingerprintPackVersion != "" {
			base.FingerprintPackVersion = extra.FingerprintPackVersion
		}
	}
	return base
}

func rulePackVersion(rules []rule.FingerprintRule, ruleID id.ID, fallback string) string {
	for _, item := range rules {
		if item.ID == ruleID && item.PackVersion != "" {
			return item.PackVersion
		}
	}
	return fallback
}

func markProductConflicts(items []Hypothesis) {
	type versionKey struct {
		product string
		version string
	}
	grouped := map[string]map[versionKey]struct{}{}
	for _, item := range items {
		if item.RawProductName == "" {
			continue
		}
		if grouped[item.ServiceType] == nil {
			grouped[item.ServiceType] = map[versionKey]struct{}{}
		}
		grouped[item.ServiceType][versionKey{item.RawProductName, item.RawVersion}] = struct{}{}
	}
	for i := range items {
		if items[i].RawProductName == "" || len(grouped[items[i].ServiceType]) < 2 {
			continue
		}
		items[i].IdentityStatus = "conflict"
		items[i].ContradictingObservationIDs = contradictingObservations(items, i)
	}
}

func applyExclusions(items []Hypothesis, exclusions []exclusion) {
	for _, item := range exclusions {
		for i := range items {
			if items[i].ServiceType != item.Service {
				continue
			}
			items[i].IdentityStatus = "conflict"
			items[i].FingerprintRuleIDs = unionIDs(items[i].FingerprintRuleIDs, []id.ID{item.RuleID})
			items[i].ContradictingObservationIDs = unionIDs(items[i].ContradictingObservationIDs, []id.ID{item.ObservationID})
		}
	}
}

func unionIDs(base, extra []id.ID) []id.ID {
	seen := map[id.ID]struct{}{}
	for _, item := range base {
		seen[item] = struct{}{}
	}
	for _, item := range extra {
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		base = append(base, item)
	}
	return base
}

func confidenceLess(current, next string) bool {
	left, leftErr := strconv.ParseFloat(current, 64)
	right, rightErr := strconv.ParseFloat(next, 64)
	if leftErr != nil || rightErr != nil {
		return false
	}
	return left < right
}

func contradictingObservations(items []Hypothesis, index int) []id.ID {
	own := map[id.ID]struct{}{}
	for _, observationID := range items[index].SupportingObservationIDs {
		own[observationID] = struct{}{}
	}
	seen := map[id.ID]struct{}{}
	var out []id.ID
	for other := range items {
		if other == index || items[other].ServiceType != items[index].ServiceType || items[other].RawProductName == "" {
			continue
		}
		if items[other].RawProductName == items[index].RawProductName && items[other].RawVersion == items[index].RawVersion {
			continue
		}
		for _, observationID := range items[other].SupportingObservationIDs {
			if _, ok := own[observationID]; ok {
				continue
			}
			if _, ok := seen[observationID]; ok {
				continue
			}
			seen[observationID] = struct{}{}
			out = append(out, observationID)
		}
	}
	return out
}

func baseHypothesis(endpointID, pointID id.ID, obs ObservationView, hit rule.Hit, packVersion string, now time.Time) Hypothesis {
	if packVersion == "" {
		packVersion = PackVersion
	}
	return Hypothesis{
		ID: id.MustNew(), EndpointID: endpointID, ObservationPointID: pointID, ServiceType: hit.ServiceType,
		RawProductName: hit.Product, RawVersion: hit.Version, Confidence: hit.Confidence, IdentityStatus: hit.Status,
		SupportingObservationIDs: []id.ID{obs.ID}, FingerprintRuleIDs: []id.ID{hit.RuleID},
		FingerprintPackVersion: packVersion, EvaluatedAt: now.UTC(),
	}
}

func resolveAlias(aliases []Alias, product string) (id.ID, string, bool) {
	var matched []Alias
	for _, alias := range aliases {
		if strings.EqualFold(alias.Value, product) {
			matched = append(matched, alias)
		}
	}
	if len(matched) == 0 {
		return id.ID{}, "", false
	}
	productID := matched[0].ProductID
	for _, alias := range matched[1:] {
		if alias.ProductID != productID {
			return id.ID{}, "", false
		}
	}
	return productID, matched[0].Ecosystem, true
}

// DecodeValue 把观察 JSON 解码为识别输入。
// DecodeValue decodes observation JSON into identification input.
func DecodeValue(raw []byte) (map[string]any, error) {
	if len(raw) == 0 {
		return map[string]any{}, nil
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out, nil
}
