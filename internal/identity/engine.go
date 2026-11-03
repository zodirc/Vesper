// Package identity 只根据已有观察生成服务候选，不发起网络连接，也不用端口号补齐产品。
// Package identity creates service candidates only from existing observations. It does not open network connections or fill in a product from a port number.
package identity

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/zodirc/Vesper/internal/id"
	"github.com/zodirc/Vesper/internal/rule"
)

const PackVersion = rule.FingerprintVersion

// ObservationView 是识别引擎读取的观察投影。
// ObservationView is the observation projection read by the identification engine.
type ObservationView struct {
	ID    id.ID
	Type  string
	Value map[string]any
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
	Confidence                  string
	IdentityStatus              string
	SupportingObservationIDs    []id.ID
	ContradictingObservationIDs []id.ID
	FingerprintRuleIDs          []id.ID
	FingerprintPackVersion      string
	EvaluatedAt                 time.Time
}

// Alias 是外部产品名到规范产品的映射。没有映射时保留原始名称。
// Alias maps an external product name to a canonical product. The raw name is kept when no mapping exists.
type Alias struct {
	ID        id.ID
	ProductID id.ID
	Source    string
	AliasType string
	Value     string
}

// Identify 用已发布指纹规则从协议观察生成候选。多种协议同时成立时，候选标记为 conflict。
// Identify creates candidates from protocol observations with published fingerprint rules. Candidates are marked conflict when more than one protocol is supported.
//
// rules 为空时不生成候选，也不根据端口号补齐服务。
// An empty rule list produces no candidates and does not fill in a service from a port number.
func Identify(endpointID, pointID id.ID, observations []ObservationView, rules []rule.FingerprintRule, packVersion string, aliases []Alias, now time.Time) []Hypothesis {
	var found []Hypothesis
	for _, obs := range observations {
		hits := rule.MatchFingerprints(rules, rule.Fact{ID: obs.ID, Type: obs.Type, Value: obs.Value})
		for _, hit := range hits {
			item := baseHypothesis(endpointID, pointID, obs, hit, packVersion, now)
			if productID, ok := findAlias(aliases, hit.Product); ok {
				item.ProductIdentityID = &productID
				if item.IdentityStatus != "conflict" {
					item.IdentityStatus = "candidate"
				}
			}
			found = append(found, item)
		}
	}
	assessmentID := id.MustNew()
	for i := range found {
		found[i].AssessmentRunID = assessmentID
	}
	if distinctServices(found) > 1 {
		for i := range found {
			found[i].IdentityStatus = "conflict"
			found[i].ContradictingObservationIDs = contradictingObservations(found, i)
		}
	}
	return found
}

func contradictingObservations(items []Hypothesis, index int) []id.ID {
	own := map[id.ID]struct{}{}
	for _, observationID := range items[index].SupportingObservationIDs {
		own[observationID] = struct{}{}
	}
	seen := map[id.ID]struct{}{}
	var out []id.ID
	for other := range items {
		if items[other].ServiceType == "" || items[other].ServiceType == items[index].ServiceType {
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

func distinctServices(items []Hypothesis) int {
	seen := map[string]struct{}{}
	for _, item := range items {
		if item.ServiceType != "" {
			seen[item.ServiceType] = struct{}{}
		}
	}
	return len(seen)
}

func findAlias(aliases []Alias, product string) (id.ID, bool) {
	for _, alias := range aliases {
		if product != "" && strings.EqualFold(alias.Value, product) {
			return alias.ProductID, true
		}
	}
	return id.ID{}, false
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
