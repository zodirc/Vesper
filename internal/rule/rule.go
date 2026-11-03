// Package rule 执行已发布的指纹规则和配置规则。规则只读取事实，不发起网络连接。
// Package rule evaluates published fingerprint and configuration rules. Rules read facts only and do not open network connections.
package rule

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/zodirc/Vesper/internal/id"
)

const SchemaVersion = "1"

var (
	// ErrPublishedImmutable 表示已发布规则包的内容不能原地修改。
	// ErrPublishedImmutable means the content of a published rule pack cannot be modified in place.
	ErrPublishedImmutable = errors.New("published rule pack is immutable")
)

// Pack 是一次不可变发布的规则集合。
// Pack is one immutable published rule set.
type Pack struct {
	ID            id.ID
	Type          string
	Version       string
	ContentDigest string
	SchemaVersion string
	Source        string
	Status        string
	License       json.RawMessage
	Compatibility json.RawMessage
	PublishedAt   *time.Time
	CreatedAt     time.Time
	Fingerprints  []FingerprintRule
	Configs       []ConfigRule
}

// FingerprintRule 根据已有协议观察提取服务和产品候选。
// FingerprintRule extracts service and product candidates from existing protocol observations.
type FingerprintRule struct {
	ID                id.ID
	Key               string
	Version           string
	Priority          int
	TargetProtocol    string
	ServiceType       string
	Conditions        []Condition
	Extractors        []Extractor
	ConfidenceMatched string
	ConfidenceEmpty   string
}

// Condition 是对观察字段的封闭比较。
// Condition is a closed comparison against an observation field.
type Condition struct {
	Field string `json:"field"`
	Op    string `json:"op"`
	Value string `json:"value,omitempty"`
}

// Extractor 用固定方法从观察字段提取产品或版本。
// Extractor extracts a product or version from an observation field with a fixed method.
type Extractor struct {
	Target string `json:"target"`
	Source string `json:"source"`
	Method string `json:"method"`
}

// ConfigRule 判断一项固定采集事实是否满足声明的字段。
// ConfigRule judges whether one fixed collection fact satisfies a declared field.
type ConfigRule struct {
	ID                      id.ID
	Key                     string
	Version                 string
	SubjectType             string
	RequiredObservationType string
	Operation               string
	PassField               string
	Severity                string
}

// Fact 是规则可读的一条观察投影。
// Fact is one observation projection readable by a rule.
type Fact struct {
	ID           id.ID
	Type         string
	Subject      string
	ResultStatus string
	Value        map[string]any
}

// Hit 是一条指纹规则对一条观察的命中。
// Hit is one fingerprint-rule match against one observation.
type Hit struct {
	RuleID      id.ID
	ServiceType string
	Product     string
	Version     string
	Confidence  string
	Status      string
}

// Decision 是配置规则或主动检测门禁的结果。
// Decision is the result of a configuration rule or the active-detection gate.
type Decision struct {
	RuleID      id.ID
	RuleKey     string
	RuleVersion string
	Status      string
	Summary     string
	Severity    string
	Matched     map[string]any
	Unmatched   map[string]any
}

// StableID 由规则键生成稳定标识。
// StableID derives a stable identifier from a rule key.
func StableID(key string) id.ID {
	sum := sha256.Sum256([]byte(key))
	var out id.ID
	copy(out[:], sum[:16])
	out[6] = (out[6] & 0x0f) | 0x50
	out[8] = (out[8] & 0x3f) | 0x80
	return out
}

// Digest 计算规则内容摘要。发布时间不参与摘要。
// Digest computes the rule-content digest. Publication time is not part of the digest.
func Digest(pack Pack) (string, error) {
	body := struct {
		Type         string            `json:"type"`
		Version      string            `json:"version"`
		Schema       string            `json:"schema"`
		Fingerprints []FingerprintRule `json:"fingerprints"`
		Configs      []ConfigRule      `json:"configs"`
	}{Type: pack.Type, Version: pack.Version, Schema: pack.SchemaVersion, Fingerprints: append([]FingerprintRule(nil), pack.Fingerprints...), Configs: append([]ConfigRule(nil), pack.Configs...)}
	sort.Slice(body.Fingerprints, func(i, j int) bool { return body.Fingerprints[i].Key < body.Fingerprints[j].Key })
	sort.Slice(body.Configs, func(i, j int) bool { return body.Configs[i].Key < body.Configs[j].Key })
	raw, err := json.Marshal(body)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

// Seal 计算摘要并把规则包标为已发布。
// Seal computes the digest and marks the pack published.
func Seal(pack Pack, now time.Time) (Pack, error) {
	digest, err := Digest(pack)
	if err != nil {
		return Pack{}, err
	}
	pack.ContentDigest = digest
	pack.Status = "published"
	if pack.SchemaVersion == "" {
		pack.SchemaVersion = SchemaVersion
	}
	stamp := now.UTC()
	pack.PublishedAt = &stamp
	if pack.CreatedAt.IsZero() {
		pack.CreatedAt = stamp
	}
	if len(pack.License) == 0 {
		pack.License = json.RawMessage(`{}`)
	}
	if len(pack.Compatibility) == 0 {
		pack.Compatibility = json.RawMessage(`{}`)
	}
	return pack, nil
}

// CheckUpdate 拒绝改变已发布规则包的内容。
// CheckUpdate rejects a change to the content of a published rule pack.
func CheckUpdate(stored, next Pack) error {
	if stored.Status != "published" {
		return nil
	}
	sameIdentity := stored.ID == next.ID || (stored.Type == next.Type && stored.Version == next.Version)
	if sameIdentity && stored.ContentDigest != next.ContentDigest {
		return fmt.Errorf("rule pack %s %s: %w", next.Type, next.Version, ErrPublishedImmutable)
	}
	return nil
}

// MatchFingerprints 返回与这条观察匹配的指纹命中。端口号不能产生产品。
// MatchFingerprints returns fingerprint hits for this observation. A port number cannot produce a product.
func MatchFingerprints(rules []FingerprintRule, fact Fact) []Hit {
	if fact.Type != "protocol_response" {
		return nil
	}
	protocol := field(fact.Value, "protocol")
	if protocol == "" {
		return nil
	}
	ordered := append([]FingerprintRule(nil), rules...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Priority < ordered[j].Priority })
	var hits []Hit
	for _, item := range ordered {
		if item.TargetProtocol != protocol || !conditionsMatch(item.Conditions, fact.Value) {
			continue
		}
		product, version := extract(item.Extractors, fact.Value)
		status := "unknown"
		confidence := item.ConfidenceEmpty
		if product != "" {
			status = "candidate"
			confidence = item.ConfidenceMatched
		}
		hits = append(hits, Hit{RuleID: item.ID, ServiceType: item.ServiceType, Product: product, Version: version, Confidence: confidence, Status: status})
	}
	return hits
}

// EvaluateConfigs 对固定采集事实作出配置判断。缺少事实时不视为通过。
// EvaluateConfigs judges fixed collection facts. Missing facts are not treated as a pass.
func EvaluateConfigs(rules []ConfigRule, facts []Fact) []Decision {
	var out []Decision
	for _, item := range rules {
		out = append(out, evaluateConfig(item, facts))
	}
	return out
}

func evaluateConfig(item ConfigRule, facts []Fact) Decision {
	decision := Decision{RuleID: item.ID, RuleKey: item.Key, RuleVersion: item.Version, Severity: item.Severity}
	var matched *Fact
	subject := "local:" + item.Operation
	for i := range facts {
		if facts[i].Type == item.RequiredObservationType && facts[i].Subject == subject {
			matched = &facts[i]
			break
		}
	}
	if matched == nil {
		decision.Status = "insufficient_evidence"
		decision.Summary = "required observation missing"
		decision.Unmatched = map[string]any{"required_observation_type": item.RequiredObservationType, "subject": subject}
		return decision
	}
	status := collectionStatus(*matched)
	switch status {
	case "unsupported":
		decision.Status = "not_applicable"
		decision.Summary = "platform unsupported"
		decision.Matched = map[string]any{"collection_status": status}
	case "not_requested":
		decision.Status = "skipped"
		decision.Summary = "collection not requested"
		decision.Matched = map[string]any{"collection_status": status}
	case "error":
		decision.Status = "execution_error"
		decision.Summary = "collection error"
		decision.Matched = map[string]any{"collection_status": status}
	case "permission_denied", "empty":
		decision.Status = "insufficient_evidence"
		decision.Summary = status
		decision.Matched = map[string]any{"collection_status": status}
	case "collected":
		if strings.TrimSpace(field(matched.Value, item.PassField)) == "" {
			decision.Status = "confirmed"
			decision.Summary = "required field missing"
			decision.Matched = map[string]any{"collection_status": status}
			decision.Unmatched = map[string]any{"pass_field": item.PassField}
		} else {
			decision.Status = "not_vulnerable"
			decision.Summary = "required field present"
			decision.Matched = map[string]any{"collection_status": status, "pass_field": item.PassField, "present": true}
		}
	default:
		decision.Status = "unknown"
		decision.Summary = "unrecognized collection status"
		decision.Unmatched = map[string]any{"collection_status": status}
	}
	return decision
}

// collectionStatus 读取设计 13.3 的采集状态。观测信封使用设计 4.12 的 result_status，两者不互相替代。
// collectionStatus reads the section 13.3 collection status. The observation envelope uses the section 4.12 result_status, and neither vocabulary replaces the other.
func collectionStatus(fact Fact) string {
	if fact.Value != nil {
		if status, ok := fact.Value["collection_status"].(string); ok && status != "" {
			return status
		}
	}
	return fact.ResultStatus
}

// ActiveDetection 在网络隔离未被证明时拒绝主动检测。即使隔离成立，当前也没有主动检测执行器。
// ActiveDetection refuses active detection when network isolation is not proven. No active-detection executor is installed even when isolation is proven.
func ActiveDetection(networkIsolated bool) Decision {
	if !networkIsolated {
		return Decision{Status: "unsupported", Summary: "network isolation is not verified"}
	}
	return Decision{Status: "skipped", Summary: "active detection executor is not installed"}
}

// Fingerprints 返回指定版本的已发布指纹规则。
// Fingerprints returns the published fingerprint rules of the requested version.
func Fingerprints(packs []Pack, version string) []FingerprintRule {
	for _, pack := range packs {
		if pack.Type == "fingerprint" && pack.Version == version && pack.Status == "published" {
			return append([]FingerprintRule(nil), pack.Fingerprints...)
		}
	}
	return nil
}

// Configs 返回指定版本的已发布配置规则。
// Configs returns the published configuration rules of the requested version.
func Configs(packs []Pack, version string) []ConfigRule {
	for _, pack := range packs {
		if pack.Type == "config" && pack.Version == version && pack.Status == "published" {
			return append([]ConfigRule(nil), pack.Configs...)
		}
	}
	return nil
}

func conditionsMatch(conditions []Condition, value map[string]any) bool {
	for _, condition := range conditions {
		got := field(value, condition.Field)
		switch condition.Op {
		case "equals":
			if got != condition.Value {
				return false
			}
		case "prefix":
			if !strings.HasPrefix(got, condition.Value) {
				return false
			}
		case "contains":
			if !strings.Contains(got, condition.Value) {
				return false
			}
		case "exists":
			if strings.TrimSpace(got) == "" {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func extract(extractors []Extractor, value map[string]any) (string, string) {
	var product, version string
	for _, extractor := range extractors {
		switch extractor.Method {
		case "server_token":
			product, version = serverToken(field(value, extractor.Source))
		case "ssh_software":
			product, version = sshSoftware(field(value, extractor.Source))
		}
	}
	return product, version
}

func field(value map[string]any, path string) string {
	if value == nil {
		return ""
	}
	if path == "headers.server" {
		return header(value, "server")
	}
	text, _ := value[path].(string)
	return text
}

func header(value map[string]any, name string) string {
	switch headers := value["headers"].(type) {
	case map[string]any:
		text, _ := headers[name].(string)
		return text
	case map[string]string:
		return headers[name]
	default:
		return ""
	}
}

func serverToken(header string) (string, string) {
	header = strings.TrimSpace(header)
	if header == "" {
		return "", ""
	}
	token := strings.Fields(header)[0]
	name, version, ok := strings.Cut(token, "/")
	if !ok {
		return name, ""
	}
	return name, version
}

func sshSoftware(banner string) (string, string) {
	if !strings.HasPrefix(banner, "SSH-") {
		return "", ""
	}
	parts := strings.SplitN(banner, "-", 3)
	if len(parts) < 3 {
		return "", ""
	}
	software := strings.Fields(parts[2])
	if len(software) == 0 {
		return "", ""
	}
	name, version, ok := strings.Cut(software[0], "_")
	if !ok {
		return software[0], ""
	}
	return name, version
}
