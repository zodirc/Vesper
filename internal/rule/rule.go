// Package rule 执行已发布的指纹规则和配置规则。规则只读取事实，不发起网络连接。
// Package rule evaluates published fingerprint and configuration rules. Rules read facts only and do not open network connections.
package rule

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
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

// FingerprintRule 根据已有观察提取服务和产品候选。未声明 EvidenceTypes 时只读取 protocol_response。
// FingerprintRule extracts service and product candidates from existing observations. It reads only protocol_response when EvidenceTypes is empty.
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
	// EvidenceTypes 是这条规则允许读取的观察类型。为空时只读取 protocol_response，已发布规则因此保持原内容。
	// EvidenceTypes lists the observation types this rule may read. An empty list reads only protocol_response, so published rules keep their original content.
	EvidenceTypes []string `json:"EvidenceTypes,omitempty"`
	// Negative 是排除条件。正条件成立且排除条件也成立时，这条规则不产生产品候选。
	// Negative holds exclusion conditions. When the positive conditions and the exclusion conditions both match, the rule does not produce a product candidate.
	Negative []Condition `json:"Negative,omitempty"`
	// PackVersion 是这条规则所属规则包的版本。它不参与内容摘要，已发布内置规则的摘要因此保持不变。
	// PackVersion is the version of the pack that owns this rule. It is not part of the content digest, so published built-in rules keep their digest.
	PackVersion string `json:"-"`
}

// Condition 是对观察字段的封闭比较。
// Condition is a closed comparison against an observation field.
type Condition struct {
	Field string `json:"field" yaml:"field"`
	Op    string `json:"op" yaml:"op"`
	Value string `json:"value,omitempty" yaml:"value,omitempty"`
}

// Extractor 用固定方法从观察字段提取产品或版本。
// Extractor extracts a product or version from an observation field with a fixed method.
//
// Template 只在 method 为 capture 时使用，可以用 $1 到 $9 引用正则捕获组。空模板不写入内容摘要。
// Template is used only when method is capture. It may reference regular-expression capture groups with $1 through $9. An empty template is omitted from the content digest.
type Extractor struct {
	Target   string `json:"target"`
	Source   string `json:"source"`
	Method   string `json:"method"`
	Template string `json:"template,omitempty"`
}

// ConfigRule 判断一项固定采集事实。Pass 为空时只检查 PassField 是否非空，已发布的内置规则因此保持原内容。
// ConfigRule judges one fixed collection fact. When Pass is empty it only checks that PassField is non-empty, so published built-in rules keep their original content.
//
// Pass 非空时按封闭条件判断。Applicability 读取其他采集操作；任一适用事实缺失、未请求或未成功采集时结果是 insufficient_evidence。Pass 与 Fail 同时成立是 conflict，同时不成立是 unknown。
// When Pass is non-empty the rule uses closed conditions. Applicability reads other collection operations. A missing, unrequested, or unsuccessfully collected applicability fact yields insufficient_evidence. Pass and Fail both matching is conflict, and neither matching is unknown.
type ConfigRule struct {
	ID                      id.ID
	Key                     string
	Version                 string
	SubjectType             string
	RequiredObservationType string
	Operation               string
	PassField               string
	Severity                string
	// Title 是确认后的 Finding 标题。空标题不参与内容摘要。
	// Title is the finding title after confirmation. An empty title is omitted from the content digest.
	Title string `json:"Title,omitempty"`
	// Category 是调用方给出的分类。空分类不参与内容摘要。
	// Category is the category supplied by the caller. An empty category is omitted from the content digest.
	Category string `json:"Category,omitempty"`
	// Remediation 是确认后写入检测摘要的修复说明。空说明不参与内容摘要。
	// Remediation is the remediation text written into the detection summary after confirmation. Empty text is omitted from the content digest.
	Remediation string `json:"Remediation,omitempty"`
	// Applicability 是规则适用前必须成立的条件。
	// Applicability holds conditions that must hold before the rule applies.
	Applicability []Predicate `json:"Applicability,omitempty"`
	// Pass 是通过条件。全部成立且 Fail 未同时全部成立时，结果是 not_vulnerable。
	// Pass holds the pass conditions. When all of them hold and Fail does not also hold, the result is not_vulnerable.
	Pass []Predicate `json:"Pass,omitempty"`
	// Fail 是失败条件。Pass 不成立且 Fail 为空或全部成立时，结果是 confirmed。
	// Fail holds the fail conditions. When Pass does not hold and Fail is empty or fully holds, the result is confirmed.
	Fail []Predicate `json:"Fail,omitempty"`
}

// Predicate 是对一个采集字段的封闭比较。它不执行命令，也不调用函数。
// Predicate is a closed comparison against one collected field. It does not execute a command or call a function.
type Predicate struct {
	Observation string      `json:"observation,omitempty"`
	Field       string      `json:"field"`
	Op          string      `json:"op"`
	Value       string      `json:"value,omitempty"`
	Match       []Condition `json:"match,omitempty"`
	Compare     string      `json:"compare,omitempty"`
	Number      int         `json:"number,omitempty"`
}

// Fact 是规则可读的一条观察投影。
// Fact is one observation projection readable by a rule.
//
// Response 是已校验证据中的原始响应。它不写入观察 JSON。字段 response 只读取这份字节。
// Response is the raw response from verified evidence. It is not written into the observation JSON. The response field reads only these bytes.
type Fact struct {
	ID           id.ID
	Type         string
	Subject      string
	ResultStatus string
	Value        map[string]any
	Response     []byte
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
	// Title 是规则标题。字段存在性规则的标题为空，Finding 仍使用规则键。
	// Title is the rule title. A field-presence rule has an empty title, and the finding still uses the rule key.
	Title     string
	Matched   map[string]any
	Unmatched map[string]any
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
//
// 规则没有声明证据类型时只读取 protocol_response。正条件不成立时不看排除条件。正条件和排除条件同时成立时，命中状态是 excluded，不提取产品。
// A rule that declares no evidence types reads only protocol_response. Exclusion conditions are not evaluated when the positive conditions do not match. When both match, the hit status is excluded and no product is extracted.
func MatchFingerprints(rules []FingerprintRule, fact Fact) []Hit {
	protocol := field(fact.Value, "protocol")
	ordered := append([]FingerprintRule(nil), rules...)
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].Priority < ordered[j].Priority })
	var hits []Hit
	for _, item := range ordered {
		matched, captures := conditionsMatch(item.Conditions, fact)
		if !evidenceAllowed(item, fact.Type) || item.TargetProtocol == "" || item.TargetProtocol != protocol || !matched {
			continue
		}
		if len(item.Negative) > 0 {
			excluded, _ := conditionsMatch(item.Negative, fact)
			if excluded {
				hits = append(hits, Hit{RuleID: item.ID, ServiceType: item.ServiceType, Status: "excluded"})
				continue
			}
		}
		product, version := extract(item.Extractors, fact, captures)
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

func evidenceAllowed(item FingerprintRule, observationType string) bool {
	if len(item.EvidenceTypes) == 0 {
		return observationType == "protocol_response"
	}
	for _, allowed := range item.EvidenceTypes {
		if allowed == observationType {
			return true
		}
	}
	return false
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
	decision := Decision{RuleID: item.ID, RuleKey: item.Key, RuleVersion: item.Version, Severity: item.Severity, Title: item.Title}
	subject := "local:" + item.Operation
	matched := findConfigFact(facts, item.RequiredObservationType, subject)
	if matched == nil {
		decision.Status = "insufficient_evidence"
		decision.Summary = "required observation missing"
		decision.Unmatched = map[string]any{"required_observation_type": item.RequiredObservationType, "subject": subject}
		return decision
	}
	if len(item.Pass) == 0 {
		return evaluatePassField(decision, item, *matched)
	}
	return evaluatePredicates(decision, item, facts, *matched)
}

func evaluatePassField(decision Decision, item ConfigRule, matched Fact) Decision {
	status := collectionStatus(matched)
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

// ReadOperations 返回这条规则判断和适用条件要读取的采集操作。主操作在前，适用条件里的操作按声明顺序追加。
// ReadOperations returns the collection operations read by this rule and its applicability conditions. The primary operation comes first, and applicability operations follow in declaration order.
func (item ConfigRule) ReadOperations() []string {
	seen := map[string]struct{}{}
	var out []string
	if item.Operation != "" {
		seen[item.Operation] = struct{}{}
		out = append(out, item.Operation)
	}
	for _, pred := range item.Applicability {
		if pred.Observation == "" {
			continue
		}
		if _, ok := seen[pred.Observation]; ok {
			continue
		}
		seen[pred.Observation] = struct{}{}
		out = append(out, pred.Observation)
	}
	return out
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

// Fingerprints 返回指定版本的已发布指纹规则。
// Fingerprints returns the published fingerprint rules of the requested version.
func Fingerprints(packs []Pack, version string) []FingerprintRule {
	return fingerprintVersion(packs, version, false)
}

// FrozenFingerprints 返回已经冻结到某次扫描的指纹规则。已发布和已弃用的版本都返回，因为弃用只影响之后的扫描。
// FrozenFingerprints returns fingerprint rules frozen into one scan. Published and deprecated versions are both returned, because deprecation affects only later scans.
func FrozenFingerprints(packs []Pack, version string) []FingerprintRule {
	return fingerprintVersion(packs, version, true)
}

func fingerprintVersion(packs []Pack, version string, includeDeprecated bool) []FingerprintRule {
	for _, pack := range packs {
		if pack.Type != "fingerprint" || pack.Version != version {
			continue
		}
		if pack.Status != "published" && !(includeDeprecated && pack.Status == "deprecated") {
			continue
		}
		out := append([]FingerprintRule(nil), pack.Fingerprints...)
		for i := range out {
			out[i].PackVersion = pack.Version
		}
		return out
	}
	return nil
}

// Configs 返回指定版本的已发布配置规则。
// Configs returns the published configuration rules of the requested version.
func Configs(packs []Pack, version string) []ConfigRule {
	return configVersion(packs, version, false)
}

// FrozenConfigs 返回已经冻结到某次扫描的配置规则。已发布和已弃用的版本都返回，因为弃用只影响之后的扫描。
// FrozenConfigs returns configuration rules frozen into one scan. Published and deprecated versions are both returned, because deprecation affects only later scans.
func FrozenConfigs(packs []Pack, version string) []ConfigRule {
	return configVersion(packs, version, true)
}

func configVersion(packs []Pack, version string, includeDeprecated bool) []ConfigRule {
	for _, pack := range packs {
		if pack.Type != "config" || pack.Version != version {
			continue
		}
		if pack.Status != "published" && !(includeDeprecated && pack.Status == "deprecated") {
			continue
		}
		return append([]ConfigRule(nil), pack.Configs...)
	}
	return nil
}

func conditionsMatch(conditions []Condition, fact Fact) (bool, []string) {
	var captures []string
	for _, condition := range conditions {
		got := factField(fact, condition.Field)
		switch condition.Op {
		case "equals":
			if got != condition.Value {
				return false, nil
			}
		case "prefix":
			if !strings.HasPrefix(got, condition.Value) {
				return false, nil
			}
		case "contains":
			if !strings.Contains(got, condition.Value) {
				return false, nil
			}
		case "exists":
			if strings.TrimSpace(got) == "" {
				return false, nil
			}
		case "regex":
			groups, ok := regexGroups(condition.Value, got)
			if !ok {
				return false, nil
			}
			captures = groups
		default:
			return false, nil
		}
	}
	return true, captures
}

func factField(fact Fact, path string) string {
	if path == "response" {
		return string(fact.Response)
	}
	return field(fact.Value, path)
}

var regexCache sync.Map

func regexGroups(pattern, value string) ([]string, bool) {
	if pattern == "" {
		return nil, false
	}
	compiled, err := cachedRegex(pattern)
	if err != nil {
		return nil, false
	}
	groups := compiled.FindStringSubmatch(value)
	if groups == nil {
		return nil, false
	}
	return groups, true
}

func cachedRegex(pattern string) (*regexp.Regexp, error) {
	if cached, ok := regexCache.Load(pattern); ok {
		return cached.(*regexp.Regexp), nil
	}
	compiled, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	regexCache.Store(pattern, compiled)
	return compiled, nil
}

func extract(extractors []Extractor, fact Fact, captures []string) (string, string) {
	var product, version string
	for _, extractor := range extractors {
		switch extractor.Method {
		case "server_token":
			product, version = serverToken(field(fact.Value, extractor.Source))
		case "ssh_software":
			product, version = sshSoftware(field(fact.Value, extractor.Source))
		case "capture":
			text, ok := fillTemplate(extractor.Template, captures)
			if !ok {
				continue
			}
			switch extractor.Target {
			case "product":
				product = text
			case "version":
				version = text
			}
		}
	}
	return product, version
}

func fillTemplate(template string, captures []string) (string, bool) {
	var out strings.Builder
	for i := 0; i < len(template); i++ {
		if template[i] != '$' {
			out.WriteByte(template[i])
			continue
		}
		if i+1 < len(template) && template[i+1] == '$' {
			out.WriteByte('$')
			i++
			continue
		}
		if i+1 >= len(template) || template[i+1] < '1' || template[i+1] > '9' {
			return "", false
		}
		index := int(template[i+1] - '0')
		if index >= len(captures) {
			return "", false
		}
		out.WriteString(captures[index])
		i++
	}
	return strings.TrimSpace(out.String()), true
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
