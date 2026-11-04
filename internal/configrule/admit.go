// Package configrule 校验调用方提交的配置规则。规则只声明对已采集字段的封闭比较，不执行命令。
// Package configrule validates caller-submitted configuration rules. A rule only declares closed comparisons against collected fields and does not execute commands.
package configrule

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"regexp"
	"unicode"
	"unicode/utf8"

	"gopkg.in/yaml.v3"

	"github.com/zodirc/Vesper/internal/collect"
	"github.com/zodirc/Vesper/internal/rule"
)

const (
	// MaxDocumentBytes 是一份配置规则文档的最大字节数。
	// MaxDocumentBytes is the maximum size of one configuration-rule document.
	MaxDocumentBytes = 256 * 1024
	// MaxRules 是一份文档中的规则数上限。
	// MaxRules is the maximum number of rules in one document.
	MaxRules = 256
	// maxClauses 是一组条件的条数上限。
	// maxClauses is the maximum number of conditions in one clause list.
	maxClauses = 8
	// maxMatch 是列表项匹配条件的条数上限。
	// maxMatch is the maximum number of match conditions on one list item.
	maxMatch = 4
	// maxText 是比较值、标题和修复说明的长度上限。
	// maxText is the maximum length of a comparison value, title, and remediation.
	maxText = 512
	// maxRegex 是正则表达式的长度上限。
	// maxRegex is the maximum length of a regular expression.
	maxRegex = 256
	// maxRemediation 是修复说明的长度上限。
	// maxRemediation is the maximum length of remediation text.
	maxRemediation = 1000
	// maxLicense 是许可说明的长度上限。
	// maxLicense is the maximum length of a license notice.
	maxLicense = 4000
	// maxCount 是 count 比较的数值上限。
	// maxCount is the maximum number accepted by a count comparison.
	maxCount = 100000
)

var (
	keyPattern      = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	categoryPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
	scalarOps       = map[string]struct{}{"equals": {}, "prefix": {}, "contains": {}, "regex": {}, "exists": {}, "absent": {}}
	listOps         = map[string]struct{}{"any": {}, "none": {}, "count": {}}
	matchOps        = map[string]struct{}{"equals": {}, "prefix": {}, "contains": {}, "regex": {}, "exists": {}, "absent": {}}
	compares        = map[string]struct{}{"eq": {}, "ne": {}, "gt": {}, "gte": {}, "lt": {}, "lte": {}}
	severities      = map[string]struct{}{"low": {}, "medium": {}, "high": {}, "critical": {}}
)

// Document 是一份通过校验的配置规则。它不包含原文。
// Document is one configuration-rule document that passed validation. It does not contain the source text.
type Document struct {
	Digest  string
	License string
	Rules   []Rule
}

// Rule 是一条封闭配置规则。主体固定为 asset，观察类型固定为 host_inventory。
// Rule is one closed configuration rule. Its subject is asset and its observation type is host_inventory.
type Rule struct {
	Key           string
	Title         string
	Category      string
	Severity      string
	Operation     string
	Remediation   string
	Applicability []rule.Predicate
	Pass          []rule.Predicate
	Fail          []rule.Predicate
}

type submitted struct {
	License string          `yaml:"license"`
	Rules   []submittedRule `yaml:"rules"`
}

type submittedRule struct {
	ID          string               `yaml:"id"`
	Title       string               `yaml:"title"`
	Category    string               `yaml:"category"`
	Severity    string               `yaml:"severity"`
	Subject     string               `yaml:"subject"`
	Operation   string               `yaml:"operation"`
	AppliesWhen []submittedPredicate `yaml:"applies_when"`
	Pass        []submittedPredicate `yaml:"pass"`
	Fail        []submittedPredicate `yaml:"fail"`
	Remediation string               `yaml:"remediation"`
}

type submittedPredicate struct {
	Observation string           `yaml:"observation"`
	Field       string           `yaml:"field"`
	Op          string           `yaml:"op"`
	Value       string           `yaml:"value"`
	Match       []rule.Condition `yaml:"match"`
	Compare     string           `yaml:"compare"`
	Number      int              `yaml:"number"`
}

// Admit 校验一份 vesper-config 文档。未知字段、自由表达式、命令和未采集的字段都会拒绝整份文档。
// Admit validates one vesper-config document. Unknown fields, free expressions, commands, and fields that are not collected reject the whole document.
//
// 事实缺失时的结果固定为 insufficient_evidence。文档不能声明 unknown_condition，也不能把缺失写成通过。
// A missing fact is always insufficient_evidence. The document cannot declare unknown_condition, and it cannot treat a missing fact as a pass.
//
// service、endpoint、software_package 和 host 主体会被拒绝。当前采集事实挂在主机资产上，这些主体没有对应的绑定。
// Subjects service, endpoint, software_package, and host are rejected. Current collection facts belong to the host asset, and those subjects have no binding.
func Admit(document []byte) (Document, error) {
	if len(document) == 0 || len(document) > MaxDocumentBytes {
		return Document{}, fmt.Errorf("config rule: document size %d", len(document))
	}
	if !utf8.Valid(document) || bytes.Contains(document, []byte{0}) {
		return Document{}, fmt.Errorf("config rule: document must be UTF-8 without NUL")
	}
	decoder := yaml.NewDecoder(bytes.NewReader(document))
	decoder.KnownFields(true)
	var body submitted
	if err := decoder.Decode(&body); err != nil {
		return Document{}, fmt.Errorf("config rule: %w", err)
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return Document{}, fmt.Errorf("config rule: extra document")
		}
		return Document{}, fmt.Errorf("config rule: %w", err)
	}
	if len(body.License) > maxLicense || containsControl(body.License) {
		return Document{}, fmt.Errorf("config rule: license")
	}
	if len(body.Rules) == 0 || len(body.Rules) > MaxRules {
		return Document{}, fmt.Errorf("config rule: rule count %d", len(body.Rules))
	}
	seen := map[string]struct{}{}
	rules := make([]Rule, 0, len(body.Rules))
	for _, item := range body.Rules {
		ruleItem, err := admitRule(item)
		if err != nil {
			return Document{}, err
		}
		if _, ok := seen[ruleItem.Key]; ok {
			return Document{}, fmt.Errorf("config rule: duplicate id %s", ruleItem.Key)
		}
		seen[ruleItem.Key] = struct{}{}
		rules = append(rules, ruleItem)
	}
	sum := sha256.Sum256(document)
	return Document{Digest: hex.EncodeToString(sum[:]), License: body.License, Rules: rules}, nil
}

func admitRule(item submittedRule) (Rule, error) {
	if !keyPattern.MatchString(item.ID) {
		return Rule{}, fmt.Errorf("config rule: id %q", item.ID)
	}
	if item.Subject != "" && item.Subject != "asset" {
		return Rule{}, fmt.Errorf("config rule: subject %s is not bound", item.Subject)
	}
	if !knownOperation(item.Operation) {
		return Rule{}, fmt.Errorf("config rule: operation %s", item.Operation)
	}
	if _, ok := severities[item.Severity]; !ok {
		return Rule{}, fmt.Errorf("config rule: severity %s", item.Severity)
	}
	if item.Category != "" && !categoryPattern.MatchString(item.Category) {
		return Rule{}, fmt.Errorf("config rule: category %s", item.Category)
	}
	title, err := plainText("title", item.Title, 1, 200)
	if err != nil {
		return Rule{}, err
	}
	remediation := ""
	if item.Remediation != "" {
		remediation, err = plainText("remediation", item.Remediation, 1, maxRemediation)
		if err != nil {
			return Rule{}, err
		}
	}
	if len(item.Pass) == 0 || len(item.Pass) > maxClauses || len(item.Fail) > maxClauses || len(item.AppliesWhen) > maxClauses {
		return Rule{}, fmt.Errorf("config rule: %s clause count", item.ID)
	}
	applies, err := admitPredicates(item.ID, item.Operation, item.AppliesWhen, true)
	if err != nil {
		return Rule{}, err
	}
	pass, err := admitPredicates(item.ID, item.Operation, item.Pass, false)
	if err != nil {
		return Rule{}, err
	}
	fail, err := admitPredicates(item.ID, item.Operation, item.Fail, false)
	if err != nil {
		return Rule{}, err
	}
	return Rule{
		Key: item.ID, Title: title, Category: item.Category, Severity: item.Severity, Operation: item.Operation,
		Remediation: remediation, Applicability: applies, Pass: pass, Fail: fail,
	}, nil
}

func admitPredicates(ruleID, operation string, items []submittedPredicate, applicability bool) ([]rule.Predicate, error) {
	out := make([]rule.Predicate, 0, len(items))
	for _, item := range items {
		pred, err := admitPredicate(ruleID, operation, item, applicability)
		if err != nil {
			return nil, err
		}
		out = append(out, pred)
	}
	return out, nil
}

func admitPredicate(ruleID, operation string, item submittedPredicate, applicability bool) (rule.Predicate, error) {
	if applicability {
		if !knownOperation(item.Observation) {
			return rule.Predicate{}, fmt.Errorf("config rule: %s observation %s", ruleID, item.Observation)
		}
		operation = item.Observation
	} else if item.Observation != "" {
		return rule.Predicate{}, fmt.Errorf("config rule: %s observation is only valid in applies_when", ruleID)
	}
	if !keyPattern.MatchString(item.Field) {
		return rule.Predicate{}, fmt.Errorf("config rule: %s field %q", ruleID, item.Field)
	}
	kind, itemFields, ok := fieldKind(operation, item.Field)
	if !ok {
		return rule.Predicate{}, fmt.Errorf("config rule: %s field %s is not collected by %s", ruleID, item.Field, operation)
	}
	switch kind {
	case "scalar":
		if _, ok := scalarOps[item.Op]; !ok {
			return rule.Predicate{}, fmt.Errorf("config rule: %s op %s", ruleID, item.Op)
		}
		if len(item.Match) != 0 || item.Compare != "" || item.Number != 0 {
			return rule.Predicate{}, fmt.Errorf("config rule: %s scalar op does not take a list match", ruleID)
		}
	case "list":
		if _, ok := listOps[item.Op]; !ok && item.Op != "exists" && item.Op != "absent" {
			return rule.Predicate{}, fmt.Errorf("config rule: %s op %s", ruleID, item.Op)
		}
	default:
		return rule.Predicate{}, fmt.Errorf("config rule: %s field %s", ruleID, item.Field)
	}
	if err := admitValue(ruleID, item.Op, item.Value); err != nil {
		return rule.Predicate{}, err
	}
	match, err := admitMatch(ruleID, item.Op, itemFields, item.Match)
	if err != nil {
		return rule.Predicate{}, err
	}
	if item.Op == "count" {
		if _, ok := compares[item.Compare]; !ok || item.Number < 0 || item.Number > maxCount {
			return rule.Predicate{}, fmt.Errorf("config rule: %s count compare", ruleID)
		}
	} else if item.Compare != "" || item.Number != 0 {
		return rule.Predicate{}, fmt.Errorf("config rule: %s compare", ruleID)
	}
	return rule.Predicate{
		Observation: item.Observation, Field: item.Field, Op: item.Op, Value: item.Value,
		Match: match, Compare: item.Compare, Number: item.Number,
	}, nil
}

func admitMatch(ruleID, op string, itemFields map[string]struct{}, match []rule.Condition) ([]rule.Condition, error) {
	if op != "any" && op != "none" && op != "count" {
		if len(match) != 0 {
			return nil, fmt.Errorf("config rule: %s match", ruleID)
		}
		return nil, nil
	}
	if (op == "any" || op == "none") && len(match) == 0 {
		return nil, fmt.Errorf("config rule: %s match", ruleID)
	}
	if len(match) > maxMatch {
		return nil, fmt.Errorf("config rule: %s match", ruleID)
	}
	out := make([]rule.Condition, 0, len(match))
	for _, item := range match {
		if _, ok := itemFields[item.Field]; !ok || !keyPattern.MatchString(item.Field) {
			return nil, fmt.Errorf("config rule: %s match field %s", ruleID, item.Field)
		}
		if _, ok := matchOps[item.Op]; !ok {
			return nil, fmt.Errorf("config rule: %s match op %s", ruleID, item.Op)
		}
		if err := admitValue(ruleID, item.Op, item.Value); err != nil {
			return nil, err
		}
		out = append(out, rule.Condition{Field: item.Field, Op: item.Op, Value: item.Value})
	}
	return out, nil
}

func admitValue(ruleID, op, value string) error {
	if op == "exists" || op == "absent" || op == "any" || op == "none" || op == "count" {
		if value != "" {
			return fmt.Errorf("config rule: %s %s does not take a value", ruleID, op)
		}
		return nil
	}
	if value == "" || len(value) > maxText || containsControl(value) {
		return fmt.Errorf("config rule: %s value", ruleID)
	}
	if op == "regex" {
		if len(value) > maxRegex {
			return fmt.Errorf("config rule: %s regex", ruleID)
		}
		if _, err := regexp.Compile(value); err != nil {
			return fmt.Errorf("config rule: %s regex: %w", ruleID, err)
		}
	}
	return nil
}

func plainText(name, value string, min, max int) (string, error) {
	if len(value) < min || len(value) > max || containsControl(value) {
		return "", fmt.Errorf("config rule: %s", name)
	}
	return value, nil
}

func containsControl(value string) bool {
	for _, item := range value {
		if unicode.IsControl(item) {
			return true
		}
	}
	return false
}

func knownOperation(operation string) bool {
	for _, item := range collect.Operations {
		if item == operation {
			return true
		}
	}
	return false
}

func fieldKind(operation, field string) (string, map[string]struct{}, bool) {
	spec, ok := collectedFields[operation]
	if !ok {
		return "", nil, false
	}
	if _, ok := spec.scalars[field]; ok {
		return "scalar", nil, true
	}
	itemFields, ok := spec.lists[field]
	if !ok {
		return "", nil, false
	}
	return "list", itemFields, true
}
