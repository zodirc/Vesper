package rule

import (
	"math"
	"strconv"
	"strings"
)

func findConfigFact(facts []Fact, observationType, subject string) *Fact {
	for i := range facts {
		if facts[i].Type == observationType && facts[i].Subject == subject {
			return &facts[i]
		}
	}
	return nil
}

func evaluatePredicates(decision Decision, item ConfigRule, facts []Fact, primary Fact) Decision {
	status := collectionStatus(primary)
	switch status {
	case "unsupported":
		decision.Status = "not_applicable"
		decision.Summary = "platform unsupported"
		decision.Matched = map[string]any{"collection_status": status}
		return decision
	case "not_requested":
		decision.Status = "skipped"
		decision.Summary = "collection not requested"
		decision.Matched = map[string]any{"collection_status": status}
		return decision
	case "error":
		decision.Status = "execution_error"
		decision.Summary = "collection error"
		decision.Matched = map[string]any{"collection_status": status}
		return decision
	case "permission_denied":
		decision.Status = "insufficient_evidence"
		decision.Summary = status
		decision.Matched = map[string]any{"collection_status": status}
		return decision
	case "collected", "empty":
	default:
		decision.Status = "unknown"
		decision.Summary = "unrecognized collection status"
		decision.Unmatched = map[string]any{"collection_status": status}
		return decision
	}
	for _, pred := range item.Applicability {
		fact := findConfigFact(facts, "host_inventory", "local:"+pred.Observation)
		if fact == nil {
			decision.Status = "insufficient_evidence"
			decision.Summary = "applicability observation unavailable"
			decision.Unmatched = map[string]any{"observation": pred.Observation, "collection_status": "missing"}
			return decision
		}
		factStatus := collectionStatus(*fact)
		if factStatus != "collected" && factStatus != "empty" {
			decision.Status = "insufficient_evidence"
			decision.Summary = "applicability observation unavailable"
			decision.Unmatched = map[string]any{"observation": pred.Observation, "collection_status": factStatus}
			return decision
		}
		if !predicateTrue(pred, fact.Value) {
			decision.Status = "not_applicable"
			decision.Summary = "applicability did not match"
			decision.Matched = map[string]any{"collection_status": status}
			decision.Unmatched = map[string]any{"observation": pred.Observation, "field": pred.Field, "op": pred.Op}
			return decision
		}
	}
	passOK := allPredicates(item.Pass, primary.Value)
	failDeclared := len(item.Fail) > 0
	failOK := failDeclared && allPredicates(item.Fail, primary.Value)
	decision.Matched = map[string]any{"collection_status": status}
	switch {
	case passOK && failOK:
		decision.Status = "conflict"
		decision.Summary = "pass and fail both matched"
		decision.Matched["pass"] = true
		decision.Matched["fail"] = true
	case passOK:
		decision.Status = "not_vulnerable"
		decision.Summary = "pass"
		decision.Matched["pass"] = true
		if failDeclared {
			decision.Unmatched = map[string]any{"fail": false}
		}
	case !failDeclared || failOK:
		decision.Status = "confirmed"
		decision.Summary = "fail"
		if item.Remediation != "" {
			decision.Summary = item.Remediation
		}
		decision.Unmatched = map[string]any{"pass": false}
		if failDeclared {
			decision.Matched["fail"] = true
		}
	default:
		decision.Status = "unknown"
		decision.Summary = "neither pass nor fail matched"
		decision.Unmatched = map[string]any{"pass": false, "fail": false}
	}
	if item.Category != "" {
		decision.Matched["category"] = item.Category
	}
	return decision
}

func allPredicates(items []Predicate, value map[string]any) bool {
	for _, item := range items {
		if !predicateTrue(item, value) {
			return false
		}
	}
	return true
}

func predicateTrue(pred Predicate, root map[string]any) bool {
	raw, ok := mapValue(root, pred.Field)
	switch pred.Op {
	case "exists":
		return valuePresent(raw, ok)
	case "absent":
		return !valuePresent(raw, ok)
	case "equals", "prefix", "contains", "regex":
		text, ok := scalarText(raw)
		if !ok {
			return false
		}
		return scalarMatch(pred.Op, text, pred.Value)
	case "any":
		items, ok := listItems(raw)
		return ok && countItems(items, pred.Match) > 0
	case "none":
		items, ok := listItems(raw)
		return ok && countItems(items, pred.Match) == 0
	case "count":
		items, ok := listItems(raw)
		return ok && countCompare(pred.Compare, countItems(items, pred.Match), pred.Number)
	default:
		return false
	}
}

func mapValue(root map[string]any, field string) (any, bool) {
	if root == nil {
		return nil, false
	}
	raw, ok := root[field]
	return raw, ok
}

func valuePresent(raw any, ok bool) bool {
	if !ok || raw == nil {
		return false
	}
	switch value := raw.(type) {
	case string:
		return strings.TrimSpace(value) != ""
	case []string:
		return len(value) > 0
	case []any:
		return len(value) > 0
	case []map[string]any:
		return len(value) > 0
	case map[string]any:
		return len(value) > 0
	default:
		return true
	}
}

func scalarMatch(op, got, want string) bool {
	switch op {
	case "equals":
		return got == want
	case "prefix":
		return strings.HasPrefix(got, want)
	case "contains":
		return strings.Contains(got, want)
	case "regex":
		compiled, err := cachedRegex(want)
		if err != nil {
			return false
		}
		return compiled.MatchString(got)
	default:
		return false
	}
}

func countCompare(op string, got, want int) bool {
	switch op {
	case "eq":
		return got == want
	case "ne":
		return got != want
	case "gt":
		return got > want
	case "gte":
		return got >= want
	case "lt":
		return got < want
	case "lte":
		return got <= want
	default:
		return false
	}
}

func countItems(items []map[string]any, conditions []Condition) int {
	if len(conditions) == 0 {
		return len(items)
	}
	count := 0
	for _, item := range items {
		if itemMatches(item, conditions) {
			count++
		}
	}
	return count
}

func itemMatches(item map[string]any, conditions []Condition) bool {
	for _, condition := range conditions {
		raw, ok := item[condition.Field]
		if !matchRaw(condition.Op, condition.Value, raw, ok) {
			return false
		}
	}
	return true
}

func matchRaw(op, want string, raw any, ok bool) bool {
	if texts, isList := stringList(raw); isList {
		switch op {
		case "exists":
			return len(texts) > 0
		case "absent":
			return len(texts) == 0
		default:
			for _, text := range texts {
				if scalarMatch(op, text, want) {
					return true
				}
			}
			return false
		}
	}
	switch op {
	case "exists":
		return valuePresent(raw, ok)
	case "absent":
		return !valuePresent(raw, ok)
	default:
		text, ok := scalarText(raw)
		return ok && scalarMatch(op, text, want)
	}
}

func listItems(raw any) ([]map[string]any, bool) {
	switch value := raw.(type) {
	case []map[string]any:
		return value, true
	case []any:
		out := make([]map[string]any, 0, len(value))
		for _, item := range value {
			mapped, ok := item.(map[string]any)
			if !ok {
				return nil, false
			}
			out = append(out, mapped)
		}
		return out, true
	default:
		return nil, false
	}
}

func stringList(raw any) ([]string, bool) {
	switch value := raw.(type) {
	case []string:
		return value, true
	case []any:
		out := make([]string, 0, len(value))
		for _, item := range value {
			text, ok := item.(string)
			if !ok {
				return nil, false
			}
			out = append(out, text)
		}
		return out, true
	default:
		return nil, false
	}
}

func scalarText(raw any) (string, bool) {
	switch value := raw.(type) {
	case string:
		return value, true
	case bool:
		return strconv.FormatBool(value), true
	case int:
		return strconv.Itoa(value), true
	case int32:
		return strconv.FormatInt(int64(value), 10), true
	case int64:
		return strconv.FormatInt(value, 10), true
	case float32:
		return scalarFloat(float64(value))
	case float64:
		return scalarFloat(value)
	default:
		return "", false
	}
}

func scalarFloat(value float64) (string, bool) {
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return "", false
	}
	if value == math.Trunc(value) && value <= math.MaxInt64 && value >= math.MinInt64 {
		return strconv.FormatInt(int64(value), 10), true
	}
	return strconv.FormatFloat(value, 'f', -1, 64), true
}
