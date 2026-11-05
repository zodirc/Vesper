package intel

import (
	"encoding/json"
	"fmt"
	"strings"
)

func parseNVD(document []byte) ([]Record, error) {
	var envelope struct {
		Format          string            `json:"format"`
		Version         string            `json:"version"`
		Vulnerabilities []json.RawMessage `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(document, &envelope); err != nil {
		return nil, fmt.Errorf("parse nvd document: %w", err)
	}
	if envelope.Format != "" && envelope.Format != "NVD_CVE" {
		return nil, fmt.Errorf("nvd format %s is not supported", envelope.Format)
	}
	if envelope.Version != "" && envelope.Version != "2.0" {
		return nil, fmt.Errorf("nvd version %s is not supported", envelope.Version)
	}
	raws := envelope.Vulnerabilities
	if len(raws) == 0 {
		raws = []json.RawMessage{append([]byte(nil), document...)}
	}
	var out []Record
	for _, raw := range raws {
		record, err := nvdRecord(raw)
		if err != nil {
			return nil, err
		}
		out = append(out, record...)
	}
	return out, nil
}

func nvdRecord(raw json.RawMessage) ([]Record, error) {
	var wrapped struct {
		CVE json.RawMessage `json:"cve"`
	}
	body := raw
	if err := json.Unmarshal(raw, &wrapped); err == nil && len(wrapped.CVE) > 0 {
		body = wrapped.CVE
	}
	var cve struct {
		ID           string `json:"id"`
		Published    string `json:"published"`
		LastModified string `json:"lastModified"`
		VulnStatus   string `json:"vulnStatus"`
		Metrics      struct {
			V40 []nvdMetric `json:"cvssMetricV40"`
			V31 []nvdMetric `json:"cvssMetricV31"`
			V30 []nvdMetric `json:"cvssMetricV30"`
			V2  []nvdMetric `json:"cvssMetricV2"`
		} `json:"metrics"`
		Configurations json.RawMessage `json:"configurations"`
	}
	if err := json.Unmarshal(body, &cve); err != nil {
		return nil, fmt.Errorf("parse nvd cve: %w", err)
	}
	if !cveID(cve.ID) {
		return nil, fmt.Errorf("nvd record %q is not a CVE id", cve.ID)
	}
	published, err := parseTime(cve.Published)
	if err != nil {
		return nil, err
	}
	modified, err := parseTime(cve.LastModified)
	if err != nil {
		return nil, err
	}
	severity, severityData, err := nvdSeverity(cve.Metrics.V40, cve.Metrics.V31, cve.Metrics.V30, cve.Metrics.V2)
	if err != nil {
		return nil, fmt.Errorf("nvd %s: %w", cve.ID, err)
	}
	base := Record{
		SourceRecordID: cve.ID, VulnerabilityID: cve.ID, Severity: severity, SeverityData: severityData,
		PublishedAt: published, ModifiedAt: modified, Raw: append([]byte(nil), body...),
	}
	if strings.EqualFold(strings.TrimSpace(cve.VulnStatus), "rejected") {
		base.WithdrawsPrior = true
		return []Record{base}, nil
	}
	grouped, err := nvdAffected(cve.Configurations)
	if err != nil {
		return nil, fmt.Errorf("nvd %s: %w", cve.ID, err)
	}
	if len(grouped) == 0 {
		return []Record{base}, nil
	}
	var out []Record
	for _, match := range grouped {
		item := base
		item.SourceRecordID = cve.ID + "#" + match.Selector
		item.Ecosystem = "cpe"
		item.ProductSelector = match.Selector
		item.Ranges = match.Ranges
		item.PlatformConstraints = match.Platform
		item.ConfigurationConstraints = match.Configuration
		out = append(out, item)
	}
	return out, nil
}

type nvdMetric struct {
	Type     string `json:"type"`
	CvssData struct {
		BaseSeverity string   `json:"baseSeverity"`
		BaseScore    *float64 `json:"baseScore"`
		VectorString string   `json:"vectorString"`
	} `json:"cvssData"`
}

func nvdSeverity(v40, v31, v30, v2 []nvdMetric) (string, json.RawMessage, error) {
	raw, err := json.Marshal(struct {
		V40 any `json:"cvssMetricV40,omitempty"`
		V31 any `json:"cvssMetricV31,omitempty"`
		V30 any `json:"cvssMetricV30,omitempty"`
		V2  any `json:"cvssMetricV2,omitempty"`
	}{emptySlice(v40), emptySlice(v31), emptySlice(v30), emptySlice(v2)})
	if err != nil {
		return "", nil, err
	}
	if string(raw) == "{}" {
		raw = nil
	}
	var fallback *nvdMetric
	for _, group := range [][]nvdMetric{v40, v31, v30, v2} {
		if len(group) == 0 {
			continue
		}
		if fallback == nil {
			fallback = &group[0]
		}
		for i := range group {
			if strings.EqualFold(group[i].Type, "Primary") {
				level, err := severityFromCVSS(group[i].CvssData.BaseSeverity, group[i].CvssData.BaseScore)
				return level, raw, err
			}
		}
	}
	if fallback != nil {
		level, err := severityFromCVSS(fallback.CvssData.BaseSeverity, fallback.CvssData.BaseScore)
		return level, raw, err
	}
	return "", raw, nil
}

func emptySlice[T any](value []T) any {
	if len(value) == 0 {
		return nil
	}
	return value
}

type nvdMatch struct {
	Vulnerable            bool   `json:"vulnerable"`
	Criteria              string `json:"criteria"`
	VersionStartIncluding string `json:"versionStartIncluding"`
	VersionStartExcluding string `json:"versionStartExcluding"`
	VersionEndIncluding   string `json:"versionEndIncluding"`
	VersionEndExcluding   string `json:"versionEndExcluding"`
}

type nvdNode struct {
	Operator string     `json:"operator"`
	Negate   bool       `json:"negate"`
	CPEMatch []nvdMatch `json:"cpeMatch"`
	Nodes    []nvdNode  `json:"nodes"`
}

type nvdGroup struct {
	Selector      string
	Ranges        []Range
	Platform      json.RawMessage
	Configuration json.RawMessage
}

func nvdAffected(raw json.RawMessage) ([]nvdGroup, error) {
	if len(bytesTrim(raw)) == 0 || string(bytesTrim(raw)) == "null" {
		return nil, nil
	}
	var configurations []struct {
		Operator string    `json:"operator"`
		Negate   bool      `json:"negate"`
		Nodes    []nvdNode `json:"nodes"`
	}
	if err := json.Unmarshal(raw, &configurations); err != nil {
		return nil, err
	}
	type state struct {
		ranges        []Range
		bare          bool
		platforms     []string
		configuration bool
	}
	grouped := map[string]*state{}
	order := []string{}
	add := func(selector string) *state {
		item, ok := grouped[selector]
		if ok {
			return item
		}
		item = &state{}
		grouped[selector] = item
		order = append(order, selector)
		return item
	}
	for _, configuration := range configurations {
		vulnerable, runningOn, blocked, err := nvdConfiguration(configuration.Operator, configuration.Negate, configuration.Nodes)
		if err != nil {
			return nil, err
		}
		if blocked {
			for _, match := range vulnerable {
				selector, versionRange, qualifiers, skip, err := nvdVersionRange(match)
				if err != nil {
					return nil, err
				}
				if skip {
					continue
				}
				item := add(selector)
				item.configuration = true
				if versionRange != nil {
					item.ranges = append(item.ranges, *versionRange)
				}
				item.platforms = append(item.platforms, qualifiers...)
			}
			continue
		}
		for _, match := range vulnerable {
			selector, versionRange, qualifiers, skip, err := nvdVersionRange(match)
			if err != nil {
				return nil, err
			}
			if skip {
				continue
			}
			item := add(selector)
			if versionRange != nil {
				item.ranges = append(item.ranges, *versionRange)
			}
			if len(runningOn) == 0 && len(qualifiers) == 0 {
				item.bare = true
				continue
			}
			item.platforms = append(item.platforms, append(append([]string{}, runningOn...), qualifiers...)...)
		}
	}
	var out []nvdGroup
	for _, selector := range order {
		item := grouped[selector]
		group := nvdGroup{Selector: selector, Ranges: item.ranges}
		if !item.bare && (item.configuration || len(item.platforms) > 0) {
			if item.configuration {
				encoded, err := json.Marshal(map[string]bool{"unresolved_configuration": true})
				if err != nil {
					return nil, err
				}
				group.Configuration = encoded
			}
			if len(item.platforms) > 0 {
				encoded, err := json.Marshal(map[string][]string{"required": uniqueStrings(item.platforms)})
				if err != nil {
					return nil, err
				}
				group.Platform = encoded
			}
		}
		out = append(out, group)
	}
	return out, nil
}

func nvdConfiguration(operator string, negate bool, nodes []nvdNode) (vulnerable []nvdMatch, runningOn []string, blocked bool, err error) {
	if negate || strings.EqualFold(operator, "AND") && hasNested(nodes) {
		blocked = true
	}
	if strings.EqualFold(operator, "AND") {
		for _, node := range nodes {
			if node.Negate || len(node.Nodes) > 0 {
				blocked = true
			}
			for _, match := range node.CPEMatch {
				if match.Vulnerable {
					vulnerable = append(vulnerable, match)
					continue
				}
				criteria, err := canonicalCPECriteria(match.Criteria)
				if err != nil {
					return nil, nil, false, err
				}
				runningOn = append(runningOn, criteria)
			}
		}
		return vulnerable, runningOn, blocked, nil
	}
	for _, node := range nodes {
		if node.Negate || len(node.Nodes) > 0 || strings.EqualFold(node.Operator, "AND") {
			blocked = true
		}
		for _, match := range node.CPEMatch {
			if !match.Vulnerable {
				continue
			}
			vulnerable = append(vulnerable, match)
		}
		if len(node.Nodes) > 0 {
			nestedVulnerable, nestedRunning, nestedBlocked, err := nvdConfiguration(node.Operator, node.Negate, node.Nodes)
			if err != nil {
				return nil, nil, false, err
			}
			vulnerable = append(vulnerable, nestedVulnerable...)
			runningOn = append(runningOn, nestedRunning...)
			blocked = blocked || nestedBlocked
		}
	}
	return vulnerable, nil, blocked, nil
}

func hasNested(nodes []nvdNode) bool {
	for _, node := range nodes {
		if len(node.Nodes) > 0 {
			return true
		}
	}
	return false
}

func nvdVersionRange(match nvdMatch) (string, *Range, []string, bool, error) {
	criteria, err := canonicalCPECriteria(match.Criteria)
	if err != nil {
		return "", nil, nil, false, err
	}
	parts := splitCPEComponents(criteria)
	version := unescapeCPE(parts[5])
	if version == "-" {
		return criteria, nil, nil, true, nil
	}
	if match.VersionStartIncluding != "" && match.VersionStartExcluding != "" {
		return "", nil, nil, false, fmt.Errorf("cpe %s has both start bounds", criteria)
	}
	if match.VersionEndIncluding != "" && match.VersionEndExcluding != "" {
		return "", nil, nil, false, fmt.Errorf("cpe %s has both end bounds", criteria)
	}
	var qualifiers []string
	for _, index := range []int{6, 7, 8, 9, 10, 11, 12} {
		value := unescapeCPE(parts[index])
		if value != "*" && value != "-" {
			qualifiers = append(qualifiers, parts[index])
		}
	}
	item := Range{Ecosystem: "generic", StartInclusive: true}
	bounded := match.VersionStartIncluding != "" || match.VersionStartExcluding != "" || match.VersionEndIncluding != "" || match.VersionEndExcluding != ""
	if version != "*" && bounded {
		return "", nil, nil, false, fmt.Errorf("cpe %s sets a version and a version bound", criteria)
	}
	switch {
	case version != "*":
		item.Start = version
		item.End = version
		item.StartInclusive = true
		item.EndInclusive = true
		item.Exact = true
	default:
		if match.VersionStartIncluding != "" {
			item.Start = match.VersionStartIncluding
			item.StartInclusive = true
		}
		if match.VersionStartExcluding != "" {
			item.Start = match.VersionStartExcluding
			item.StartInclusive = false
		}
		if match.VersionEndIncluding != "" {
			item.End = match.VersionEndIncluding
			item.EndInclusive = true
		}
		if match.VersionEndExcluding != "" {
			item.End = match.VersionEndExcluding
			item.EndInclusive = false
		}
	}
	return criteria, &item, qualifiers, false, nil
}

func canonicalCPECriteria(value string) (string, error) {
	value = strings.TrimSpace(value)
	if !splitCPEComponentsOK(value) {
		return "", fmt.Errorf("cpe %s is not a cpe 2.3 name", value)
	}
	if strings.Contains(value, `\`) {
		return value, nil
	}
	return strings.ToLower(value), nil
}

func splitCPEComponentsOK(value string) bool {
	return len(splitCPEComponents(value)) == 13
}

func splitCPEComponents(value string) []string {
	var parts []string
	var b strings.Builder
	for i := 0; i < len(value); i++ {
		if value[i] == '\\' && i+1 < len(value) {
			b.WriteByte(value[i])
			i++
			b.WriteByte(value[i])
			continue
		}
		if value[i] == ':' {
			parts = append(parts, b.String())
			b.Reset()
			continue
		}
		b.WriteByte(value[i])
	}
	parts = append(parts, b.String())
	return parts
}

func unescapeCPE(part string) string {
	var b strings.Builder
	for i := 0; i < len(part); i++ {
		if part[i] == '\\' && i+1 < len(part) {
			i++
			b.WriteByte(part[i])
			continue
		}
		b.WriteByte(part[i])
	}
	return b.String()
}
