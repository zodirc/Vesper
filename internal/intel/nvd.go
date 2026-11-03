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
		Metrics      struct {
			V31 []nvdMetric `json:"cvssMetricV31"`
			V30 []nvdMetric `json:"cvssMetricV30"`
			V2  []struct {
				CvssData struct {
					BaseSeverity string   `json:"baseSeverity"`
					BaseScore    *float64 `json:"baseScore"`
				} `json:"cvssData"`
			} `json:"cvssMetricV2"`
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
	severity, severityData, err := nvdSeverity(cve.Metrics.V31, cve.Metrics.V30, cve.Metrics.V2)
	if err != nil {
		return nil, fmt.Errorf("nvd %s: %w", cve.ID, err)
	}
	matches, err := nvdMatches(cve.Configurations)
	if err != nil {
		return nil, fmt.Errorf("nvd %s: %w", cve.ID, err)
	}
	if len(matches) == 0 {
		return []Record{{
			SourceRecordID: cve.ID, VulnerabilityID: cve.ID, Severity: severity, SeverityData: severityData,
			ConfigurationConstraints: emptyObject(cve.Configurations), PublishedAt: published, ModifiedAt: modified,
			Raw: append([]byte(nil), body...),
		}}, nil
	}
	var out []Record
	for _, match := range matches {
		selector := match.Criteria
		recordID := cve.ID + "#" + selector
		if match.VersionStartIncluding != "" || match.VersionStartExcluding != "" || match.VersionEndIncluding != "" || match.VersionEndExcluding != "" {
			recordID += "#" + match.VersionStartIncluding + "#" + match.VersionStartExcluding + "#" + match.VersionEndIncluding + "#" + match.VersionEndExcluding
		}
		item := Range{Ecosystem: "cpe", StartInclusive: match.VersionStartIncluding != "" || (match.VersionStartIncluding == "" && match.VersionStartExcluding == "")}
		if match.VersionStartIncluding != "" && match.VersionStartExcluding != "" {
			return nil, fmt.Errorf("nvd %s has both start bounds", cve.ID)
		}
		if match.VersionEndIncluding != "" && match.VersionEndExcluding != "" {
			return nil, fmt.Errorf("nvd %s has both end bounds", cve.ID)
		}
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
		out = append(out, Record{
			SourceRecordID: recordID, VulnerabilityID: cve.ID, Ecosystem: "cpe", ProductSelector: selector,
			Ranges: []Range{item}, ConfigurationConstraints: cve.Configurations, SeverityData: severityData, Severity: severity,
			PublishedAt: published, ModifiedAt: modified, Raw: append([]byte(nil), body...),
		})
	}
	return out, nil
}

type nvdMetric struct {
	CvssData struct {
		BaseSeverity string   `json:"baseSeverity"`
		BaseScore    *float64 `json:"baseScore"`
		VectorString string   `json:"vectorString"`
	} `json:"cvssData"`
}

func nvdSeverity(v31, v30 []nvdMetric, v2 []struct {
	CvssData struct {
		BaseSeverity string   `json:"baseSeverity"`
		BaseScore    *float64 `json:"baseScore"`
	} `json:"cvssData"`
}) (string, json.RawMessage, error) {
	raw, err := json.Marshal(struct {
		V31 any `json:"cvssMetricV31,omitempty"`
		V30 any `json:"cvssMetricV30,omitempty"`
		V2  any `json:"cvssMetricV2,omitempty"`
	}{emptySlice(v31), emptySlice(v30), emptySlice(v2)})
	if err != nil {
		return "", nil, err
	}
	if string(raw) == "{}" {
		raw = nil
	}
	if len(v31) > 0 {
		level, err := severityFromCVSS(v31[0].CvssData.BaseSeverity, v31[0].CvssData.BaseScore)
		return level, raw, err
	}
	if len(v30) > 0 {
		level, err := severityFromCVSS(v30[0].CvssData.BaseSeverity, v30[0].CvssData.BaseScore)
		return level, raw, err
	}
	if len(v2) > 0 {
		level, err := severityFromCVSS(v2[0].CvssData.BaseSeverity, v2[0].CvssData.BaseScore)
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

func nvdMatches(raw json.RawMessage) ([]nvdMatch, error) {
	if len(bytesTrim(raw)) == 0 || string(bytesTrim(raw)) == "null" {
		return nil, nil
	}
	var configurations []struct {
		Nodes []struct {
			CPEMatch []nvdMatch `json:"cpeMatch"`
		} `json:"nodes"`
	}
	if err := json.Unmarshal(raw, &configurations); err != nil {
		return nil, err
	}
	var out []nvdMatch
	for _, configuration := range configurations {
		for _, node := range configuration.Nodes {
			for _, match := range node.CPEMatch {
				if !match.Vulnerable {
					continue
				}
				if strings.TrimSpace(match.Criteria) == "" {
					return nil, fmt.Errorf("vulnerable cpe match has no criteria")
				}
				out = append(out, match)
			}
		}
	}
	return out, nil
}

func emptyObject(raw json.RawMessage) json.RawMessage {
	if len(bytesTrim(raw)) == 0 || string(bytesTrim(raw)) == "null" {
		return nil
	}
	return raw
}
