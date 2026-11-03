package intel

import (
	"encoding/json"
	"fmt"
	"strings"
)

func parseOSV(document []byte) ([]Record, error) {
	var envelope struct {
		SchemaVersion   string            `json:"schema_version"`
		Vulnerabilities []json.RawMessage `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(document, &envelope); err != nil {
		return nil, fmt.Errorf("parse osv document: %w", err)
	}
	if envelope.SchemaVersion != "" && !strings.HasPrefix(envelope.SchemaVersion, "1.") {
		return nil, fmt.Errorf("osv schema version %s is not supported", envelope.SchemaVersion)
	}
	raws := envelope.Vulnerabilities
	if len(raws) == 0 {
		raws = []json.RawMessage{append([]byte(nil), document...)}
	}
	var out []Record
	for _, raw := range raws {
		records, err := parseOSVRecord(raw)
		if err != nil {
			return nil, err
		}
		out = append(out, records...)
	}
	return out, nil
}

func parseOSVRecord(raw json.RawMessage) ([]Record, error) {
	var body struct {
		SchemaVersion string `json:"schema_version"`
		ID            string `json:"id"`
		Published     string `json:"published"`
		Modified      string `json:"modified"`
		Aliases       []string
		Severity      []struct {
			Type  string `json:"type"`
			Score string `json:"score"`
		} `json:"severity"`
		Affected []struct {
			Package struct {
				Ecosystem string `json:"ecosystem"`
				Name      string `json:"name"`
			} `json:"package"`
			Ranges []struct {
				Type   string `json:"type"`
				Events []struct {
					Introduced   string `json:"introduced"`
					Fixed        string `json:"fixed"`
					LastAffected string `json:"last_affected"`
					Limit        string `json:"limit"`
				} `json:"events"`
			} `json:"ranges"`
		} `json:"affected"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		return nil, fmt.Errorf("parse osv record: %w", err)
	}
	if body.SchemaVersion != "" && !strings.HasPrefix(body.SchemaVersion, "1.") {
		return nil, fmt.Errorf("osv schema version %s is not supported", body.SchemaVersion)
	}
	if strings.TrimSpace(body.ID) == "" {
		return nil, fmt.Errorf("osv record is missing id")
	}
	published, err := parseTime(body.Published)
	if err != nil {
		return nil, err
	}
	modified, err := parseTime(body.Modified)
	if err != nil {
		return nil, err
	}
	severity, severityData, err := osvSeverity(body.Severity)
	if err != nil {
		return nil, fmt.Errorf("osv %s: %w", body.ID, err)
	}
	vulnerabilityID := body.ID
	for _, alias := range body.Aliases {
		if cveID(alias) {
			vulnerabilityID = alias
			break
		}
	}
	if len(body.Affected) == 0 {
		return nil, fmt.Errorf("osv %s has no affected package", body.ID)
	}
	var out []Record
	for _, affected := range body.Affected {
		ecosystem := strings.TrimSpace(affected.Package.Ecosystem)
		name := strings.TrimSpace(affected.Package.Name)
		if ecosystem == "" || name == "" {
			return nil, fmt.Errorf("osv %s has an affected package without ecosystem or name", body.ID)
		}
		ranges, fixed, err := osvRanges(affected.Ranges, storedEcosystem(ecosystem))
		if err != nil {
			return nil, fmt.Errorf("osv %s %s:%s: %w", body.ID, ecosystem, name, err)
		}
		selector := ecosystem + ":" + name
		out = append(out, Record{
			SourceRecordID:  body.ID + "#" + selector,
			VulnerabilityID: vulnerabilityID,
			Ecosystem:       storedEcosystem(ecosystem),
			ProductSelector: selector,
			Ranges:          ranges,
			FixedVersions:   fixed,
			SeverityData:    severityData,
			Severity:        severity,
			PublishedAt:     published,
			ModifiedAt:      modified,
			Raw:             append([]byte(nil), raw...),
		})
	}
	return out, nil
}

func osvSeverity(items []struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}) (string, json.RawMessage, error) {
	if len(items) == 0 {
		return "", nil, nil
	}
	raw, err := json.Marshal(items)
	if err != nil {
		return "", nil, err
	}
	for _, item := range items {
		switch strings.ToUpper(item.Type) {
		case "CVSS_V3", "CVSS_V3.0", "CVSS_V3.1":
			score, err := BaseScore(item.Score)
			if err != nil {
				return "", nil, err
			}
			level, err := severityFromCVSS("", &score)
			if err != nil {
				return "", nil, err
			}
			return level, raw, nil
		}
	}
	return "", raw, nil
}

func osvRanges(items []struct {
	Type   string `json:"type"`
	Events []struct {
		Introduced   string `json:"introduced"`
		Fixed        string `json:"fixed"`
		LastAffected string `json:"last_affected"`
		Limit        string `json:"limit"`
	} `json:"events"`
}, ecosystem string) ([]Range, []string, error) {
	var ranges []Range
	var fixed []string
	for _, item := range items {
		introduced := 0
		endKind := ""
		end := ""
		limit := ""
		var current *Range
		for _, event := range item.Events {
			set := 0
			if event.Introduced != "" {
				set++
			}
			if event.Fixed != "" {
				set++
			}
			if event.LastAffected != "" {
				set++
			}
			if event.Limit != "" {
				set++
			}
			if set != 1 {
				return nil, nil, fmt.Errorf("range event must set exactly one boundary")
			}
			switch {
			case event.Introduced != "":
				if current != nil {
					return nil, nil, fmt.Errorf("introduced starts a second window before the previous window ends")
				}
				current = &Range{Ecosystem: rangeEcosystem(item.Type, ecosystem), StartInclusive: true}
				if event.Introduced != "0" {
					current.Start = event.Introduced
				}
				introduced++
			case event.Fixed != "":
				if current == nil {
					return nil, nil, fmt.Errorf("fixed appears before introduced")
				}
				current.End = event.Fixed
				current.EndInclusive = false
				endKind = "fixed"
				end = event.Fixed
				ranges = append(ranges, *current)
				fixed = append(fixed, event.Fixed)
				current = nil
			case event.LastAffected != "":
				if current == nil {
					return nil, nil, fmt.Errorf("last_affected appears before introduced")
				}
				current.End = event.LastAffected
				current.EndInclusive = true
				endKind = "last_affected"
				end = event.LastAffected
				ranges = append(ranges, *current)
				current = nil
			case event.Limit != "":
				limit = event.Limit
			}
		}
		if current != nil {
			if limit != "" && endKind == "" {
				current.End = limit
				current.EndInclusive = false
			}
			ranges = append(ranges, *current)
		}
		if introduced == 0 {
			return nil, nil, fmt.Errorf("range has no introduced event")
		}
		if endKind != "" && limit != "" && limit != end && item.Type == "GIT" {
			return nil, nil, fmt.Errorf("git range limit disagrees with the range end")
		}
	}
	return ranges, fixed, nil
}

func storedEcosystem(source string) string {
	switch strings.ToLower(strings.TrimSpace(source)) {
	case "debian", "ubuntu":
		return "deb"
	case "redhat", "red hat", "rhel", "rocky linux", "almalinux", "alma linux", "fedora", "suse", "opensuse", "opensuse leap":
		return "rpm"
	default:
		return strings.ToLower(strings.TrimSpace(source))
	}
}

func rangeEcosystem(rangeType, ecosystem string) string {
	if strings.EqualFold(rangeType, "GIT") {
		return "git"
	}
	return ecosystem
}
