package intel

import (
	"encoding/json"
	"fmt"
	"strings"
)

func parseDistro(document []byte) ([]Record, error) {
	var packages map[string]map[string]json.RawMessage
	if err := json.Unmarshal(document, &packages); err != nil {
		return nil, fmt.Errorf("parse distro advisory: %w", err)
	}
	if len(packages) == 0 {
		return nil, fmt.Errorf("distro advisory has no packages")
	}
	var out []Record
	var distribution string
	for name, vulnerabilities := range packages {
		if !packageName(name) {
			return nil, fmt.Errorf("distro package %s is invalid", name)
		}
		for vulnerabilityID, raw := range vulnerabilities {
			if !cveID(vulnerabilityID) && !tempID(vulnerabilityID) {
				return nil, fmt.Errorf("distro vulnerability id %s is invalid", vulnerabilityID)
			}
			var body struct {
				Releases map[string]json.RawMessage `json:"releases"`
			}
			if err := json.Unmarshal(raw, &body); err != nil {
				return nil, fmt.Errorf("parse distro %s %s: %w", name, vulnerabilityID, err)
			}
			if len(body.Releases) == 0 {
				return nil, fmt.Errorf("distro %s %s has no releases", name, vulnerabilityID)
			}
			for release, releaseRaw := range body.Releases {
				if release == "upstream" {
					continue
				}
				family, ok := releaseFamily(release)
				if !ok {
					return nil, fmt.Errorf("distro release %s is not recognized", release)
				}
				if distribution == "" {
					distribution = family
				} else if distribution != family {
					return nil, fmt.Errorf("distro document mixes %s and %s", distribution, family)
				}
				var status struct {
					Status       string `json:"status"`
					FixedVersion string `json:"fixed_version"`
				}
				if err := json.Unmarshal(releaseRaw, &status); err != nil {
					return nil, fmt.Errorf("parse distro %s %s %s: %w", name, vulnerabilityID, release, err)
				}
				record, ok, err := distroRecord(name, vulnerabilityID, family, release, status.Status, status.FixedVersion, releaseRaw)
				if err != nil {
					return nil, err
				}
				if ok {
					out = append(out, record)
				}
			}
		}
	}
	return out, nil
}

func distroRecord(name, vulnerabilityID, distribution, release, status, fixed string, raw json.RawMessage) (Record, bool, error) {
	fixed = strings.TrimSpace(fixed)
	var span Range
	switch status {
	case "resolved":
		if fixed == "" {
			return Record{}, false, nil
		}
		if !debVersionToken(fixed) {
			return Record{}, false, fmt.Errorf("distro %s %s %s fixed version is invalid", name, vulnerabilityID, release)
		}
		if fixed == "0" {
			span = Range{Ecosystem: "deb", Start: "0", StartInclusive: true, Excluded: true}
		} else {
			span = Range{Ecosystem: "deb", End: fixed, EndInclusive: false}
		}
	case "open":
		if fixed != "" {
			return Record{}, false, fmt.Errorf("distro %s %s %s is open and also has a fixed version", name, vulnerabilityID, release)
		}
		span = Range{Ecosystem: "deb"}
	case "undetermined", "ignored":
		return Record{}, false, nil
	default:
		return Record{}, false, fmt.Errorf("distro %s %s %s status %s is not supported", name, vulnerabilityID, release, status)
	}
	platform, err := json.Marshal(struct {
		Distribution string `json:"distribution"`
		Release      string `json:"release"`
	}{distribution, release})
	if err != nil {
		return Record{}, false, err
	}
	stored, err := json.Marshal(struct {
		Package         string          `json:"package"`
		VulnerabilityID string          `json:"vulnerability_id"`
		Release         json.RawMessage `json:"release"`
	}{name, vulnerabilityID, raw})
	if err != nil {
		return Record{}, false, err
	}
	record := Record{
		SourceRecordID:  name + "#" + vulnerabilityID + "#" + distribution + "#" + release,
		VulnerabilityID: vulnerabilityID, Ecosystem: "deb", ProductSelector: name,
		Ranges: []Range{span}, PlatformConstraints: platform, Raw: stored,
	}
	if status == "resolved" && fixed != "0" {
		record.FixedVersions = []string{fixed}
	}
	return record, true, nil
}

func releaseFamily(release string) (string, bool) {
	switch release {
	case "squeeze", "wheezy", "jessie", "stretch", "buster", "bullseye", "bookworm", "trixie", "forky", "sid", "experimental":
		return "debian", true
	case "precise", "trusty", "xenial", "bionic", "focal", "jammy", "noble", "oracular", "plucky", "questing":
		return "ubuntu", true
	default:
		return "", false
	}
}

func packageName(value string) bool {
	if value == "" || len(value) > 200 {
		return false
	}
	for i, r := range value {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		case i > 0 && (r == '+' || r == '.' || r == '-'):
		default:
			return false
		}
	}
	return true
}

func debVersionToken(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, r := range value {
		switch {
		case r >= '0' && r <= '9', r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z':
		case r == '.' || r == '+' || r == '~' || r == ':' || r == '-':
		default:
			return false
		}
	}
	return true
}

func tempID(value string) bool {
	if !strings.HasPrefix(value, "TEMP-") || len(value) > 80 {
		return false
	}
	for _, r := range value[len("TEMP-"):] {
		if r >= '0' && r <= '9' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r == '-' {
			continue
		}
		return false
	}
	return len(value) > len("TEMP-")
}
