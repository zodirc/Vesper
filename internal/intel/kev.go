package intel

import (
	"encoding/json"
	"fmt"
)

func parseKEV(document []byte) ([]Record, error) {
	var catalog struct {
		CatalogVersion  string            `json:"catalogVersion"`
		Count           *int              `json:"count"`
		Vulnerabilities []json.RawMessage `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(document, &catalog); err != nil {
		return nil, fmt.Errorf("parse kev catalog: %w", err)
	}
	if catalog.CatalogVersion == "" {
		return nil, fmt.Errorf("kev catalog version is missing")
	}
	if catalog.Count != nil && *catalog.Count != len(catalog.Vulnerabilities) {
		return nil, fmt.Errorf("kev count is %d and the catalog has %d vulnerabilities", *catalog.Count, len(catalog.Vulnerabilities))
	}
	var out []Record
	for _, raw := range catalog.Vulnerabilities {
		var item struct {
			CVEID     string `json:"cveID"`
			DateAdded string `json:"dateAdded"`
			Vendor    string `json:"vendorProject"`
			Product   string `json:"product"`
		}
		if err := json.Unmarshal(raw, &item); err != nil {
			return nil, fmt.Errorf("parse kev vulnerability: %w", err)
		}
		if !cveID(item.CVEID) {
			return nil, fmt.Errorf("kev record %q is not a CVE id", item.CVEID)
		}
		published, err := parseTime(item.DateAdded)
		if err != nil {
			return nil, err
		}
		selector := ""
		if item.Vendor != "" || item.Product != "" {
			selector = item.Vendor + ":" + item.Product
		}
		out = append(out, Record{
			SourceRecordID: item.CVEID, VulnerabilityID: item.CVEID, ProductSelector: selector,
			KEV: true, PublishedAt: published, Raw: append([]byte(nil), raw...),
		})
	}
	return out, nil
}
