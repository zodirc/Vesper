package intel

import (
	"strings"
	"testing"
)

func TestCSAFKeepsListedVersionsExact(t *testing.T) {
	document := []byte(`{
		"document": {"category": "csaf_security_advisory", "csaf_version": "2.0", "tracking": {"id": "EXAMPLE-2026-0001", "status": "final", "initial_release_date": "2026-01-02T00:00:00Z", "current_release_date": "2026-01-03T00:00:00Z"}},
		"product_tree": {"branches": [{"category": "vendor", "name": "Example", "branches": [{"category": "product_name", "name": "Widget", "branches": [
			{"category": "product_version", "name": "1.2.3", "product": {"name": "Widget 1.2.3", "product_id": "WID-123", "product_identification_helper": {"purl": "pkg:generic/example/widget@1.2.3"}}},
			{"category": "product_version", "name": "1.2.4", "product": {"name": "Widget 1.2.4", "product_id": "WID-124", "product_identification_helper": {"purl": "pkg:generic/example/widget@1.2.4"}}}
		]}]}]},
		"vulnerabilities": [{"cve": "CVE-2026-1000", "product_status": {"known_affected": ["WID-123"], "fixed": ["WID-124"]}, "scores": [{"products": ["WID-123"], "cvss_v3": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]}]
	}`)
	records, err := Parse("vendor", document)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Source != SourceVendor || records[0].ProductSelector != "pkg:generic/example/widget" || records[0].Severity != "critical" {
		t.Fatalf("records = %+v", records)
	}
	var affected, excluded int
	for _, item := range records[0].Ranges {
		if item.Exact && !item.Excluded && item.Start == "1.2.3" {
			affected++
		}
		if item.Exact && item.Excluded && item.Start == "1.2.4" {
			excluded++
		}
	}
	if affected != 1 || excluded != 1 || len(records[0].FixedVersions) != 1 || records[0].FixedVersions[0] != "1.2.4" {
		t.Fatalf("ranges = %+v fixed = %+v", records[0].Ranges, records[0].FixedVersions)
	}
	if _, err := Parse("csaf", []byte(`{"document":{"category":"csaf_security_advisory","csaf_version":"2.0","tracking":{"id":"X","status":"draft","initial_release_date":"2026-01-02T00:00:00Z"}},"vulnerabilities":[{}]}`)); err == nil || !strings.Contains(err.Error(), "draft") {
		t.Fatal(err)
	}
}

func TestCSAFBoundsFirstAffectedAndFirstFixed(t *testing.T) {
	document := []byte(`{
		"document": {"category": "csaf_vex", "csaf_version": "2.0", "tracking": {"id": "EXAMPLE-2026-0002", "status": "interim", "initial_release_date": "2026-01-02T00:00:00Z"}},
		"product_tree": {"branches": [{"category": "vendor", "name": "Example", "branches": [{"category": "product_name", "name": "Widget", "branches": [
			{"category": "product_version", "name": "1.0.0", "product": {"name": "Widget 1.0.0", "product_id": "A", "product_identification_helper": {"purl": "pkg:generic/example/widget@1.0.0"}}},
			{"category": "product_version", "name": "1.2.0", "product": {"name": "Widget 1.2.0", "product_id": "B", "product_identification_helper": {"purl": "pkg:generic/example/widget@1.2.0"}}}
		]}]}]},
		"vulnerabilities": [{"cve": "CVE-2026-1001", "product_status": {"first_affected": ["A"], "first_fixed": ["B"]}}]
	}`)
	records, err := Parse("vendor_advisory", document)
	if err != nil || len(records) != 1 || len(records[0].Ranges) != 1 {
		t.Fatalf("records = %+v err = %v", records, err)
	}
	span := records[0].Ranges[0]
	if span.Exact || span.Excluded || span.Start != "1.0.0" || !span.StartInclusive || span.End != "1.2.0" || span.EndInclusive {
		t.Fatalf("span = %+v", span)
	}
}

func TestDistroAdvisoryUsesDebianRevision(t *testing.T) {
	document := []byte(`{
		"openssl": {"CVE-2026-2000": {"releases": {
			"bookworm": {"status": "resolved", "fixed_version": "3.0.11-1~deb12u2", "urgency": "high"},
			"bullseye": {"status": "open"},
			"upstream": {"status": "resolved", "fixed_version": "3.0.12"}
		}}},
		"nginx": {"CVE-2026-2001": {"releases": {"bookworm": {"status": "ignored"}}}}
	}`)
	records, err := Parse("distro", document)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 {
		t.Fatalf("records = %+v", records)
	}
	var bookworm, bullseye Record
	for _, item := range records {
		if item.Source != SourceDistro || item.VulnerabilityID != "CVE-2026-2000" || item.Ecosystem != "deb" || item.ProductSelector != "openssl" {
			t.Fatalf("record = %+v", item)
		}
		switch {
		case strings.Contains(item.SourceRecordID, "bookworm"):
			bookworm = item
		case strings.Contains(item.SourceRecordID, "bullseye"):
			bullseye = item
		default:
			t.Fatalf("record = %+v", item)
		}
	}
	if bookworm.Ranges[0].End != "3.0.11-1~deb12u2" || bookworm.Ranges[0].EndInclusive || len(bookworm.FixedVersions) != 1 {
		t.Fatalf("bookworm = %+v", bookworm)
	}
	if bullseye.Ranges[0].Start != "" || bullseye.Ranges[0].End != "" {
		t.Fatalf("bullseye = %+v", bullseye.Ranges)
	}
	if _, err := Parse("distro_advisory", []byte(`{"openssl":{"CVE-2026-2000":{"releases":{"unstable-next":{"status":"open"}}}}}`)); err == nil {
		t.Fatal("unknown release was accepted")
	}
}
