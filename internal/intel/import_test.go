package intel

import "testing"

func TestCVSSBaseScore(t *testing.T) {
	score, err := BaseScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
	if err != nil || score != 9.8 {
		t.Fatalf("score = %v err = %v", score, err)
	}
	score, err = BaseScore("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H")
	if err != nil || score != 7.8 {
		t.Fatalf("score = %v err = %v", score, err)
	}
	if _, err := BaseScore("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"); err == nil {
		t.Fatal("cvss 4.0 was accepted")
	}
}

func TestParseOSVDebianKeepsEcosystemAndSeverity(t *testing.T) {
	document := []byte(`{
	  "schema_version": "1.6.1",
	  "id": "GHSA-test-0001",
	  "published": "2026-01-02T03:04:05Z",
	  "aliases": ["CVE-2026-1000"],
	  "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
	  "affected": [{
	    "package": {"ecosystem": "Debian", "name": "nginx"},
	    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "1.0.0"}, {"fixed": "1.26.0"}]}]
	  }]
	}`)
	records, err := Parse("osv", document)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Ecosystem != "deb" || records[0].VulnerabilityID != "CVE-2026-1000" || records[0].Severity != "critical" {
		t.Fatalf("records = %+v", records)
	}
	if records[0].ProductSelector != "Debian:nginx" || len(records[0].Ranges) != 1 || records[0].Ranges[0].End != "1.26.0" || records[0].Ranges[0].EndInclusive {
		t.Fatalf("range = %+v", records[0].Ranges)
	}
	if len(records[0].FixedVersions) != 1 || records[0].FixedVersions[0] != "1.26.0" {
		t.Fatalf("fixed = %+v", records[0].FixedVersions)
	}
}

func TestParseRejectsConflictingEPSS(t *testing.T) {
	document := []byte("#model_version:v2026.01.01\ncve,epss,percentile\nCVE-2026-1000,0.5,0.9\nCVE-2026-1000,0.2,0.1\n")
	if _, err := Parse("epss", document); err == nil {
		t.Fatal("conflicting epss rows were accepted")
	}
}

func TestParseNVDStoresCPERangeWithoutGenericEcosystem(t *testing.T) {
	document := []byte(`{
	  "format": "NVD_CVE",
	  "version": "2.0",
	  "vulnerabilities": [{
	    "cve": {
	      "id": "CVE-2026-2000",
	      "metrics": {"cvssMetricV31": [{"cvssData": {"baseSeverity": "HIGH", "baseScore": 7.5}}]},
	      "configurations": [{"nodes": [{"cpeMatch": [{
	        "vulnerable": true,
	        "criteria": "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*",
	        "versionStartIncluding": "1.0.0",
	        "versionEndExcluding": "1.26.0"
	      }]}]}]
	    }
	  }]
	}`)
	records, err := Parse("NVD", document)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Ecosystem != "cpe" || records[0].Severity != "high" || records[0].Ranges[0].Ecosystem != "cpe" {
		t.Fatalf("records = %+v", records)
	}
}

func TestParseKEVRequiresCatalogVersion(t *testing.T) {
	if _, err := Parse("cisa_kev", []byte(`{"vulnerabilities":[{"cveID":"CVE-2026-1000"}]}`)); err == nil {
		t.Fatal("kev catalog without a version was accepted")
	}
	records, err := Parse("kev", []byte(`{"catalogVersion":"2026.01.02","count":1,"vulnerabilities":[{"cveID":"CVE-2026-1000","vendorProject":"nginx","product":"nginx","dateAdded":"2026-01-02"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || !records[0].KEV || records[0].VulnerabilityID != "CVE-2026-1000" {
		t.Fatalf("records = %+v", records)
	}
}
