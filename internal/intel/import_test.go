package intel

import (
	"strings"
	"testing"
)

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
	if len(records) != 1 || records[0].Ecosystem != "cpe" || records[0].Severity != "high" || records[0].Ranges[0].Ecosystem != "generic" {
		t.Fatalf("records = %+v", records)
	}
	if len(records[0].ConfigurationConstraints) != 0 || len(records[0].PlatformConstraints) != 0 {
		t.Fatalf("constraints = %s %s", records[0].ConfigurationConstraints, records[0].PlatformConstraints)
	}
	if records[0].Ranges[0].Start != "1.0.0" || records[0].Ranges[0].End != "1.26.0" || records[0].Ranges[0].EndInclusive {
		t.Fatalf("range = %+v", records[0].Ranges[0])
	}
}

func TestParseNVDUsesPrimaryCVSSAndExactVersion(t *testing.T) {
	document := []byte(`{
	  "vulnerabilities": [{
	    "cve": {
	      "id": "CVE-2026-2001",
	      "vulnStatus": "Analyzed",
	      "metrics": {
	        "cvssMetricV40": [{"type": "Secondary", "cvssData": {"baseSeverity": "LOW", "baseScore": 2.0}}],
	        "cvssMetricV31": [{"type": "Primary", "cvssData": {"baseSeverity": "HIGH", "baseScore": 7.5}}]
	      },
	      "configurations": [{"nodes": [{"operator": "OR", "cpeMatch": [{
	        "vulnerable": true,
	        "criteria": "cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*"
	      }]}]}]
	    }
	  }]
	}`)
	records, err := Parse("nvd", document)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Severity != "high" || !records[0].Ranges[0].Exact || records[0].Ranges[0].Start != "1.24.0" {
		t.Fatalf("records = %+v", records)
	}
	if records[0].ProductSelector != "cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*" {
		t.Fatalf("selector = %s", records[0].ProductSelector)
	}
}

func TestParseNVDRejectedWithdrawsAndANDKeepsRunningOn(t *testing.T) {
	rejected, err := Parse("nvd", []byte(`{"vulnerabilities":[{"cve":{"id":"CVE-2026-2002","vulnStatus":"Rejected"}}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(rejected) != 1 || !rejected[0].WithdrawsPrior || len(rejected[0].Ranges) != 0 {
		t.Fatalf("rejected = %+v", rejected)
	}
	document := []byte(`{
	  "vulnerabilities": [{
	    "cve": {
	      "id": "CVE-2026-2003",
	      "configurations": [{
	        "operator": "AND",
	        "nodes": [
	          {"operator": "OR", "cpeMatch": [{"vulnerable": true, "criteria": "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*", "versionEndExcluding": "1.26.0"}]},
	          {"operator": "OR", "cpeMatch": [{"vulnerable": false, "criteria": "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*"}]}
	        ]
	      }]
	    }
	  }]
	}`)
	records, err := Parse("nvd", document)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || len(records[0].PlatformConstraints) == 0 || !records[0].Ranges[0].EndInclusive == false {
		t.Fatalf("records = %+v platform = %s", records[0].Ranges, records[0].PlatformConstraints)
	}
}

func TestParseOSVVersionsAndWithdrawn(t *testing.T) {
	document := []byte(`{
	  "schema_version": "1.6.0",
	  "id": "GHSA-test-0002",
	  "affected": [{
	    "package": {"ecosystem": "npm", "name": "left-pad"},
	    "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}],
	    "versions": ["1.0.0"]
	  }]
	}`)
	records, err := Parse("osv", document)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Ranges[0].Ecosystem != "semver" || !records[0].Ranges[1].Exact || records[0].Ranges[1].Start != "1.0.0" {
		t.Fatalf("records = %+v", records[0].Ranges)
	}
	withdrawn, err := Parse("osv", []byte(`{
	  "id": "GHSA-test-0002",
	  "withdrawn": "2026-02-02T00:00:00Z",
	  "affected": [{"package": {"ecosystem": "npm", "name": "left-pad"}, "versions": ["1.0.0"]}]
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(withdrawn) != 1 || len(withdrawn[0].Ranges) != 0 || withdrawn[0].SourceRecordID != "GHSA-test-0002#npm:left-pad" {
		t.Fatalf("withdrawn = %+v", withdrawn)
	}
	qualified, err := Parse("osv", []byte(`{
	  "id": "CVE-2026-4100",
	  "affected": [
	    {"package": {"ecosystem": "Debian:12", "name": "nginx"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.26.0-1"}]}]},
	    {"package": {"ecosystem": "Go", "name": "example.com/mod"}, "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.2.0"}]}]},
	    {"package": {"ecosystem": "Ubuntu:Pro:18.04:LTS", "name": "openssl"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.1.1-1"}]}]}
	  ]
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(qualified) != 3 || qualified[0].Ecosystem != "deb" || qualified[0].ProductSelector != "Debian:12:nginx" || !strings.Contains(string(qualified[0].PlatformConstraints), `"release":"12"`) || !strings.Contains(string(qualified[0].PlatformConstraints), `"package":"nginx"`) {
		t.Fatalf("debian = %+v %s", qualified[0], qualified[0].PlatformConstraints)
	}
	if qualified[1].Ecosystem != "go" || qualified[1].Ranges[0].Ecosystem != "semver" || len(qualified[1].PlatformConstraints) != 0 {
		t.Fatalf("go = %+v", qualified[1])
	}
	if qualified[2].Ecosystem != "deb" || !strings.Contains(string(qualified[2].PlatformConstraints), `"distribution":"ubuntu-pro"`) {
		t.Fatalf("ubuntu pro = %s", qualified[2].PlatformConstraints)
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
