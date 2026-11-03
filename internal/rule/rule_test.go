package rule

import (
	"errors"
	"testing"
	"time"
)

func TestFingerprintDoesNotInventProductFromPort(t *testing.T) {
	packs, err := Builtin(time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	rules := Fingerprints(packs, FingerprintVersion)
	hits := MatchFingerprints(rules, Fact{Type: "protocol_response", Value: map[string]any{"port": "80"}})
	if len(hits) != 0 {
		t.Fatalf("hits = %+v", hits)
	}
	hits = MatchFingerprints(rules, Fact{Type: "protocol_response", Value: map[string]any{
		"protocol": "http", "headers": map[string]any{"server": "nginx/1.24.0"},
	}})
	if len(hits) != 1 || hits[0].Product != "nginx" || hits[0].Version != "1.24.0" || hits[0].Status != "candidate" {
		t.Fatalf("hits = %+v", hits)
	}
}

func TestPublishedPackRejectsContentChange(t *testing.T) {
	now := time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC)
	packs, err := Builtin(now)
	if err != nil {
		t.Fatal(err)
	}
	changed := packs[0]
	changed.Fingerprints[0].ServiceType = "database"
	digest, err := Digest(changed)
	if err != nil {
		t.Fatal(err)
	}
	changed.ContentDigest = digest
	if err := CheckUpdate(packs[0], changed); !errors.Is(err, ErrPublishedImmutable) {
		t.Fatalf("err = %v", err)
	}
}

func TestConfigRuleDoesNotPassWithoutEvidence(t *testing.T) {
	packs, err := Builtin(time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	rules := Configs(packs, ConfigVersion)
	missing := EvaluateConfigs(rules, nil)
	if missing[0].Status != "insufficient_evidence" || missing[0].Unmatched["required_observation_type"] != "host_inventory" {
		t.Fatalf("missing = %+v", missing[0])
	}
	unsupported := EvaluateConfigs(rules, []Fact{{Type: "host_inventory", Subject: "local:collect_os_info", ResultStatus: "unsupported"}})
	if unsupported[0].Status != "not_applicable" {
		t.Fatalf("unsupported = %+v", unsupported[0])
	}
	present := EvaluateConfigs(rules, []Fact{{Type: "host_inventory", Subject: "local:collect_os_info", ResultStatus: "collected", Value: map[string]any{"name": "Fedora"}}})
	if present[0].Status != "not_vulnerable" || present[0].Matched["pass_field"] != "name" || present[0].Matched["present"] != true {
		t.Fatalf("present = %+v", present[0])
	}
	absent := EvaluateConfigs(rules, []Fact{{Type: "host_inventory", Subject: "local:collect_os_info", ResultStatus: "collected", Value: map[string]any{}}})
	if absent[0].Status != "confirmed" || absent[0].Unmatched["pass_field"] != "name" {
		t.Fatalf("absent = %+v", absent[0])
	}
	envelope := EvaluateConfigs(rules, []Fact{{
		Type: "host_inventory", Subject: "local:collect_os_info", ResultStatus: "observed",
		Value: map[string]any{"collection_status": "collected", "name": "Fedora"},
	}})
	if envelope[0].Status != "not_vulnerable" {
		t.Fatalf("envelope = %+v", envelope[0])
	}
}

func TestActiveDetectionStaysUnexecuted(t *testing.T) {
	if got := ActiveDetection(false); got.Status != "unsupported" {
		t.Fatalf("status = %s", got.Status)
	}
	if got := ActiveDetection(true); got.Status != "skipped" {
		t.Fatalf("status = %s", got.Status)
	}
}
