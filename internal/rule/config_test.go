package rule

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestBuiltinConfigJSONOmitsPredicateFields(t *testing.T) {
	packs, err := Builtin(time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	for _, pack := range packs {
		if pack.Type != "config" {
			continue
		}
		digest, err := Digest(pack)
		if err != nil || digest != pack.ContentDigest {
			t.Fatalf("digest = %s stored = %s err = %v", digest, pack.ContentDigest, err)
		}
		for _, item := range pack.Configs {
			raw, err := json.Marshal(item)
			if err != nil {
				t.Fatal(err)
			}
			for _, key := range []string{`"Title"`, `"Pass"`, `"Fail"`, `"Applicability"`, `"Category"`, `"Remediation"`} {
				if strings.Contains(string(raw), key) {
					t.Fatalf("%s contains %s: %s", item.Key, key, raw)
				}
			}
		}
	}
}

func TestPredicateConfigSeparatesPassFailAndMissingEvidence(t *testing.T) {
	item := ConfigRule{
		Key: "os_name", Version: "config:test", SubjectType: "asset", RequiredObservationType: "host_inventory",
		Operation: "collect_os_info", Severity: "low", Title: "OS name is present", Category: "host",
		Pass: []Predicate{{Field: "name", Op: "exists"}},
		Fail: []Predicate{{Field: "name", Op: "absent"}},
	}
	collected := func(value map[string]any) Fact {
		value["collection_status"] = "collected"
		return Fact{Type: "host_inventory", Subject: "local:collect_os_info", ResultStatus: "observed", Value: value}
	}
	present := EvaluateConfigs([]ConfigRule{item}, []Fact{collected(map[string]any{"name": "Fedora"})})
	if present[0].Status != "not_vulnerable" || present[0].Matched["pass"] != true || present[0].Unmatched["fail"] != false || present[0].Matched["pass_field"] != nil {
		t.Fatalf("present = %+v", present[0])
	}
	absent := EvaluateConfigs([]ConfigRule{item}, []Fact{collected(map[string]any{})})
	if absent[0].Status != "confirmed" || absent[0].Summary != "fail" || absent[0].Unmatched["pass"] != false || absent[0].Matched["fail"] != true {
		t.Fatalf("absent = %+v", absent[0])
	}
	item.Remediation = "Record the operating system name."
	remediated := EvaluateConfigs([]ConfigRule{item}, []Fact{collected(map[string]any{})})
	if remediated[0].Status != "confirmed" || remediated[0].Summary != item.Remediation || remediated[0].Title != item.Title {
		t.Fatalf("remediated = %+v", remediated[0])
	}
	both := item
	both.Pass = []Predicate{{Field: "name", Op: "exists"}}
	both.Fail = []Predicate{{Field: "name", Op: "exists"}}
	conflict := EvaluateConfigs([]ConfigRule{both}, []Fact{collected(map[string]any{"name": "Fedora"})})
	if conflict[0].Status != "conflict" || conflict[0].Matched["pass"] != true || conflict[0].Matched["fail"] != true {
		t.Fatalf("conflict = %+v", conflict[0])
	}
	neither := item
	neither.Pass = []Predicate{{Field: "name", Op: "equals", Value: "Fedora"}}
	neither.Fail = []Predicate{{Field: "name", Op: "equals", Value: "Debian"}}
	unknown := EvaluateConfigs([]ConfigRule{neither}, []Fact{collected(map[string]any{"name": "Ubuntu"})})
	if unknown[0].Status != "unknown" || unknown[0].Unmatched["pass"] != false || unknown[0].Unmatched["fail"] != false {
		t.Fatalf("unknown = %+v", unknown[0])
	}
	denied := EvaluateConfigs([]ConfigRule{item}, []Fact{{
		Type: "host_inventory", Subject: "local:collect_os_info", ResultStatus: "observed",
		Value: map[string]any{"collection_status": "permission_denied"},
	}})
	if denied[0].Status != "insufficient_evidence" {
		t.Fatalf("denied = %+v", denied[0])
	}
	empty := EvaluateConfigs([]ConfigRule{{
		Key: "no_telnet", Operation: "collect_packages", RequiredObservationType: "host_inventory", Severity: "medium",
		Pass: []Predicate{{Field: "packages", Op: "none", Match: []Condition{{Field: "name", Op: "equals", Value: "telnet"}}}},
		Fail: []Predicate{{Field: "packages", Op: "any", Match: []Condition{{Field: "name", Op: "equals", Value: "telnet"}}}},
	}}, []Fact{{
		Type: "host_inventory", Subject: "local:collect_packages", ResultStatus: "empty",
		Value: map[string]any{"collection_status": "empty", "packages": []map[string]any{}},
	}})
	if empty[0].Status != "not_vulnerable" || empty[0].Matched["pass"] != true {
		t.Fatalf("empty = %+v", empty[0])
	}
	installed := EvaluateConfigs([]ConfigRule{{
		Key: "no_telnet", Operation: "collect_packages", RequiredObservationType: "host_inventory", Severity: "medium",
		Pass: []Predicate{{Field: "packages", Op: "none", Match: []Condition{{Field: "name", Op: "equals", Value: "telnet"}}}},
		Fail: []Predicate{{Field: "packages", Op: "any", Match: []Condition{{Field: "name", Op: "equals", Value: "telnet"}}}},
	}}, []Fact{{
		Type: "host_inventory", Subject: "local:collect_packages", ResultStatus: "observed",
		Value: map[string]any{"collection_status": "collected", "packages": []any{map[string]any{"name": "telnet", "version": "1"}}},
	}})
	if installed[0].Status != "confirmed" || installed[0].Matched["fail"] != true {
		t.Fatalf("installed = %+v", installed[0])
	}
	sockets := EvaluateConfigs([]ConfigRule{{
		Key: "no_ssh_socket", Operation: "collect_listening_sockets", RequiredObservationType: "host_inventory", Severity: "low",
		Pass: []Predicate{{Field: "sockets", Op: "count", Compare: "eq", Number: 1, Match: []Condition{{Field: "port", Op: "equals", Value: "22"}}}},
	}}, []Fact{{
		Type: "host_inventory", Subject: "local:collect_listening_sockets", ResultStatus: "observed",
		Value: map[string]any{"collection_status": "collected", "sockets": []any{map[string]any{"port": float64(22), "transport": "tcp"}}},
	}})
	if sockets[0].Status != "not_vulnerable" {
		t.Fatalf("sockets = %+v", sockets[0])
	}
}

func TestApplicabilityDoesNotTurnMissingFactsIntoPass(t *testing.T) {
	item := ConfigRule{
		Key: "fedora_name", Operation: "collect_os_info", RequiredObservationType: "host_inventory", Severity: "low",
		Applicability: []Predicate{{Observation: "collect_os_info", Field: "id", Op: "equals", Value: "fedora"}},
		Pass:          []Predicate{{Field: "name", Op: "exists"}},
	}
	os := Fact{
		Type: "host_inventory", Subject: "local:collect_os_info", ResultStatus: "observed",
		Value: map[string]any{"collection_status": "collected", "id": "rhel", "name": "Red Hat Enterprise Linux"},
	}
	miss := EvaluateConfigs([]ConfigRule{item}, []Fact{os})
	if miss[0].Status != "not_applicable" || miss[0].Unmatched["field"] != "id" {
		t.Fatalf("miss = %+v", miss[0])
	}
	item.Applicability = []Predicate{{Observation: "collect_packages", Field: "packages", Op: "exists"}}
	unavailable := EvaluateConfigs([]ConfigRule{item}, []Fact{os})
	if unavailable[0].Status != "insufficient_evidence" || unavailable[0].Unmatched["collection_status"] != "missing" {
		t.Fatalf("unavailable = %+v", unavailable[0])
	}
	denied := EvaluateConfigs([]ConfigRule{item}, []Fact{os, {
		Type: "host_inventory", Subject: "local:collect_packages", ResultStatus: "observed",
		Value: map[string]any{"collection_status": "permission_denied"},
	}})
	if denied[0].Status != "insufficient_evidence" || denied[0].Unmatched["collection_status"] != "permission_denied" {
		t.Fatalf("denied = %+v", denied[0])
	}
	unsupported := EvaluateConfigs([]ConfigRule{item}, []Fact{{
		Type: "host_inventory", Subject: "local:collect_os_info", ResultStatus: "unsupported",
		Value: map[string]any{"collection_status": "unsupported"},
	}})
	if unsupported[0].Status != "not_applicable" || unsupported[0].Summary != "platform unsupported" {
		t.Fatalf("unsupported = %+v", unsupported[0])
	}
}

func TestFrozenConfigsKeepsDeprecatedPacks(t *testing.T) {
	item := ConfigRule{Key: "packages_present", Version: "config:abc", Operation: "collect_packages", Pass: []Predicate{{Field: "packages", Op: "exists"}}}
	packs := []Pack{{Type: "config", Version: "config:abc", Status: "deprecated", Source: "config", Configs: []ConfigRule{item}}}
	if len(Configs(packs, "config:abc")) != 0 {
		t.Fatal("deprecated pack was selected as published")
	}
	if got := FrozenConfigs(packs, "config:abc"); len(got) != 1 || got[0].Key != "packages_present" {
		t.Fatalf("frozen = %+v", got)
	}
	packs[0].Status = "validated"
	if len(FrozenConfigs(packs, "config:abc")) != 0 {
		t.Fatal("unpublished pack was frozen")
	}
}
