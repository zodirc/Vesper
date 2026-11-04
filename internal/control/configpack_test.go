package control

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/zodirc/Vesper/internal/id"
	"github.com/zodirc/Vesper/internal/scope"
)

const configDocument = `rules:
  - id: not_this_os
    title: Operating system is not the marker
    severity: low
    operation: collect_os_info
    applies_when:
      - observation: collect_os_info
        field: id
        op: equals
        value: vesper-no-such-os
    pass:
      - field: name
        op: exists
  - id: name_is_marker
    title: Operating system name is the marker
    severity: low
    operation: collect_os_info
    pass:
      - field: name
        op: equals
        value: vesper-no-such-name
`

const configVerificationDocument = `rules:
  - id: firewall_when_packages_exist
    title: Firewall ruleset exists when packages were collected
    severity: medium
    operation: collect_firewall_config
    applies_when:
      - observation: collect_packages
        field: packages
        op: exists
    pass:
      - field: ruleset
        op: exists
    remediation: Keep a firewall ruleset.
`

func TestConfigPackStaysUnusedUntilPublishedAndSurvivesDeprecation(t *testing.T) {
	now := time.Date(2026, 11, 4, 10, 0, 0, 0, time.UTC)
	svc, err := New(t.TempDir(), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	imported, err := svc.ImportConfigPack(context.Background(), []byte(configDocument))
	if err != nil {
		t.Fatal(err)
	}
	if imported.Status != "validated" || imported.Rules != 2 || imported.LicenseRecorded {
		t.Fatalf("imported = %+v", imported)
	}
	again, err := svc.ImportConfigPack(context.Background(), []byte(configDocument))
	if err != nil || again.ID != imported.ID || len(svc.ConfigPacks()) != 1 {
		t.Fatalf("again = %+v packs = %+v err = %v", again, svc.ConfigPacks(), err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 64)
				_, _ = c.Read(buf)
				_, _ = io.WriteString(c, "ok")
			}(conn)
		}
	}()
	port := listener.Addr().(*net.TCPAddr).Port
	grantID := approveConfigGrant(t, svc, port, now)
	unpublished, err := svc.CreateScan(context.Background(), ScanInput{Name: "config", Target: "127.0.0.1", Type: "ip", Ports: []int{port}, GrantID: grantID})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(unpublished.Plan), imported.Version) {
		t.Fatalf("unpublished pack was frozen: %s", unpublished.Plan)
	}
	if _, err := svc.PublishConfigPack(context.Background(), imported.ID); err != nil {
		t.Fatal(err)
	}
	frozen, err := svc.CreateScan(context.Background(), ScanInput{Name: "config", Target: "127.0.0.1", Type: "ip", Ports: []int{port}, GrantID: grantID})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(frozen.Plan), imported.Version) || frozen.RulePackVersion != "builtin-1" {
		t.Fatalf("plan = %s version = %s", frozen.Plan, frozen.RulePackVersion)
	}
	if _, err := svc.DeprecateConfigPack(context.Background(), imported.ID); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 40; i++ {
		worked, err := svc.ExecuteAvailable(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if !worked {
			break
		}
	}
	for _, runID := range []id.ID{unpublished.ID, frozen.ID} {
		got, err := svc.Run(runID)
		if err != nil {
			t.Fatal(err)
		}
		if got.Status != "completed" && got.Status != "completed_with_errors" {
			t.Fatalf("status = %s failure=%s", got.Status, got.FailureSummary)
		}
	}
	raw, err := os.ReadFile("/etc/machine-id")
	if err != nil || strings.TrimSpace(string(raw)) == "" {
		t.Skip("machine-id is unavailable, so configuration evaluation is not linked to an asset")
	}
	var saw int
	var applicability string
	for _, item := range svc.detections {
		if item.VulnerabilityID != "not_this_os" {
			continue
		}
		saw++
		applicability = item.Summary
		if item.RuleVersion != imported.Version || item.ResultStatus != "not_applicable" || item.Severity != "low" {
			t.Fatalf("detection = %+v", item)
		}
		if strings.Contains(string(item.Matched), `"pass_field"`) {
			t.Fatalf("matched = %s", item.Matched)
		}
	}
	if saw != 1 {
		t.Fatalf("detections = %+v", svc.detections)
	}
	for _, item := range svc.Findings() {
		if item.VulnerabilityID == "not_this_os" {
			t.Fatalf("not applicable became a finding: %+v", item)
		}
	}
	if applicability == "applicability did not match" {
		var confirmed bool
		for _, item := range svc.Findings() {
			if item.VulnerabilityID == "name_is_marker" && item.Title == "Operating system name is the marker" && item.FindingType == "misconfiguration" && item.Severity == "low" {
				confirmed = true
			}
		}
		if !confirmed {
			t.Fatalf("findings = %+v", svc.Findings())
		}
	}
	var sawBuiltin bool
	for _, item := range svc.detections {
		if item.VulnerabilityID == "host_identity_present" && item.RuleVersion == "builtin-1" && strings.Contains(string(item.Matched), `"pass_field":"name"`) {
			sawBuiltin = true
		}
	}
	if !sawBuiltin {
		t.Fatalf("detections = %+v", svc.detections)
	}
	later, err := svc.CreateScan(context.Background(), ScanInput{Name: "config", Target: "127.0.0.1", Type: "ip", Ports: []int{port}, GrantID: grantID})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(later.Plan), "config:") {
		t.Fatalf("deprecated pack was frozen: %s", later.Plan)
	}
}

func TestConfigVerificationCollectsApplicabilityOperations(t *testing.T) {
	now := time.Date(2026, 11, 4, 11, 0, 0, 0, time.UTC)
	svc, err := New(t.TempDir(), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	imported, err := svc.ImportConfigPack(context.Background(), []byte(configVerificationDocument))
	if err != nil {
		t.Fatal(err)
	}
	var ruleID id.ID
	for _, pack := range svc.packs {
		if pack.ID == imported.ID {
			ruleID = pack.Configs[0].ID
		}
	}
	findingID := id.MustNew()
	assetID := id.MustNew()
	svc.findings[assetID.String()+"|firewall_when_packages_exist"] = &Finding{
		ID: findingID, FindingKey: assetID.String() + "|firewall_when_packages_exist", FindingType: "misconfiguration",
		AssetID: assetID, RuleID: ruleID, VulnerabilityID: "firewall_when_packages_exist", Title: "Firewall ruleset exists when packages were collected",
		Severity: "medium", Status: "open", FirstSeenAt: now, LastSeenAt: now,
	}
	svc.occurrences = append(svc.occurrences, Occurrence{
		ID: id.MustNew(), FindingID: findingID, AssessmentRunID: id.MustNew(), DetectionID: id.MustNew(),
		ObservedAt: now, Severity: "medium", ConditionDigest: "present",
	})
	actor := id.MustNew()
	grant, err := svc.CreateGrant(GrantInput{
		Name: "collect", SubjectType: "user",
		Selectors:  []SelectorInput{{Kind: "ip", Value: "127.0.0.1"}},
		Transports: []string{"tcp"}, Ports: []scope.PortRange{{Start: 1, End: 1}},
		Operations:          []string{scope.OpConfigCheck},
		ObservationPointIDs: []id.ID{svc.ObservationPointID()}, ValidFrom: now.Add(-time.Minute),
		MaxTargets: 2, MaxAddresses: 2, MaxConnections: 2, MaxRequests: 2, MaxConcurrency: 1,
		MaxRatePerSecond: 1000, MaxRuntimeSeconds: 60, MaxEvidenceBytes: 1000,
	}, actor)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.ApproveGrant(grant.ID, actor); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreateVerification(context.Background(), findingID, grant.ID); !errors.Is(err, ErrVerificationUnavailable) {
		t.Fatalf("unpublished verification err = %v", err)
	}
	if _, err := svc.PublishConfigPack(context.Background(), imported.ID); err != nil {
		t.Fatal(err)
	}
	run, err := svc.CreateVerification(context.Background(), findingID, grant.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(run.Plan), imported.Version) {
		t.Fatalf("plan = %s", run.Plan)
	}
	_, units, err := svc.tasks.Snapshot(run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(units) != 1 || units[0].UnitType != "host_collect" {
		t.Fatalf("units = %+v", units)
	}
	var payload struct {
		Operations []string `json:"operations"`
	}
	if err := json.Unmarshal(units[0].Input, &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Operations) != 2 || payload.Operations[0] != "collect_firewall_config" || payload.Operations[1] != "collect_packages" {
		t.Fatalf("operations = %+v", payload.Operations)
	}
}

func approveConfigGrant(t *testing.T, svc *Service, port int, now time.Time) id.ID {
	t.Helper()
	actor := id.MustNew()
	grant, err := svc.CreateGrant(GrantInput{
		Name: "config", SubjectType: "user",
		Selectors:  []SelectorInput{{Kind: "ip", Value: "127.0.0.1"}},
		Transports: []string{"tcp"}, Ports: []scope.PortRange{{Start: port, End: port}},
		Operations:          []string{scope.OpDiscovery, scope.OpConnect, scope.OpConfigCheck},
		ObservationPointIDs: []id.ID{svc.ObservationPointID()}, ValidFrom: now.Add(-time.Minute),
		MaxTargets: 4, MaxAddresses: 4, MaxConnections: 50, MaxRequests: 50, MaxConcurrency: 4,
		MaxRatePerSecond: 1000, MaxRuntimeSeconds: 60, MaxEvidenceBytes: 1 << 20,
	}, actor)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.ApproveGrant(grant.ID, actor); err != nil {
		t.Fatal(err)
	}
	return grant.ID
}
