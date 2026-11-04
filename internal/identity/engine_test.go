package identity

import (
	"testing"
	"time"

	"github.com/zodirc/Vesper/internal/id"
	"github.com/zodirc/Vesper/internal/rule"
)

func TestUniqueAliasNormalizesTheVersionAndKeepsTheRawText(t *testing.T) {
	packs, err := rule.Builtin(time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	productID := id.MustNew()
	found := Identify(id.MustNew(), id.MustNew(), []ObservationView{
		{ID: id.MustNew(), Type: "protocol_response", Value: map[string]any{"protocol": "http", "headers": map[string]any{"server": "nginx/01.24.0"}}},
	}, rule.Fingerprints(packs, rule.FingerprintVersion), rule.FingerprintVersion, []Alias{
		{ProductID: productID, Ecosystem: "generic", Value: "nginx"},
		{ProductID: productID, Ecosystem: "generic", Value: "Nginx"},
	}, time.Now().UTC())
	if len(found) != 1 || found[0].RawProductName != "nginx" || found[0].RawVersion != "01.24.0" || found[0].NormalizedVersion != "1.24.0" || found[0].IdentityStatus != "candidate" || found[0].ProductIdentityID == nil || *found[0].ProductIdentityID != productID {
		t.Fatalf("hypothesis = %+v", found)
	}
}

func TestMissingOrAmbiguousAliasDoesNotBindAProduct(t *testing.T) {
	packs, err := rule.Builtin(time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	observations := []ObservationView{{ID: id.MustNew(), Type: "protocol_response", Value: map[string]any{"protocol": "http", "headers": map[string]any{"server": "nginx/1.24.0"}}}}
	rules := rule.Fingerprints(packs, rule.FingerprintVersion)
	missing := Identify(id.MustNew(), id.MustNew(), observations, rules, rule.FingerprintVersion, nil, time.Now().UTC())
	if len(missing) != 1 || missing[0].IdentityStatus != "unknown" || missing[0].ProductIdentityID != nil || missing[0].RawProductName != "nginx" || missing[0].NormalizedVersion != "" {
		t.Fatalf("missing = %+v", missing)
	}
	ambiguous := Identify(id.MustNew(), id.MustNew(), observations, rules, rule.FingerprintVersion, []Alias{
		{ProductID: id.MustNew(), Ecosystem: "generic", Value: "nginx"},
		{ProductID: id.MustNew(), Ecosystem: "deb", Value: "NGINX"},
	}, time.Now().UTC())
	if len(ambiguous) != 1 || ambiguous[0].IdentityStatus != "unknown" || ambiguous[0].ProductIdentityID != nil || ambiguous[0].RawVersion != "1.24.0" || ambiguous[0].NormalizedVersion != "" {
		t.Fatalf("ambiguous = %+v", ambiguous)
	}
}

func TestDistinctServicesDoNotConflict(t *testing.T) {
	packs, err := rule.Builtin(time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	found := Identify(id.MustNew(), id.MustNew(), []ObservationView{
		{ID: id.MustNew(), Type: "protocol_response", Value: map[string]any{"protocol": "http", "headers": map[string]any{"server": "nginx/1.24.0"}}},
		{ID: id.MustNew(), Type: "protocol_response", Value: map[string]any{"protocol": "ssh", "banner": "SSH-2.0-OpenSSH_9.0"}},
	}, rule.Fingerprints(packs, rule.FingerprintVersion), rule.FingerprintVersion, nil, time.Now().UTC())
	if len(found) != 2 {
		t.Fatalf("hypotheses = %+v", found)
	}
	for _, item := range found {
		if item.IdentityStatus == "conflict" || len(item.ContradictingObservationIDs) != 0 {
			t.Fatalf("hypothesis = %+v", item)
		}
	}
}

func TestSameServiceProductDisagreementConflicts(t *testing.T) {
	packs, err := rule.Builtin(time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	nginxID := id.MustNew()
	apacheID := id.MustNew()
	found := Identify(id.MustNew(), id.MustNew(), []ObservationView{
		{ID: nginxID, Type: "protocol_response", Value: map[string]any{"protocol": "http", "headers": map[string]any{"server": "nginx/1.24.0"}}},
		{ID: apacheID, Type: "protocol_response", Value: map[string]any{"protocol": "http", "headers": map[string]any{"server": "Apache/2.4.62"}}},
	}, rule.Fingerprints(packs, rule.FingerprintVersion), rule.FingerprintVersion, nil, time.Now().UTC())
	if len(found) != 2 {
		t.Fatalf("hypotheses = %+v", found)
	}
	for _, item := range found {
		if item.IdentityStatus != "conflict" || len(item.ContradictingObservationIDs) != 1 {
			t.Fatalf("hypothesis = %+v", item)
		}
		other := item.ContradictingObservationIDs[0]
		if item.RawProductName == "nginx" && other != apacheID {
			t.Fatalf("nginx contradiction = %s", other)
		}
		if item.RawProductName == "Apache" && other != nginxID {
			t.Fatalf("apache contradiction = %s", other)
		}
	}
}

func TestAgreeingObservationsMergeAndProtocolEvidenceDoesNotEraseTheProduct(t *testing.T) {
	packs, err := rule.Builtin(time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	first := id.MustNew()
	second := id.MustNew()
	protocolOnly := id.MustNew()
	found := Identify(id.MustNew(), id.MustNew(), []ObservationView{
		{ID: first, Type: "protocol_response", Value: map[string]any{"protocol": "http", "headers": map[string]any{"server": "nginx/1.24.0"}}},
		{ID: second, Type: "protocol_response", Value: map[string]any{"protocol": "http", "headers": map[string]any{"server": "nginx/1.24.0"}}},
		{ID: protocolOnly, Type: "protocol_response", Value: map[string]any{"protocol": "http"}},
	}, rule.Fingerprints(packs, rule.FingerprintVersion), rule.FingerprintVersion, nil, time.Now().UTC())
	if len(found) != 1 || found[0].RawProductName != "nginx" || found[0].IdentityStatus == "conflict" || len(found[0].SupportingObservationIDs) != 3 {
		t.Fatalf("hypothesis = %+v", found)
	}
}

func TestExclusionContradictsTheSameService(t *testing.T) {
	ruleID := id.MustNew()
	negativeID := id.MustNew()
	observationID := id.MustNew()
	rules := []rule.FingerprintRule{{
		ID: ruleID, Key: "http", Version: "test", Priority: 10, TargetProtocol: "http", ServiceType: "http",
		Conditions:        []rule.Condition{{Field: "protocol", Op: "equals", Value: "http"}},
		Extractors:        []rule.Extractor{{Target: "product", Source: "headers.server", Method: "server_token"}},
		ConfidenceMatched: "0.8500", ConfidenceEmpty: "0.7000",
	}, {
		ID: negativeID, Key: "http-proxy", Version: "test", Priority: 20, TargetProtocol: "http", ServiceType: "http",
		Conditions: []rule.Condition{{Field: "protocol", Op: "equals", Value: "http"}},
		Negative:   []rule.Condition{{Field: "headers.server", Op: "contains", Value: "proxy"}},
	}}
	found := Identify(id.MustNew(), id.MustNew(), []ObservationView{
		{ID: observationID, Type: "protocol_response", Value: map[string]any{"protocol": "http", "headers": map[string]any{"server": "nginx/1.24.0 proxy"}}},
	}, rules, "test", nil, time.Now().UTC())
	if len(found) != 1 || found[0].IdentityStatus != "conflict" || found[0].RawProductName != "nginx" || len(found[0].ContradictingObservationIDs) != 1 || found[0].ContradictingObservationIDs[0] != observationID {
		t.Fatalf("hypothesis = %+v", found)
	}
	var sawNegative bool
	for _, item := range found[0].FingerprintRuleIDs {
		if item == negativeID {
			sawNegative = true
		}
	}
	if !sawNegative {
		t.Fatalf("rules = %+v", found[0].FingerprintRuleIDs)
	}
}

func TestEvidenceTypeDoesNotMatchAnotherObservation(t *testing.T) {
	rules := []rule.FingerprintRule{{
		ID: id.MustNew(), Key: "cert", Version: "test", Priority: 10, TargetProtocol: "tls", ServiceType: "tls",
		EvidenceTypes: []string{"tls_certificate"},
		Conditions:    []rule.Condition{{Field: "protocol", Op: "equals", Value: "tls"}},
	}}
	found := Identify(id.MustNew(), id.MustNew(), []ObservationView{
		{ID: id.MustNew(), Type: "protocol_response", Value: map[string]any{"protocol": "tls"}},
	}, rules, "test", nil, time.Now().UTC())
	if len(found) != 0 {
		t.Fatalf("hypotheses = %+v", found)
	}
}

func TestVersionDisagreementConflicts(t *testing.T) {
	packs, err := rule.Builtin(time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	found := Identify(id.MustNew(), id.MustNew(), []ObservationView{
		{ID: id.MustNew(), Type: "protocol_response", Value: map[string]any{"protocol": "http", "headers": map[string]any{"server": "nginx/1.24.0"}}},
		{ID: id.MustNew(), Type: "protocol_response", Value: map[string]any{"protocol": "http", "headers": map[string]any{"server": "nginx/1.25.3"}}},
	}, rule.Fingerprints(packs, rule.FingerprintVersion), rule.FingerprintVersion, nil, time.Now().UTC())
	if len(found) != 2 {
		t.Fatalf("hypotheses = %+v", found)
	}
	for _, item := range found {
		if item.RawProductName != "nginx" || item.IdentityStatus != "conflict" || len(item.ContradictingObservationIDs) != 1 {
			t.Fatalf("hypothesis = %+v", item)
		}
	}
}

func TestConflictingProductsDoNotAbsorbProtocolEvidence(t *testing.T) {
	packs, err := rule.Builtin(time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	found := Identify(id.MustNew(), id.MustNew(), []ObservationView{
		{ID: id.MustNew(), Type: "protocol_response", Value: map[string]any{"protocol": "http", "headers": map[string]any{"server": "nginx/1.24.0"}}},
		{ID: id.MustNew(), Type: "protocol_response", Value: map[string]any{"protocol": "http", "headers": map[string]any{"server": "Apache/2.4.62"}}},
		{ID: id.MustNew(), Type: "protocol_response", Value: map[string]any{"protocol": "http"}},
	}, rule.Fingerprints(packs, rule.FingerprintVersion), rule.FingerprintVersion, nil, time.Now().UTC())
	if len(found) != 3 {
		t.Fatalf("hypotheses = %+v", found)
	}
	var protocolOnly bool
	for _, item := range found {
		if item.RawProductName == "" {
			protocolOnly = item.IdentityStatus == "unknown" && len(item.ContradictingObservationIDs) == 0
		}
	}
	if !protocolOnly {
		t.Fatalf("hypotheses = %+v", found)
	}
}

func TestExclusionAloneDoesNotCreateAService(t *testing.T) {
	rules := []rule.FingerprintRule{{
		ID: id.MustNew(), Key: "http-proxy", Version: "test", Priority: 10, TargetProtocol: "http", ServiceType: "http",
		Conditions: []rule.Condition{{Field: "protocol", Op: "equals", Value: "http"}},
		Negative:   []rule.Condition{{Field: "headers.server", Op: "contains", Value: "proxy"}},
	}}
	found := Identify(id.MustNew(), id.MustNew(), []ObservationView{
		{ID: id.MustNew(), Type: "protocol_response", Value: map[string]any{"protocol": "http", "headers": map[string]any{"server": "nginx/1.24.0 proxy"}}},
	}, rules, "test", nil, time.Now().UTC())
	if len(found) != 0 {
		t.Fatalf("hypotheses = %+v", found)
	}
}

func TestHigherDeclaredConfidenceSurvivesTheMerge(t *testing.T) {
	low := id.MustNew()
	high := id.MustNew()
	extractor := []rule.Extractor{{Target: "product", Source: "headers.server", Method: "server_token"}}
	conditions := []rule.Condition{{Field: "protocol", Op: "equals", Value: "http"}}
	rules := []rule.FingerprintRule{
		{ID: low, Key: "low", Version: "test", Priority: 30, TargetProtocol: "http", ServiceType: "http", Conditions: conditions, Extractors: extractor, ConfidenceMatched: "0.4000", ConfidenceEmpty: "0.1000"},
		{ID: high, Key: "high", Version: "test", Priority: 10, TargetProtocol: "http", ServiceType: "http", Conditions: conditions, Extractors: extractor, ConfidenceMatched: "0.9000", ConfidenceEmpty: "0.1000"},
	}
	found := Identify(id.MustNew(), id.MustNew(), []ObservationView{
		{ID: id.MustNew(), Type: "protocol_response", Value: map[string]any{"protocol": "http", "headers": map[string]any{"server": "nginx/1.24.0"}}},
	}, rules, "test", nil, time.Now().UTC())
	if len(found) != 1 || found[0].Confidence != "0.9000" || found[0].RawProductName != "nginx" || len(found[0].FingerprintRuleIDs) != 2 {
		t.Fatalf("hypothesis = %+v", found)
	}
}
