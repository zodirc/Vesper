package control

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/zodirc/Vesper/internal/id"
)

func TestDispositionProjectsStatusWithoutRewritingFacts(t *testing.T) {
	current := time.Date(2026, 11, 4, 4, 0, 0, 0, time.UTC)
	svc, err := New(t.TempDir(), func() time.Time { return current })
	if err != nil {
		t.Fatal(err)
	}
	actor := id.MustNew()
	findingID, endpointID, evidenceID, confirmedID := seedOpenFinding(svc, current)
	if _, err := svc.AddDisposition(findingID, actor, DispositionInput{Type: DispositionAcceptRisk, Reason: "  owned  "}); err != nil {
		t.Fatal(err)
	}
	findings := svc.Findings()
	if len(findings) != 1 || findings[0].Status != "accepted" || findings[0].ResolvedAt != nil {
		t.Fatalf("findings = %+v", findings)
	}
	if len(svc.occurrences) != 1 || svc.detections[0].ResultStatus != "confirmed" {
		t.Fatal("accept rewrote a detection fact or occurrence")
	}
	current = current.Add(time.Minute)
	svc.mergeFinding(endpointID, id.ID{}, "CVE-2026-0001", id.MustNew(), id.MustNew(), "1.24.0", "vulnerability", "high", []id.ID{evidenceID}, id.ID{}, id.ID{})
	findings = svc.Findings()
	if findings[0].Status != "accepted" || len(svc.occurrences) != 2 {
		t.Fatalf("status = %s occurrences = %d", findings[0].Status, len(svc.occurrences))
	}

	until := current.Add(time.Hour)
	if _, err := svc.AddDisposition(findingID, actor, DispositionInput{Type: DispositionSuppress, Reason: "maintenance", ValidUntil: &until}); err != nil {
		t.Fatal(err)
	}
	if svc.Findings()[0].Status != "suppressed" {
		t.Fatalf("status = %s", svc.Findings()[0].Status)
	}
	current = until
	if svc.Findings()[0].Status != "accepted" {
		t.Fatalf("expired suppress status = %s", svc.Findings()[0].Status)
	}

	if _, err := svc.AddDisposition(findingID, id.ID{}, DispositionInput{Type: DispositionReopen, Reason: "review"}); err == nil {
		t.Fatal("empty actor was accepted")
	}
	if _, err := svc.AddDisposition(findingID, actor, DispositionInput{Type: DispositionResolve, Reason: "fixed"}); !errors.Is(err, ErrDispositionVerification) || len(svc.Dispositions(findingID)) != 2 {
		t.Fatal("resolve without a detection was stored")
	}
	if _, err := svc.AddDisposition(findingID, actor, DispositionInput{Type: DispositionResolve, Reason: "fixed", DetectionID: confirmedID}); !errors.Is(err, ErrDispositionVerification) {
		t.Fatal("confirming detection closed the finding")
	}
	weak := id.MustNew()
	svc.detections = append(svc.detections, Detection{
		ID: weak, EndpointID: endpointID, VulnerabilityID: "CVE-2026-0001", ResultStatus: "not_applicable",
		EvidenceIDs: []id.ID{evidenceID}, EvaluatedAt: current.Add(time.Second),
	})
	if _, err := svc.AddDisposition(findingID, actor, DispositionInput{Type: DispositionResolve, Reason: "fixed", DetectionID: weak}); !errors.Is(err, ErrDispositionVerification) {
		t.Fatal("not_applicable closed the finding")
	}
	bare := id.MustNew()
	svc.detections = append(svc.detections, Detection{
		ID: bare, EndpointID: endpointID, VulnerabilityID: "CVE-2026-0001", ResultStatus: "not_vulnerable",
		EvaluatedAt: current.Add(2 * time.Second),
	})
	if _, err := svc.AddDisposition(findingID, actor, DispositionInput{Type: DispositionResolve, Reason: "fixed", DetectionID: bare}); !errors.Is(err, ErrDispositionVerification) {
		t.Fatal("not_vulnerable without evidence closed the finding")
	}

	current = current.Add(time.Minute)
	verified := id.MustNew()
	svc.detections = append(svc.detections, Detection{
		ID: verified, EndpointID: endpointID, VulnerabilityID: "CVE-2026-0001", ResultStatus: "not_vulnerable",
		EvidenceIDs: []id.ID{evidenceID}, EvaluatedAt: current,
	})
	current = current.Add(time.Second)
	record, err := svc.AddDisposition(findingID, actor, DispositionInput{Type: DispositionResolve, Reason: "version moved", DetectionID: verified})
	if err != nil {
		t.Fatal(err)
	}
	findings = svc.Findings()
	if findings[0].Status != "resolved" || findings[0].ResolvedAt == nil || !findings[0].ResolvedAt.Equal(record.ValidFrom) {
		t.Fatalf("findings = %+v", findings)
	}
	var scope map[string]any
	if err := json.Unmarshal(record.Scope, &scope); err != nil || scope["verification_detection_id"] != verified.String() {
		t.Fatalf("scope = %s", record.Scope)
	}
	if svc.detections[0].ResultStatus != "confirmed" || len(svc.occurrences) != 2 {
		t.Fatal("resolve rewrote a detection fact or occurrence")
	}

	current = current.Add(time.Minute)
	svc.mergeFinding(endpointID, id.ID{}, "CVE-2026-0001", id.MustNew(), id.MustNew(), "1.24.0", "vulnerability", "high", []id.ID{evidenceID}, id.ID{}, id.ID{})
	findings = svc.Findings()
	if findings[0].Status != "reopened" || findings[0].ResolvedAt != nil || len(svc.occurrences) != 3 || len(svc.Dispositions(findingID)) != 3 {
		t.Fatalf("status = %s occurrences = %d dispositions = %d", findings[0].Status, len(svc.occurrences), len(svc.Dispositions(findingID)))
	}
}

func TestDispositionRejectsBlankReasonAndUnknownFinding(t *testing.T) {
	svc, err := New(t.TempDir(), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	actor := id.MustNew()
	if _, err := svc.AddDisposition(id.MustNew(), actor, DispositionInput{Type: DispositionReopen, Reason: "back"}); !errors.Is(err, ErrFindingNotFound) {
		t.Fatalf("err = %v", err)
	}
	findingID, _, _, _ := seedOpenFinding(svc, time.Now().UTC())
	if _, err := svc.AddDisposition(findingID, actor, DispositionInput{Type: "close", Reason: "no"}); err == nil {
		t.Fatal("unknown type was accepted")
	}
	if _, err := svc.AddDisposition(findingID, actor, DispositionInput{Type: DispositionException, Reason: " "}); err == nil {
		t.Fatal("blank reason was accepted")
	}
	if _, err := svc.AddDisposition(findingID, actor, DispositionInput{Type: DispositionException, Reason: "window"}); err != nil {
		t.Fatal(err)
	}
	if findings := svc.Findings(); findings[0].Status != "accepted" || findings[0].ActiveDispositionType != DispositionException {
		t.Fatalf("exception status = %+v", findings[0])
	}
	if _, err := svc.AddDisposition(findingID, actor, DispositionInput{Type: DispositionFalsePositive, Reason: "banner mismatch"}); err != nil {
		t.Fatal(err)
	}
	if findings := svc.Findings(); findings[0].Status != "suppressed" || findings[0].ActiveDispositionType != DispositionFalsePositive {
		t.Fatalf("false positive status = %+v", findings[0])
	}
}

func TestDispositionKeepsTheTypeAndConfirmsUndisposedFindings(t *testing.T) {
	current := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	svc, err := New(t.TempDir(), func() time.Time { return current })
	if err != nil {
		t.Fatal(err)
	}
	actor := id.MustNew()
	findingID, endpointID, evidenceID, _ := seedOpenFinding(svc, current)
	findings := svc.Findings()
	if findings[0].Status != "confirmed" || !findings[0].ActiveDispositionID.IsZero() || findings[0].ActiveDispositionType != "" {
		t.Fatalf("undisposed = %+v", findings[0])
	}
	bareID := id.MustNew()
	svc.findings["bare"] = &Finding{ID: bareID, FindingKey: "bare", VulnerabilityID: "CVE-2026-0002", Status: "open", FirstSeenAt: current, LastSeenAt: current}
	if status := findingStatus(svc, bareID); status != "open" {
		t.Fatalf("occurrence-free status = %s", status)
	}
	if _, err := svc.AddDisposition(findingID, actor, DispositionInput{Type: DispositionReopen, Reason: "not closed"}); !errors.Is(err, ErrDispositionState) || len(svc.Dispositions(findingID)) != 0 {
		t.Fatalf("reopen stored: %v", err)
	}
	if _, err := svc.AddDisposition(findingID, actor, DispositionInput{Type: DispositionAcceptRisk, Reason: "owned", Scope: json.RawMessage(`[]`)}); err == nil {
		t.Fatal("array scope was accepted")
	}
	later := current.Add(time.Hour)
	if _, err := svc.AddDisposition(findingID, actor, DispositionInput{Type: DispositionAcceptRisk, Reason: "owned", ValidFrom: &later}); err != nil {
		t.Fatal(err)
	}
	got := findingByID(svc, findingID)
	if got.Status != "confirmed" || got.ActiveDispositionType != "" {
		t.Fatalf("future disposition changed status: %+v", got)
	}
	current = later
	got = findingByID(svc, findingID)
	if got.Status != "accepted" || got.ActiveDispositionType != DispositionAcceptRisk {
		t.Fatalf("accepted = %+v", got)
	}
	until := current.Add(time.Minute)
	if _, err := svc.AddDisposition(findingID, actor, DispositionInput{Type: DispositionSuppress, Reason: "window", ValidUntil: &until}); err != nil {
		t.Fatal(err)
	}
	svc.mergeFinding(endpointID, id.ID{}, "CVE-2026-0001", id.MustNew(), id.MustNew(), "1.24.0", "vulnerability", "high", []id.ID{evidenceID}, id.ID{}, id.ID{})
	got = findingByID(svc, findingID)
	if got.Status != "suppressed" || got.ActiveDispositionType != DispositionSuppress {
		t.Fatalf("suppress = %+v", got)
	}
	current = until
	got = findingByID(svc, findingID)
	if got.Status != "accepted" || got.ActiveDispositionType != DispositionAcceptRisk {
		t.Fatalf("fallback = %+v", got)
	}
	if _, err := svc.AddDisposition(findingID, actor, DispositionInput{Type: DispositionReopen, Reason: "review"}); err != nil {
		t.Fatal(err)
	}
	got = findingByID(svc, findingID)
	if got.Status != "reopened" || got.ActiveDispositionType != DispositionReopen || got.ResolvedAt != nil {
		t.Fatalf("reopened = %+v", got)
	}
	if len(svc.detections) == 0 || svc.detections[0].ResultStatus != "confirmed" {
		t.Fatal("disposition rewrote a detection")
	}
}

func findingByID(svc *Service, findingID id.ID) Finding {
	for _, item := range svc.Findings() {
		if item.ID == findingID {
			return item
		}
	}
	return Finding{}
}

func seedOpenFinding(svc *Service, when time.Time) (id.ID, id.ID, id.ID, id.ID) {
	findingID := id.MustNew()
	endpointID := id.MustNew()
	evidenceID := id.MustNew()
	detectionID := id.MustNew()
	svc.findings[endpointID.String()+"|CVE-2026-0001"] = &Finding{
		ID: findingID, FindingKey: endpointID.String() + "|CVE-2026-0001", FindingType: "vulnerability",
		EndpointID: endpointID, VulnerabilityID: "CVE-2026-0001", Title: "CVE-2026-0001", Severity: "high",
		Status: "open", FirstSeenAt: when, LastSeenAt: when,
	}
	svc.occurrences = append(svc.occurrences, Occurrence{
		ID: id.MustNew(), FindingID: findingID, AssessmentRunID: id.MustNew(), DetectionID: detectionID,
		ObservedAt: when, Severity: "high", EvidenceIDs: []id.ID{evidenceID}, ConditionDigest: "confirmed",
	})
	svc.detections = append(svc.detections, Detection{
		ID: detectionID, EndpointID: endpointID, VulnerabilityID: "CVE-2026-0001", ResultStatus: "confirmed",
		EvidenceIDs: []id.ID{evidenceID}, EvaluatedAt: when,
	})
	stored := when
	svc.evidenceRows = append(svc.evidenceRows, EvidenceRecord{ID: evidenceID, IntegrityStatus: "verified", StoredAt: &stored})
	return findingID, endpointID, evidenceID, detectionID
}
