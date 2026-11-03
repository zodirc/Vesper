package control

import (
	"encoding/json"
	"testing"

	"github.com/zodirc/Vesper/internal/id"
	"github.com/zodirc/Vesper/internal/identity"
)

func TestAssessmentSummaryCountsActualResults(t *testing.T) {
	raw, err := assessmentResultSummary(
		[]identity.Hypothesis{{IdentityStatus: "candidate"}, {IdentityStatus: "candidate"}},
		[]Detection{{ID: id.MustNew(), ResultStatus: "confirmed"}},
	)
	if err != nil {
		t.Fatal(err)
	}
	var summary struct {
		Hypotheses       int            `json:"hypotheses"`
		HypothesisStatus map[string]int `json:"hypothesis_status"`
		Detections       int            `json:"detections"`
		DetectionStatus  map[string]int `json:"detection_status"`
	}
	if err := json.Unmarshal(raw, &summary); err != nil {
		t.Fatal(err)
	}
	if summary.Hypotheses != 2 || summary.HypothesisStatus["candidate"] != 2 || summary.Detections != 1 || summary.DetectionStatus["confirmed"] != 1 {
		t.Fatalf("summary = %s", raw)
	}
}
