package identity

import (
	"testing"
	"time"

	"github.com/zodirc/Vesper/internal/id"
	"github.com/zodirc/Vesper/internal/rule"
)

func TestConflictKeepsTheOtherServiceObservation(t *testing.T) {
	packs, err := rule.Builtin(time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	httpID := id.MustNew()
	sshID := id.MustNew()
	found := Identify(id.MustNew(), id.MustNew(), []ObservationView{
		{ID: httpID, Type: "protocol_response", Value: map[string]any{"protocol": "http", "headers": map[string]any{"server": "nginx/1.24.0"}}},
		{ID: sshID, Type: "protocol_response", Value: map[string]any{"protocol": "ssh", "banner": "SSH-2.0-OpenSSH_9.0"}},
	}, rule.Fingerprints(packs, rule.FingerprintVersion), rule.FingerprintVersion, nil, time.Now().UTC())
	if len(found) != 2 {
		t.Fatalf("hypotheses = %+v", found)
	}
	for _, item := range found {
		if item.IdentityStatus != "conflict" || len(item.ContradictingObservationIDs) != 1 {
			t.Fatalf("hypothesis = %+v", item)
		}
		other := item.ContradictingObservationIDs[0]
		if item.ServiceType == "http" && other != sshID {
			t.Fatalf("http contradiction = %s", other)
		}
		if item.ServiceType == "ssh" && other != httpID {
			t.Fatalf("ssh contradiction = %s", other)
		}
	}
}
