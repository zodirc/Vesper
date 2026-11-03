package udp

import "testing"

func TestEmptyRequestDoesNotConcludeClosed(t *testing.T) {
	outcome, err := Evaluate(Spec{}, nil, false, true)
	if err == nil {
		t.Fatal("expected error")
	}
	if outcome.State != "unknown" || outcome.Status != "unsupported" {
		t.Fatalf("outcome = %+v", outcome)
	}
}

func TestTimeoutStaysNoResponseUntilProbeDefinesStrongerConclusion(t *testing.T) {
	outcome, err := Evaluate(Spec{Name: "dns", Request: []byte{0x01}, MaxRequestBytes: 4, ResponseMatches: func([]byte) bool { return false }}, nil, false, true)
	if err != nil {
		t.Fatal(err)
	}
	if outcome.State != "no_response" {
		t.Fatalf("state = %s", outcome.State)
	}
}
