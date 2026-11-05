package udp

import (
	"context"
	"testing"

	"github.com/zodirc/Vesper/pkg/probesdk"
)

func validSpec() Spec {
	return Spec{
		Name: "dns", Version: DNSVersion, Request: []byte{0x01}, MaxRequestBytes: 4, MaxResponseBytes: 4, Attempts: 1,
		ResponseMatches: func([]byte) bool { return false }, TimeoutConclusion: "no_response",
	}
}

func TestEmptyRequestDoesNotSend(t *testing.T) {
	called := false
	outcome, err := Run(context.Background(), Spec{}, func(context.Context, []byte) ([]byte, error) {
		called = true
		return []byte{1}, nil
	})
	if err == nil || called {
		t.Fatalf("outcome = %+v called = %v err = %v", outcome, called, err)
	}
	if outcome.Outcome.State != "unknown" || outcome.Outcome.Status != "not_scanned" {
		t.Fatalf("outcome = %+v", outcome.Outcome)
	}
}

func TestTimeoutStaysNoResponseUntilProbeDefinesStrongerConclusion(t *testing.T) {
	outcome, err := Evaluate(validSpec(), nil, false, true)
	if err != nil {
		t.Fatal(err)
	}
	if outcome.State != "no_response" {
		t.Fatalf("state = %s", outcome.State)
	}
}

func TestTimeoutCannotConcludeClosed(t *testing.T) {
	spec := validSpec()
	spec.TimeoutConclusion = "closed"
	called := false
	outcome, err := Run(context.Background(), spec, func(context.Context, []byte) ([]byte, error) {
		called = true
		return nil, nil
	})
	if err == nil || called || outcome.Outcome.State != "unknown" {
		t.Fatalf("outcome = %+v called = %v err = %v", outcome.Outcome, called, err)
	}
}

func TestICMPCannotConcludeOpen(t *testing.T) {
	spec := validSpec()
	spec.ICMPUnreachableMeans = "open"
	called := false
	_, err := Run(context.Background(), spec, func(context.Context, []byte) ([]byte, error) {
		called = true
		return nil, nil
	})
	if err == nil || called {
		t.Fatalf("called = %v err = %v", called, err)
	}
}

func TestRunRetriesOnlyTimeoutAndStopsOnICMP(t *testing.T) {
	spec := validSpec()
	spec.Attempts = 2
	calls := 0
	result, err := Run(context.Background(), spec, func(context.Context, []byte) ([]byte, error) {
		calls++
		return nil, &probesdk.Error{Class: probesdk.ClassTimeout, Message: "timeout"}
	})
	if err != nil || calls != 2 || result.Outcome.State != "no_response" || result.Rounds != 2 {
		t.Fatalf("result = %+v calls = %d err = %v", result.Outcome, calls, err)
	}
	calls = 0
	spec.ICMPUnreachableMeans = "closed"
	result, err = Run(context.Background(), spec, func(context.Context, []byte) ([]byte, error) {
		calls++
		return nil, &probesdk.Error{Class: probesdk.ClassICMPUnreachable, Message: "icmp"}
	})
	if err != nil || calls != 1 || result.Outcome.State != "closed" || result.Rounds != 1 {
		t.Fatalf("result = %+v calls = %d err = %v", result.Outcome, calls, err)
	}
}

func TestUnregisteredProbeDoesNotSend(t *testing.T) {
	called := false
	result, err := Execute(context.Background(), "snmp", func(context.Context, []byte) ([]byte, error) {
		called = true
		return []byte{1}, nil
	}, "")
	if err != nil || called || result.Outcome.State != "unknown" || result.Outcome.Status != "not_scanned" {
		t.Fatalf("result = %+v called = %v err = %v", result.Outcome, called, err)
	}
}

func TestICMPPortUnreachableUsesTheProbeConclusion(t *testing.T) {
	spec := validSpec()
	spec.ICMPUnreachableMeans = "closed"
	outcome, err := Evaluate(spec, nil, true, false)
	if err != nil || outcome.State != "closed" || outcome.Status != "observed" {
		t.Fatalf("outcome = %+v err = %v", outcome, err)
	}
	spec.ICMPUnreachableMeans = ""
	outcome, err = Evaluate(spec, nil, true, false)
	if err != nil || outcome.State != "unknown" || outcome.Status != "unreachable" {
		t.Fatalf("outcome = %+v err = %v", outcome, err)
	}
}
