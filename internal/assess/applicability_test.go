package assess

import "testing"

func TestGenericRangeUsesNumericComponents(t *testing.T) {
	statement := Statement{Ecosystem: "generic", Ranges: []Range{{Ecosystem: "generic", Start: "1.0", StartInclusive: true, End: "1.9", EndInclusive: true}}}
	if got := Judge("generic", "1.10", statement); got != NotAffected {
		t.Fatalf("1.10 judged %s", got)
	}
	if got := Judge("generic", "1.8", statement); got != Affected {
		t.Fatalf("1.8 judged %s", got)
	}
}

func TestPackageEcosystemsDoNotUseStringOrder(t *testing.T) {
	statement := Statement{Ecosystem: "deb", KEV: true, Ranges: []Range{{Ecosystem: "deb", Start: "1.0", StartInclusive: true, End: "2.0", EndInclusive: true}}}
	if got := Judge("deb", "1.1", statement); got != InsufficientEvidence {
		t.Fatalf("deb judged %s", got)
	}
}

func TestMissingVersionIsInsufficient(t *testing.T) {
	statement := Statement{Ecosystem: "generic", Ranges: []Range{{Start: "1", StartInclusive: true}}}
	if got := Judge("generic", "", statement); got != InsufficientEvidence {
		t.Fatalf("judged %s", got)
	}
}
