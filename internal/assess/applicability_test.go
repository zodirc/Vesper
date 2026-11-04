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
	deb := Statement{Ecosystem: "deb", KEV: true, Ranges: []Range{{Ecosystem: "deb", Start: "1.0", StartInclusive: true, End: "1.9", EndInclusive: true}}}
	if got := Judge("deb", "1.10", deb); got != NotAffected {
		t.Fatalf("deb 1.10 judged %s", got)
	}
	if got := Judge("deb", "1.1", deb); got != Affected {
		t.Fatalf("deb 1.1 judged %s", got)
	}
	if got := Judge("deb", "1.0~rc1", deb); got != NotAffected {
		t.Fatalf("deb prerelease judged %s", got)
	}
	rpm := Statement{Ecosystem: "rpm", KEV: true, Ranges: []Range{{Ecosystem: "rpm", Start: "0:1.0", StartInclusive: true, End: "0:2.0", EndInclusive: false}}}
	if got := Judge("rpm", "1:0.1", rpm); got != NotAffected {
		t.Fatalf("rpm epoch judged %s", got)
	}
	if got := Judge("rpm", "1.5-1.el9", rpm); got != Affected {
		t.Fatalf("rpm 1.5 judged %s", got)
	}
	if got := Judge("deb", "1.0 beta", deb); got != InsufficientEvidence {
		t.Fatalf("illegal deb version judged %s", got)
	}
}

func TestNormalizeVersionUsesTheEcosystemParser(t *testing.T) {
	if got, ok := NormalizeVersion("generic", "01.02.0"); !ok || got != "1.2.0" {
		t.Fatalf("generic = %q %v", got, ok)
	}
	if _, ok := NormalizeVersion("generic", "1.2.3-1"); ok {
		t.Fatal("generic accepted a package revision")
	}
	if got, ok := NormalizeVersion("deb", "1.2.3-1"); !ok || got != "0:1.2.3-1" {
		t.Fatalf("deb = %q %v", got, ok)
	}
	if got, ok := NormalizeVersion("rpm", "1:1.2.3-4"); !ok || got != "1:1.2.3-4" {
		t.Fatalf("rpm = %q %v", got, ok)
	}
	if _, ok := NormalizeVersion("npm", "1.2.3"); ok {
		t.Fatal("npm was normalized with another ecosystem")
	}
	if _, ok := NormalizeVersion("generic", ""); ok {
		t.Fatal("empty version was normalized")
	}
}

func TestMissingVersionIsInsufficient(t *testing.T) {
	statement := Statement{Ecosystem: "generic", Ranges: []Range{{Start: "1", StartInclusive: true}}}
	if got := Judge("generic", "", statement); got != InsufficientEvidence {
		t.Fatalf("judged %s", got)
	}
}
