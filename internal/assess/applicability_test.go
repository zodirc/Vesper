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
	if got, ok := NormalizeVersion("npm", "v1.2.3"); !ok || got != "1.2.3" {
		t.Fatalf("npm = %q %v", got, ok)
	}
	if _, ok := NormalizeVersion("npm", "1.2"); ok {
		t.Fatal("npm accepted a short version")
	}
	if got, ok := NormalizeVersion("cargo", "1.2.3"); !ok || got != "1.2.3" {
		t.Fatalf("cargo = %q %v", got, ok)
	}
	if _, ok := NormalizeVersion("vendorx", "1.2.3"); ok {
		t.Fatal("an unnamed ecosystem was normalized")
	}
	if _, ok := NormalizeVersion("generic", ""); ok {
		t.Fatal("empty version was normalized")
	}
}

func TestSchemeSpecificRangesStayInTheirEcosystem(t *testing.T) {
	semverRange := Statement{Ecosystem: "go", Ranges: []Range{{Ecosystem: "semver", Start: "1.0.0", StartInclusive: true, End: "1.2.0", EndInclusive: false}}}
	if got := Judge("go", "v1.1.0", semverRange); got != Affected {
		t.Fatalf("go semver range judged %s", got)
	}
	if got := Judge("go", "v0.0.0-20191109021931-daa7c04131f5", semverRange); got != NotAffected {
		t.Fatalf("go pseudo-version judged %s", got)
	}
	if got := Judge("npm", "1.1.0", semverRange); got != NotApplicable {
		t.Fatalf("npm against go judged %s", got)
	}
	gitRange := Statement{Ecosystem: "go", Ranges: []Range{{Ecosystem: "git", Start: "aaa", StartInclusive: true, End: "bbb", EndInclusive: false}}}
	if got := Judge("go", "v1.1.0", gitRange); got != InsufficientEvidence {
		t.Fatalf("git range judged %s", got)
	}
	debProduct := Statement{Ecosystem: "cpe", Ranges: []Range{{Ecosystem: "generic", Start: "1.0.0", StartInclusive: true, End: "2.0.0", EndInclusive: false}}}
	if got := Judge("deb", "1.2.3-1", debProduct); got != InsufficientEvidence {
		t.Fatalf("generic range on deb judged %s", got)
	}
	order := []string{"1.0_alpha", "1.0_beta", "1.0_pre", "1.0_rc", "1.0", "1.0-r1", "1.0.1"}
	assertOrder(t, "apk", order)
	if cmp, ok := compareAlpine("1.2.3", "1.2.3_pre1"); !ok || cmp <= 0 {
		t.Fatalf("apk prerelease = %d %v", cmp, ok)
	}
	if _, ok := compareAlpine("1.0bc", "1.0"); ok {
		t.Fatal("apk accepted two letters")
	}
	if cmp, ok := compareRuby("1.0", "1.0.0"); !ok || cmp != 0 {
		t.Fatalf("ruby padding = %d %v", cmp, ok)
	}
	if cmp, ok := compareRuby("1.0.a10", "1.0.a2"); !ok || cmp <= 0 {
		t.Fatalf("ruby prerelease number = %d %v", cmp, ok)
	}
	if cmp, ok := compareRuby("1.0-java", "1.0.pre.java"); !ok || cmp != 0 {
		t.Fatalf("ruby hyphen = %d %v", cmp, ok)
	}
	if cmp, ok := compareNuGet("1", "1.0.0.0"); !ok || cmp != 0 {
		t.Fatalf("nuget padding = %d %v", cmp, ok)
	}
	if cmp, ok := compareNuGet("1.0.0-ALPHA", "1.0.0"); !ok || cmp >= 0 {
		t.Fatalf("nuget prerelease = %d %v", cmp, ok)
	}
	if cmp, ok := compareComposer("1.0.0-dev", "1.0.0-alpha"); !ok || cmp >= 0 {
		t.Fatalf("composer dev = %d %v", cmp, ok)
	}
	if cmp, ok := compareComposer("v1.0", "1.0.0"); !ok || cmp != 0 {
		t.Fatalf("composer padding = %d %v", cmp, ok)
	}
	if cmp, ok := compareComposer("1.0.0", "1.0.0-patch1"); !ok || cmp >= 0 {
		t.Fatalf("composer patch = %d %v", cmp, ok)
	}
	if _, ok := compareComposer("dev-master", "1.0.0"); ok {
		t.Fatal("composer ordered a branch name")
	}
}

func TestMissingVersionIsInsufficient(t *testing.T) {
	statement := Statement{Ecosystem: "generic", Ranges: []Range{{Start: "1", StartInclusive: true}}}
	if got := Judge("generic", "", statement); got != InsufficientEvidence {
		t.Fatalf("judged %s", got)
	}
}

func TestExactVersionDoesNotDecideOtherVersions(t *testing.T) {
	statement := Statement{Ecosystem: "generic", Ranges: []Range{{
		Ecosystem: "generic", Start: "1.2.3", StartInclusive: true, End: "1.2.3", EndInclusive: true, Exact: true,
	}}}
	if got := Judge("generic", "1.2.3", statement); got != Affected {
		t.Fatalf("listed version judged %s", got)
	}
	if got := Judge("generic", "1.2.4", statement); got != InsufficientEvidence {
		t.Fatalf("unlisted version judged %s", got)
	}
	excluded := Statement{Ecosystem: "generic", Ranges: []Range{{
		Ecosystem: "generic", Start: "1.2.4", StartInclusive: true, End: "1.2.4", EndInclusive: true, Exact: true, Excluded: true,
	}}}
	if got := Judge("generic", "1.2.4", excluded); got != NotAffected {
		t.Fatalf("excluded version judged %s", got)
	}
	if got := Judge("generic", "1.2.3", excluded); got != InsufficientEvidence {
		t.Fatalf("version outside an exclusion judged %s", got)
	}
}
