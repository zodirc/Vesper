package assess

import "testing"

func TestSemVerPrecedenceIgnoresBuild(t *testing.T) {
	order := []string{"1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta", "1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0"}
	assertOrder(t, "semver", order)
	if cmp, ok := compareSemver("1.0.0+aaa", "1.0.0+bbb"); !ok || cmp != 0 {
		t.Fatalf("build precedence = %d %v", cmp, ok)
	}
	if got, ok := NormalizeVersion("semver", "V1.2.3-rc.1+build.7"); !ok || got != "1.2.3-rc.1+build.7" {
		t.Fatalf("canonical = %q %v", got, ok)
	}
	if _, ok := NormalizeVersion("semver", "01.2.3"); ok {
		t.Fatal("leading zero was accepted")
	}
	if _, ok := NormalizeVersion("npm", "1.2.3-01"); ok {
		t.Fatal("numeric prerelease with a leading zero was accepted")
	}
	statement := Statement{Ecosystem: "npm", Ranges: []Range{{Ecosystem: "npm", Start: "1.0.0", StartInclusive: true, End: "2.0.0"}}}
	if got := Judge("npm", "1.0.0-rc.1", statement); got != NotAffected {
		t.Fatalf("prerelease judged %s", got)
	}
	if got := Judge("npm", "1.2.3+build", statement); got != Affected {
		t.Fatalf("build judged %s", got)
	}
	if got := Judge("npm", "1.2", statement); got != InsufficientEvidence {
		t.Fatalf("short version judged %s", got)
	}
}

func TestPEP440OrderAndCanonicalForm(t *testing.T) {
	order := []string{
		"1.dev0", "1.0.dev456", "1.0a1", "1.0a2.dev456", "1.0a12", "1.0b1", "1.0rc1", "1.0",
		"1.0+abc.5", "1.0+abc.7", "1.0+5", "1.0.post456",
	}
	assertOrder(t, "pypi", order)
	if cmp, ok := comparePyPI("1.0", "1.0.0"); !ok || cmp != 0 {
		t.Fatalf("trailing zero = %d %v", cmp, ok)
	}
	if got, ok := NormalizeVersion("pypi", "1!1.0.0-alpha1"); !ok || got != "1!1a1" {
		t.Fatalf("canonical = %q %v", got, ok)
	}
	if got, ok := NormalizeVersion("pypi", "1.0-1"); !ok || got != "1.post1" {
		t.Fatalf("implicit post = %q %v", got, ok)
	}
	if _, ok := NormalizeVersion("pypi", "not-a-version"); ok {
		t.Fatal("text was accepted as a Python version")
	}
}

func TestMavenQualifierOrder(t *testing.T) {
	order := []string{
		"1-alpha2snapshot", "1-alpha2", "1-alpha-123", "1-beta-2", "1-beta123", "1-m2", "1-m11",
		"1-rc", "1-cr2", "1-rc123", "1-SNAPSHOT", "1", "1-sp", "1-sp2", "1-abc", "1-def", "1-1",
	}
	assertOrder(t, "maven", order)
	if cmp, ok := compareMaven("1", "1.0.0"); !ok || cmp != 0 {
		t.Fatalf("padding = %d %v", cmp, ok)
	}
	if cmp, ok := compareMaven("1.0", "1.0-ga"); !ok || cmp != 0 {
		t.Fatalf("ga = %d %v", cmp, ok)
	}
	if got, ok := NormalizeVersion("maven", "1.0.0-Final"); !ok || got != "1" {
		t.Fatalf("canonical = %q %v", got, ok)
	}
	if got, ok := NormalizeVersion("maven", "1.0-alpha-1"); !ok || got != "1.0-alpha-1" {
		t.Fatalf("alpha canonical = %q %v", got, ok)
	}
	statement := Statement{Ecosystem: "maven", Ranges: []Range{{Ecosystem: "maven", Start: "1.0", StartInclusive: true, End: "2.0"}}}
	if got := Judge("maven", "1.0-alpha", statement); got != NotAffected {
		t.Fatalf("qualifier judged %s", got)
	}
	if got := Judge("maven", "1.0-sp", statement); got != Affected {
		t.Fatalf("service pack judged %s", got)
	}
}

func assertOrder(t *testing.T, ecosystem string, versions []string) {
	t.Helper()
	for i := 0; i < len(versions); i++ {
		for j := i + 1; j < len(versions); j++ {
			cmp, ok := compareEcosystem(ecosystem, versions[i], versions[j])
			if !ok || cmp >= 0 {
				t.Fatalf("%s: %s compared with %s = %d %v", ecosystem, versions[i], versions[j], cmp, ok)
			}
		}
	}
}

func compareEcosystem(ecosystem, left, right string) (int, bool) {
	switch ecosystem {
	case "semver":
		return compareSemver(left, right)
	case "pypi":
		return comparePyPI(left, right)
	case "maven":
		return compareMaven(left, right)
	case "apk":
		return compareAlpine(left, right)
	default:
		return 0, false
	}
}
