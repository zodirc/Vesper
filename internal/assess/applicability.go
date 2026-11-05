// Package assess 判断漏洞适用性。版本证据不足时不生成受影响结论，已知利用记录本身也不证明目标受影响。
// Package assess judges vulnerability applicability. Insufficient version evidence does not produce an affected conclusion, and a known-exploited record by itself does not prove that a target is affected.
package assess

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/zodirc/Vesper/internal/id"
)

const (
	Affected             = "affected"
	NotAffected          = "not_affected"
	NotApplicable        = "not_applicable"
	Unknown              = "unknown"
	Conflict             = "conflict"
	InsufficientEvidence = "insufficient_evidence"
)

// Range 是一个生态相关的版本区间。
// Range is an ecosystem-specific version interval.
type Range struct {
	Ecosystem      string
	Start          string
	StartInclusive bool
	End            string
	EndInclusive   bool
	// Exact 表示这个区间只对列出的版本给出肯定结论。落在区间外时不能据此写成不受影响。
	// Exact means the interval states a positive conclusion only for the listed version. A version outside it is not evidence that the product is unaffected.
	Exact bool `json:"Exact,omitempty"`
	// Excluded 表示落在区间内的版本已被来源明确排除。
	// Excluded means a version inside the interval has been explicitly excluded by the source.
	Excluded bool `json:"Excluded,omitempty"`
}

// Statement 是一条标准化漏洞情报。来源原文的版本区间保持原生态语义，不在这里改写成通用字符串比较。
// Statement is one normalized vulnerability statement. Source version ranges keep their ecosystem semantics and are not rewritten here into a generic string comparison.
type Statement struct {
	ID                       id.ID
	Source                   string
	SourceRecordID           string
	VulnerabilityID          string
	Ecosystem                string
	ProductKey               string
	Ranges                   []Range
	FixedVersions            []string
	PlatformConstraints      json.RawMessage
	ConfigurationConstraints json.RawMessage
	SeverityData             json.RawMessage
	Severity                 string
	KEV                      bool
	EPSS                     *float64
	PublishedAt              *time.Time
	ModifiedAt               *time.Time
	ImportedAt               time.Time
	RawRecordDigest          string
	NormalizationVersion     string
	SupersedesID             id.ID
}

// Judge 比较产品版本和情报区间。
// Judge compares a product version with intelligence ranges.
//
// generic 使用点分数字比较。deb 使用 Debian 版本比较，rpm 使用 RPM EVR 比较，apk 使用 apk-tools 的版本状态机。semver、npm、Go、crates.io、Hex、Pub 和 Swift 使用 SemVer 2.0.0。pypi 使用 PEP 440，maven 使用 Maven ComparableVersion，rubygems 使用 RubyGems 分段，nuget 使用 NuGet 版本，packagist 使用 Composer 规范化。版本无法按对应方案解析时返回证据不足，不用字典序代替。已知但不相同的方案返回 not_applicable。git 提交区间没有仓库时返回证据不足。KEV 不参与是否受影响的判断。Exact 区间只覆盖列出的版本，区间外仍是证据不足。Excluded 区间内的版本是来源明确排除的版本。
// generic uses dotted numeric comparison. deb uses Debian version comparison, rpm uses RPM EVR comparison, and apk uses the apk-tools version state machine. semver, npm, Go, crates.io, Hex, Pub, and Swift use SemVer 2.0.0. pypi uses PEP 440, maven uses Maven ComparableVersion, rubygems uses RubyGems segments, nuget uses NuGet versions, and packagist uses Composer normalization. A version that cannot be parsed for its scheme returns insufficient evidence rather than a lexicographic substitute. Known schemes that differ return not_applicable. A git commit interval returns insufficient evidence when no repository is available. KEV does not participate in the affected decision. An Exact interval covers only the listed version, and a version outside it remains insufficient evidence. A version inside an Excluded interval is one the source explicitly excludes.
func Judge(ecosystem, version string, statement Statement) string {
	if statement.Ecosystem != "" && ecosystem != "" && !ecosystemsCompatible(statement.Ecosystem, ecosystem) {
		if Scheme(statement.Ecosystem) == "unknown" || Scheme(ecosystem) == "unknown" || Scheme(statement.Ecosystem) == "git" || Scheme(ecosystem) == "git" {
			return InsufficientEvidence
		}
		return NotApplicable
	}
	if version == "" || len(statement.Ranges) == 0 {
		return InsufficientEvidence
	}
	comparable := false
	bounded := false
	matchedExclusion := false
	for _, item := range statement.Ranges {
		compare, ok := comparatorFor(ecosystem, item.Ecosystem)
		if !ok {
			continue
		}
		contains, parsed := rangeContains(version, item, compare)
		if !parsed {
			return InsufficientEvidence
		}
		comparable = true
		if item.Exact || item.Excluded {
			if contains && item.Excluded {
				matchedExclusion = true
			}
			if contains && !item.Excluded {
				return Affected
			}
			continue
		}
		bounded = true
		if contains {
			return Affected
		}
	}
	if !comparable {
		return InsufficientEvidence
	}
	if matchedExclusion || bounded {
		return NotAffected
	}
	return InsufficientEvidence
}

func comparatorFor(product, item string) (func(string, string) (int, bool), bool) {
	productScheme, itemScheme := Scheme(product), Scheme(item)
	if item != "" && (itemScheme == "unknown" || itemScheme == "git") {
		return nil, false
	}
	if item != "" && product != "" && itemScheme != "" && productScheme != "" && itemScheme != productScheme {
		return nil, false
	}
	scheme := itemScheme
	if scheme == "" {
		scheme = productScheme
	}
	switch scheme {
	case "deb":
		return compareDeb, true
	case "rpm":
		return compareRPM, true
	case "apk":
		return compareAlpine, true
	case "semver":
		return compareSemver, true
	case "pypi":
		return comparePyPI, true
	case "maven":
		return compareMaven, true
	case "rubygems":
		return compareRuby, true
	case "nuget":
		return compareNuGet, true
	case "composer":
		return compareComposer, true
	case "generic", "":
		return compareGeneric, true
	default:
		return nil, false
	}
}

func rangeContains(version string, item Range, compare func(string, string) (int, bool)) (bool, bool) {
	if item.Start != "" {
		cmp, ok := compare(version, item.Start)
		if !ok {
			return false, false
		}
		if cmp < 0 || (cmp == 0 && !item.StartInclusive) {
			return false, true
		}
	}
	if item.End != "" {
		cmp, ok := compare(version, item.End)
		if !ok {
			return false, false
		}
		if cmp > 0 || (cmp == 0 && !item.EndInclusive) {
			return false, true
		}
	}
	return true, true
}

func compareGeneric(left, right string) (int, bool) {
	a := strings.Split(left, ".")
	b := strings.Split(right, ".")
	n := len(a)
	if len(b) > n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		av, aok := component(a, i)
		bv, bok := component(b, i)
		if !aok || !bok {
			return 0, false
		}
		if av < bv {
			return -1, true
		}
		if av > bv {
			return 1, true
		}
	}
	return 0, true
}

func component(parts []string, index int) (int, bool) {
	if index >= len(parts) {
		return 0, true
	}
	if parts[index] == "" {
		return 0, false
	}
	for _, r := range parts[index] {
		if r < '0' || r > '9' {
			return 0, false
		}
	}
	value, err := strconv.Atoi(parts[index])
	if err != nil {
		return 0, false
	}
	return value, true
}
