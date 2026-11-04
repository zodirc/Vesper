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
	Unknown              = "unknown"
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
// generic 使用点分数字比较。deb 使用 Debian 版本比较，rpm 使用 RPM EVR 比较。版本无法按对应生态解析时返回证据不足，不用字典序代替。KEV 不参与是否受影响的判断。
// generic uses dotted numeric comparison. deb uses Debian version comparison and rpm uses RPM EVR comparison. A version that cannot be parsed for its ecosystem returns insufficient evidence rather than a lexicographic substitute. KEV does not participate in the affected decision.
func Judge(ecosystem, version string, statement Statement) string {
	if statement.Ecosystem != "" && ecosystem != "" && statement.Ecosystem != ecosystem {
		return NotAffected
	}
	if version == "" || len(statement.Ranges) == 0 {
		return InsufficientEvidence
	}
	comparable := false
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
		if contains {
			return Affected
		}
	}
	if !comparable {
		return InsufficientEvidence
	}
	return NotAffected
}

func comparatorFor(product, item string) (func(string, string) (int, bool), bool) {
	if item != "" && item != "generic" && item != product {
		return nil, false
	}
	switch {
	case item == "deb" || (item == "" && product == "deb"):
		return compareDeb, true
	case item == "rpm" || (item == "" && product == "rpm"):
		return compareRPM, true
	case product == "" || product == "generic" || item == "generic":
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
