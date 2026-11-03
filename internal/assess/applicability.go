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
// deb 和 rpm 目前没有对应的版本比较器，因此返回证据不足，不用字典序代替。KEV 不参与是否受影响的判断。
// deb and rpm do not yet have version comparators, so the result is insufficient evidence rather than a lexicographic substitute. KEV does not participate in the affected decision.
func Judge(ecosystem, version string, statement Statement) string {
	if statement.Ecosystem != "" && ecosystem != "" && statement.Ecosystem != ecosystem {
		return NotAffected
	}
	switch ecosystem {
	case "", "generic":
	case "deb", "rpm":
		return InsufficientEvidence
	default:
		return InsufficientEvidence
	}
	if version == "" || len(statement.Ranges) == 0 {
		return InsufficientEvidence
	}
	for _, item := range statement.Ranges {
		if item.Ecosystem != "" && item.Ecosystem != "generic" && item.Ecosystem != ecosystem {
			continue
		}
		if genericContains(version, item) {
			return Affected
		}
	}
	return NotAffected
}

func genericContains(version string, item Range) bool {
	if item.Start != "" {
		cmp, ok := compareGeneric(version, item.Start)
		if !ok {
			return false
		}
		if cmp < 0 || (cmp == 0 && !item.StartInclusive) {
			return false
		}
	}
	if item.End != "" {
		cmp, ok := compareGeneric(version, item.End)
		if !ok {
			return false
		}
		if cmp > 0 || (cmp == 0 && !item.EndInclusive) {
			return false
		}
	}
	return true
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
