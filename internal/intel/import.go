// Package intel 把外部漏洞文档规范化为情报记录。解析失败时不返回部分记录。
// Package intel normalizes external vulnerability documents into intelligence records. A parse failure returns no partial records.
package intel

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	// NormalizationVersion 是当前标准化规则的版本。文档结构无法按这个版本解释时拒绝导入。
	// NormalizationVersion is the current normalization rule version. A document that cannot be interpreted by this version is rejected.
	NormalizationVersion = "1"
	// MaxDocumentBytes 是单次导入接受的原文最大字节数。
	// MaxDocumentBytes is the maximum source-document size accepted in one import.
	MaxDocumentBytes = 32 << 20

	SourceNVD     = "nvd"
	SourceOSV     = "osv"
	SourceCISAKEV = "cisa_kev"
	SourceEPSS    = "epss"
	// SourceVendor 是 CSAF 2.0 厂商安全公告或 VEX。
	// SourceVendor is a CSAF 2.0 vendor security advisory or VEX document.
	SourceVendor = "vendor_advisory"
	// SourceDistro 是 Debian 或 Ubuntu 安全跟踪器文档。
	// SourceDistro is a Debian or Ubuntu security-tracker document.
	SourceDistro = "distro_advisory"
)

// Record 是一条尚未分配内部 ID 的标准化情报。Raw 是参与摘要的原始记录字节。
// Record is one normalized intelligence item without an internal ID. Raw is the original record bytes included in the digest.
type Record struct {
	Source                   string
	SourceRecordID           string
	VulnerabilityID          string
	Ecosystem                string
	ProductSelector          string
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
	Raw                      []byte
	// WithdrawsPrior 表示这条记录撤销同一来源、同一漏洞下已经发布的受影响范围。
	// WithdrawsPrior means this record withdraws affected ranges already published for the same source and vulnerability.
	WithdrawsPrior bool
}

// Range 是从来源事件转换出的版本区间，生态名称保持来源语义。
// Range is a version interval converted from source events. The ecosystem name keeps the source semantics.
type Range struct {
	Ecosystem      string
	Start          string
	StartInclusive bool
	End            string
	EndInclusive   bool
	Exact          bool
	Excluded       bool
}

// Parse 按来源校验并规范化整份文档。source 取 nvd、osv、cisa_kev、epss、vendor_advisory 或 distro_advisory。
// Parse validates and normalizes a whole document for one source. source is nvd, osv, cisa_kev, epss, vendor_advisory, or distro_advisory.
//
// 文档超过大小上限、结构不符合该来源、严重性或分数越界、同一来源记录内容冲突时返回错误，并且不返回记录。
// It returns an error and no records when the document exceeds the size limit, does not match the source structure, has an out-of-range severity or score, or contains conflicting content for one source record.
func Parse(source string, document []byte) ([]Record, error) {
	source, err := CanonicalSource(source)
	if err != nil {
		return nil, err
	}
	document = trimBOM(document)
	if len(bytesTrim(document)) == 0 {
		return nil, errors.New("intel document is empty")
	}
	if len(document) > MaxDocumentBytes {
		return nil, fmt.Errorf("intel document is %d bytes, limit is %d", len(document), MaxDocumentBytes)
	}
	var records []Record
	switch source {
	case SourceOSV:
		records, err = parseOSV(document)
	case SourceNVD:
		records, err = parseNVD(document)
	case SourceCISAKEV:
		records, err = parseKEV(document)
	case SourceEPSS:
		records, err = parseEPSS(document)
	case SourceVendor:
		records, err = parseCSAF(document)
	case SourceDistro:
		records, err = parseDistro(document)
	default:
		err = fmt.Errorf("intel source %s is not supported", source)
	}
	if err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return nil, errors.New("intel document has no records")
	}
	seen := map[string]string{}
	for i := range records {
		records[i].Source = source
		if records[i].SourceRecordID == "" || records[i].VulnerabilityID == "" {
			return nil, fmt.Errorf("intel record %d is missing a source record id or vulnerability id", i)
		}
		if records[i].Severity != "" && !ValidSeverity(records[i].Severity) {
			return nil, fmt.Errorf("intel record %s has severity %s", records[i].SourceRecordID, records[i].Severity)
		}
		sum := sha256.Sum256(records[i].Raw)
		digest := hex.EncodeToString(sum[:])
		previous, ok := seen[records[i].SourceRecordID]
		if ok && previous != digest {
			return nil, fmt.Errorf("intel record %s has conflicting content", records[i].SourceRecordID)
		}
		seen[records[i].SourceRecordID] = digest
	}
	return dedupeRecords(records), nil
}

// CanonicalSource 把调用方写的来源名规范为稳定标识。
// CanonicalSource normalizes a caller-supplied source name to a stable identifier.
func CanonicalSource(source string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(source)) {
	case "nvd":
		return SourceNVD, nil
	case "osv":
		return SourceOSV, nil
	case "cisa_kev", "cisa kev", "kev":
		return SourceCISAKEV, nil
	case "epss", "first epss":
		return SourceEPSS, nil
	case "vendor_advisory", "vendor", "csaf":
		return SourceVendor, nil
	case "distro_advisory", "distro", "distribution":
		return SourceDistro, nil
	default:
		return "", fmt.Errorf("intel source %q is not supported", source)
	}
}

// ValidSeverity 判断严重性是否属于设计列出的等级。空字符串表示来源没有给出可用等级。
// ValidSeverity reports whether a severity is one of the designed levels. An empty string means the source did not provide a usable level.
func ValidSeverity(value string) bool {
	switch value {
	case "info", "low", "medium", "high", "critical":
		return true
	default:
		return false
	}
}

func dedupeRecords(records []Record) []Record {
	seen := map[string]struct{}{}
	var out []Record
	for _, item := range records {
		sum := sha256.Sum256(item.Raw)
		key := item.SourceRecordID + "|" + hex.EncodeToString(sum[:])
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, item)
	}
	return out
}

func trimBOM(document []byte) []byte {
	return []byte(strings.TrimPrefix(string(document), "\uFEFF"))
}

func bytesTrim(document []byte) []byte {
	return []byte(strings.TrimSpace(string(document)))
}

func parseTime(value string) (*time.Time, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		parsed, err = time.Parse("2006-01-02", value)
		if err != nil {
			return nil, fmt.Errorf("parse time %q: %w", value, err)
		}
	}
	utc := parsed.UTC()
	return &utc, nil
}

func severityFromCVSS(baseSeverity string, baseScore *float64) (string, error) {
	stated := strings.ToLower(strings.TrimSpace(baseSeverity))
	if baseScore != nil && (*baseScore < 0 || *baseScore > 10) {
		return "", fmt.Errorf("cvss score %v is outside 0 to 10", *baseScore)
	}
	if stated == "none" {
		if baseScore != nil && *baseScore != 0 {
			return "", fmt.Errorf("cvss severity %s does not match score %v", baseSeverity, *baseScore)
		}
		return "", nil
	}
	var fromScore string
	if baseScore != nil {
		fromScore = severityBand(*baseScore)
	}
	switch stated {
	case "":
		return fromScore, nil
	case "low", "medium", "high", "critical":
		if fromScore != "" && stated != fromScore {
			return "", fmt.Errorf("cvss severity %s does not match score %v", baseSeverity, *baseScore)
		}
		return stated, nil
	default:
		return "", fmt.Errorf("cvss severity %s is not recognized", baseSeverity)
	}
}

func severityBand(score float64) string {
	switch {
	case score <= 0:
		return ""
	case score < 4:
		return "low"
	case score < 7:
		return "medium"
	case score < 9:
		return "high"
	default:
		return "critical"
	}
}

func cveID(value string) bool {
	value = strings.TrimSpace(value)
	if !strings.HasPrefix(value, "CVE-") {
		return false
	}
	parts := strings.Split(value, "-")
	if len(parts) != 3 || len(parts[1]) != 4 || len(parts[2]) < 4 {
		return false
	}
	for _, part := range parts[1:] {
		for _, r := range part {
			if r < '0' || r > '9' {
				return false
			}
		}
	}
	return true
}
