package control

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/zodirc/Vesper/internal/id"
	"github.com/zodirc/Vesper/internal/nmapfinger"
	"github.com/zodirc/Vesper/internal/rule"
)

// NmapFingerprintPack 是一份已转换的 Nmap 服务探针规则包，不包含原文和正则。
// NmapFingerprintPack is one converted Nmap service-probe rule pack. It does not contain the source text or regular expressions.
type NmapFingerprintPack struct {
	ID              id.ID
	Version         string
	Status          string
	Accepted        int
	Skipped         map[string]int
	LicenseRecorded bool
}

// ImportNmapFingerprints 校验调用方提交的 nmap-service-probes 文档并保存为未发布规则包。
// ImportNmapFingerprints validates a caller-supplied nmap-service-probes document and stores it as an unpublished rule pack.
//
// 相同文档再次导入时返回已有规则包，不改写规则。导入不下载文件，也不把探针载荷交给扫描器。
// Importing the same document again returns the existing pack and does not rewrite the rules. Import does not download a file and does not give probe payloads to the scanner.
func (s *Service) ImportNmapFingerprints(ctx context.Context, document []byte) (NmapFingerprintPack, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	converted, report, err := nmapfinger.Convert(document)
	if err != nil {
		return NmapFingerprintPack{}, err
	}
	version := "nmap:" + report.DocumentDigest
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, pack := range s.packs {
		if pack.Type == "fingerprint" && pack.Source == "nmap" && pack.Version == version {
			return nmapPackView(pack), nil
		}
	}
	pack, err := newNmapPack(version, converted, report, s.now().UTC())
	if err != nil {
		return NmapFingerprintPack{}, err
	}
	if err := s.commitState(ctx, func() error {
		s.packs = append(s.packs, pack)
		return nil
	}); err != nil {
		return NmapFingerprintPack{}, err
	}
	return nmapPackView(pack), nil
}

// PublishNmapFingerprints 发布一份已通过转换的规则包。之后创建的扫描会冻结这个版本。
// PublishNmapFingerprints publishes one pack that has passed conversion. Scans created afterward freeze this version.
func (s *Service) PublishNmapFingerprints(ctx context.Context, packID id.ID) (NmapFingerprintPack, error) {
	return s.setNmapPackStatus(ctx, packID, "published")
}

// DeprecateNmapFingerprints 停止新扫描选用这份规则包。已经冻结该版本的扫描仍使用当时的规则。
// DeprecateNmapFingerprints stops new scans from selecting this pack. A scan that already froze the version keeps those rules.
func (s *Service) DeprecateNmapFingerprints(ctx context.Context, packID id.ID) (NmapFingerprintPack, error) {
	return s.setNmapPackStatus(ctx, packID, "deprecated")
}

// NmapFingerprintPacks 返回 Nmap 规则包元数据，不返回规则正文。
// NmapFingerprintPacks returns Nmap pack metadata and does not return rule bodies.
func (s *Service) NmapFingerprintPacks() []NmapFingerprintPack {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []NmapFingerprintPack
	for _, pack := range s.packs {
		if pack.Type == "fingerprint" && pack.Source == "nmap" {
			out = append(out, nmapPackView(pack))
		}
	}
	return out
}

func (s *Service) setNmapPackStatus(ctx context.Context, packID id.ID, status string) (NmapFingerprintPack, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	index := -1
	for i := range s.packs {
		if s.packs[i].ID == packID && s.packs[i].Type == "fingerprint" && s.packs[i].Source == "nmap" {
			index = i
			break
		}
	}
	if index < 0 {
		return NmapFingerprintPack{}, fmt.Errorf("nmap fingerprint pack %s: not found", packID)
	}
	if err := s.commitState(ctx, func() error {
		if status == "published" {
			now := s.now().UTC()
			s.packs[index].Status = "published"
			if s.packs[index].PublishedAt == nil {
				s.packs[index].PublishedAt = &now
			}
			return nil
		}
		if s.packs[index].Status != "published" && s.packs[index].Status != "deprecated" && s.packs[index].Status != "validated" {
			return fmt.Errorf("nmap fingerprint pack %s: status %s", packID, s.packs[index].Status)
		}
		s.packs[index].Status = "deprecated"
		return nil
	}); err != nil {
		return NmapFingerprintPack{}, err
	}
	return nmapPackView(s.packs[index]), nil
}

func (s *Service) publishedNmapFingerprints() []string {
	var out []string
	for _, pack := range s.packs {
		if pack.Type == "fingerprint" && pack.Source == "nmap" && pack.Status == "published" {
			out = append(out, pack.Version)
		}
	}
	sort.Strings(out)
	return out
}

func newNmapPack(version string, converted []nmapfinger.Rule, report nmapfinger.Report, now time.Time) (rule.Pack, error) {
	rules := make([]rule.FingerprintRule, 0, len(converted))
	for _, item := range converted {
		var extractors []rule.Extractor
		if item.Product != "" {
			extractors = append(extractors, rule.Extractor{Target: "product", Source: "response", Method: "capture", Template: item.Product})
		}
		if item.Version != "" {
			extractors = append(extractors, rule.Extractor{Target: "version", Source: "response", Method: "capture", Template: item.Version})
		}
		rules = append(rules, rule.FingerprintRule{
			ID: rule.StableID("fingerprint:" + version + ":" + item.Key), Key: item.Key, Version: version, Priority: item.Priority,
			TargetProtocol: item.Protocol, ServiceType: item.Protocol,
			Conditions:        []rule.Condition{{Field: "response", Op: "regex", Value: item.Pattern}},
			Extractors:        extractors,
			ConfidenceMatched: item.ConfidenceMatched, ConfidenceEmpty: item.ConfidenceEmpty,
		})
	}
	license, err := json.Marshal(map[string]string{"format": report.Format, "notice": report.License})
	if err != nil {
		return rule.Pack{}, err
	}
	compatibility, err := json.Marshal(report)
	if err != nil {
		return rule.Pack{}, err
	}
	pack := rule.Pack{
		ID: rule.StableID("pack:fingerprint:" + version), Type: "fingerprint", Version: version,
		SchemaVersion: rule.SchemaVersion, Source: "nmap", Status: "validated", License: license,
		Compatibility: compatibility, CreatedAt: now, Fingerprints: rules,
	}
	digest, err := rule.Digest(pack)
	if err != nil {
		return rule.Pack{}, err
	}
	pack.ContentDigest = digest
	return pack, nil
}

func nmapPackView(pack rule.Pack) NmapFingerprintPack {
	var report nmapfinger.Report
	_ = json.Unmarshal(pack.Compatibility, &report)
	if report.Skipped == nil {
		report.Skipped = map[string]int{}
	}
	return NmapFingerprintPack{
		ID: pack.ID, Version: pack.Version, Status: pack.Status, Accepted: report.Accepted,
		Skipped: report.Skipped, LicenseRecorded: len(pack.License) > 2,
	}
}
