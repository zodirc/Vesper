package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/zodirc/Vesper/internal/configrule"
	"github.com/zodirc/Vesper/internal/id"
	"github.com/zodirc/Vesper/internal/rule"
)

// ErrConfigPackNotFound 表示配置规则包不存在，或标识不属于调用方提交的配置包。
// ErrConfigPackNotFound means the configuration pack does not exist, or the identifier does not belong to a caller-submitted configuration pack.
var ErrConfigPackNotFound = errors.New("config pack not found")

// ConfigPack 是一份配置规则包的元数据，不包含规则正文。
// ConfigPack is metadata for one configuration-rule pack. It does not contain the rule body.
type ConfigPack struct {
	ID              id.ID
	Version         string
	Status          string
	Rules           int
	LicenseRecorded bool
}

// ImportConfigPack 校验调用方提交的 vesper-config 文档并保存为未发布规则包。
// ImportConfigPack validates a caller-supplied vesper-config document and stores it as an unpublished rule pack.
//
// 相同文档再次导入时返回已有规则包，不改写规则。导入不下载基准，也不执行采集。
// Importing the same document again returns the existing pack and does not rewrite the rules. Import does not download a benchmark and does not run collection.
func (s *Service) ImportConfigPack(ctx context.Context, document []byte) (ConfigPack, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	doc, err := configrule.Admit(document)
	if err != nil {
		return ConfigPack{}, err
	}
	version := "config:" + doc.Digest
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, pack := range s.packs {
		if pack.Type == "config" && pack.Source == "config" && pack.Version == version {
			return configPackView(pack), nil
		}
	}
	pack, err := newConfigPack(version, doc, s.now().UTC())
	if err != nil {
		return ConfigPack{}, err
	}
	if err := s.commitState(ctx, func() error {
		s.packs = append(s.packs, pack)
		return nil
	}); err != nil {
		return ConfigPack{}, err
	}
	return configPackView(pack), nil
}

// PublishConfigPack 发布一份已通过校验的配置规则包。之后创建的扫描会冻结这个版本。
// PublishConfigPack publishes one configuration pack that has passed validation. Scans created afterward freeze this version.
func (s *Service) PublishConfigPack(ctx context.Context, packID id.ID) (ConfigPack, error) {
	return s.setConfigPackStatus(ctx, packID, "published")
}

// DeprecateConfigPack 停止新扫描选用这份规则包。已经冻结该版本的扫描仍使用当时的规则。
// DeprecateConfigPack stops new scans from selecting this pack. A scan that already froze the version keeps those rules.
func (s *Service) DeprecateConfigPack(ctx context.Context, packID id.ID) (ConfigPack, error) {
	return s.setConfigPackStatus(ctx, packID, "deprecated")
}

// ConfigPacks 返回配置规则包元数据，不返回规则正文。
// ConfigPacks returns configuration-pack metadata and does not return rule bodies.
func (s *Service) ConfigPacks() []ConfigPack {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []ConfigPack
	for _, pack := range s.packs {
		if pack.Type == "config" && pack.Source == "config" {
			out = append(out, configPackView(pack))
		}
	}
	return out
}

func (s *Service) setConfigPackStatus(ctx context.Context, packID id.ID, status string) (ConfigPack, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	index := -1
	for i := range s.packs {
		if s.packs[i].ID == packID && s.packs[i].Type == "config" && s.packs[i].Source == "config" {
			index = i
			break
		}
	}
	if index < 0 {
		return ConfigPack{}, fmt.Errorf("config pack %s: %w", packID, ErrConfigPackNotFound)
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
			return fmt.Errorf("config pack %s: status %s", packID, s.packs[index].Status)
		}
		s.packs[index].Status = "deprecated"
		return nil
	}); err != nil {
		return ConfigPack{}, err
	}
	return configPackView(s.packs[index]), nil
}

func (s *Service) publishedConfigPacks() []string {
	var out []string
	for _, pack := range s.packs {
		if pack.Type == "config" && pack.Source == "config" && pack.Status == "published" {
			out = append(out, pack.Version)
		}
	}
	sort.Strings(out)
	return out
}

func (s *Service) configPackVersion(ruleID id.ID) string {
	if ruleID.IsZero() {
		return ""
	}
	for _, pack := range s.packs {
		if pack.Type != "config" || pack.Source != "config" {
			continue
		}
		if pack.Status != "published" && pack.Status != "deprecated" {
			continue
		}
		for _, item := range pack.Configs {
			if item.ID == ruleID {
				return pack.Version
			}
		}
	}
	return ""
}

func newConfigPack(version string, doc configrule.Document, now time.Time) (rule.Pack, error) {
	rules := make([]rule.ConfigRule, 0, len(doc.Rules))
	for _, item := range doc.Rules {
		rules = append(rules, rule.ConfigRule{
			ID: rule.StableID("config:" + version + ":" + item.Key), Key: item.Key, Version: version,
			SubjectType: "asset", RequiredObservationType: "host_inventory", Operation: item.Operation,
			Severity: item.Severity, Title: item.Title, Category: item.Category, Remediation: item.Remediation,
			Applicability: item.Applicability, Pass: item.Pass, Fail: item.Fail,
		})
	}
	licenseBody := map[string]string{"format": "vesper-config", "origin": "caller"}
	if doc.License != "" {
		licenseBody = map[string]string{"format": "vesper-config", "notice": doc.License}
	}
	license, err := json.Marshal(licenseBody)
	if err != nil {
		return rule.Pack{}, err
	}
	compatibility, err := json.Marshal(map[string]any{"format": "vesper-config", "rules": len(rules)})
	if err != nil {
		return rule.Pack{}, err
	}
	pack := rule.Pack{
		ID: rule.StableID("pack:config:" + version), Type: "config", Version: version,
		SchemaVersion: rule.SchemaVersion, Source: "config", Status: "validated", License: license,
		Compatibility: compatibility, CreatedAt: now, Configs: rules,
	}
	digest, err := rule.Digest(pack)
	if err != nil {
		return rule.Pack{}, err
	}
	pack.ContentDigest = digest
	return pack, nil
}

func configPackView(pack rule.Pack) ConfigPack {
	var meta struct {
		Notice string `json:"notice"`
	}
	_ = json.Unmarshal(pack.License, &meta)
	return ConfigPack{
		ID: pack.ID, Version: pack.Version, Status: pack.Status, Rules: len(pack.Configs),
		LicenseRecorded: meta.Notice != "",
	}
}

func addUnique(values []string, extra string) []string {
	if extra == "" {
		return values
	}
	for _, item := range values {
		if item == extra {
			return values
		}
	}
	return append(values, extra)
}
