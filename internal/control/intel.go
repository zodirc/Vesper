package control

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/zodirc/Vesper/internal/assess"
	"github.com/zodirc/Vesper/internal/id"
	"github.com/zodirc/Vesper/internal/identity"
	"github.com/zodirc/Vesper/internal/intel"
)

// IntelSnapshot 是一次不可变的情报发布。内容摘要覆盖该快照纳入的当前语句，不随后续导入改变。
// IntelSnapshot is one immutable intelligence publication. Its content digest covers the current statements included in that snapshot and does not change with later imports.
type IntelSnapshot struct {
	ID                   id.ID
	NormalizationVersion string
	ContentDigest        string
	Sources              []string
	ImportBatchID        id.ID
	StatementIDs         []id.ID
	PublishedAt          time.Time
}

// ImportIntel 校验一份外部文档，写入新的情报语句，并在内容变化时发布新快照。
// ImportIntel validates one external document, stores new intelligence statements, and publishes a new snapshot when the content changed.
//
// source 取 nvd、osv、cisa_kev 或 epss。相同来源记录且原始摘要不变时不新增语句。内容变化时保留旧语句，新语句记录它所替代的语句。
// source is nvd, osv, cisa_kev, or epss. An unchanged source record does not create another statement. When content changes, the old statement stays and the new statement records the statement it supersedes.
//
// 校验失败时不发布快照。调用方持有的文档是输入，这个方法不从外部网络获取数据。
// A validation failure publishes no snapshot. The caller supplies the document, and this method does not fetch data from an external network.
func (s *Service) ImportIntel(ctx context.Context, source string, document []byte) (IntelSnapshot, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	records, err := intel.Parse(source, document)
	if err != nil {
		return IntelSnapshot{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var published IntelSnapshot
	err = s.commitState(ctx, func() error {
		if err := s.stageRecords(records, s.now().UTC()); err != nil {
			return err
		}
		var publishErr error
		published, publishErr = s.publishSnapshot(s.now().UTC())
		return publishErr
	})
	return published, err
}

// Reassess 用指定情报快照对已有服务候选和已采集的发行版软件包重新做适用性判断。
// Reassess judges applicability of existing service candidates and collected distribution packages again with one selected intelligence snapshot.
//
// 已有观察、已有候选和已有检测结果保持不变。当前已发布的指纹规则会追加新的服务候选，当前已发布的配置规则会用每个资产最新的主机观察再判断一次。同一快照、同一主体、同一规则和同一输入已经有相同结论时不再追加。新的确认会更新 Finding 的当前严重性。证据过期后的补充采集没有设计给出的时限，这里不创建新的扫描，也不写入 resolve。
// Existing observations, candidates, and detection results stay unchanged. The currently published fingerprint rules append new service candidates, and the currently published configuration rules judge each asset's latest host observations again. An identical conclusion for the same snapshot, subject, rule, and inputs is not appended. A new confirmation updates the Finding's current severity. Supplemental collection after evidence expiry has no designed time limit, so this does not create a scan and does not write resolve.
func (s *Service) Reassess(ctx context.Context, snapshotID id.ID) (int, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var added int
	err := s.commitState(ctx, func() error {
		if _, ok := s.snapshotByID(snapshotID); !ok {
			return fmt.Errorf("reassess: intel snapshot %s not found", snapshotID)
		}
		before := len(s.detections)
		if err := s.reidentify(snapshotID); err != nil {
			return err
		}
		if err := s.reevaluateConfigs(snapshotID); err != nil {
			return err
		}
		for _, item := range s.hypotheses {
			if err := s.judgeHypothesis(snapshotID, item); err != nil {
				return err
			}
		}
		if err := s.judgeDistroPackages(snapshotID, id.ID{}); err != nil {
			return err
		}
		added = len(s.detections) - before
		return nil
	})
	return added, err
}

// Snapshots 返回已发布情报快照的副本。
// Snapshots returns copies of published intelligence snapshots.
func (s *Service) Snapshots() []IntelSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]IntelSnapshot, len(s.snapshots))
	for i, item := range s.snapshots {
		out[i] = item
		out[i].Sources = append([]string(nil), item.Sources...)
		out[i].StatementIDs = append([]id.ID(nil), item.StatementIDs...)
	}
	return out
}

func (s *Service) stageRecords(records []intel.Record, now time.Time) error {
	for _, record := range records {
		statement, err := statementFromRecord(record, now)
		if err != nil {
			return err
		}
		if !intel.ValidSeverity(statement.Severity) && statement.Severity != "" {
			return fmt.Errorf("intel statement %s has severity %s", statement.SourceRecordID, statement.Severity)
		}
		if record.WithdrawsPrior {
			if err := s.withdrawVulnerability(record, now); err != nil {
				return err
			}
			continue
		}
		previous, ok := s.latestStatement(statement.Source, statement.SourceRecordID)
		if ok && previous.RawRecordDigest == statement.RawRecordDigest {
			continue
		}
		if ok {
			statement.SupersedesID = previous.ID
			if !statement.ImportedAt.After(previous.ImportedAt) {
				statement.ImportedAt = previous.ImportedAt.Add(time.Nanosecond)
			}
		}
		statement.ID, err = id.New()
		if err != nil {
			return err
		}
		s.statements = append(s.statements, statement)
	}
	return nil
}

func statementFromRecord(record intel.Record, now time.Time) (assess.Statement, error) {
	sum := sha256.Sum256(record.Raw)
	ranges := make([]assess.Range, len(record.Ranges))
	for i, item := range record.Ranges {
		ranges[i] = assess.Range{Ecosystem: item.Ecosystem, Start: item.Start, StartInclusive: item.StartInclusive, End: item.End, EndInclusive: item.EndInclusive, Exact: item.Exact, Excluded: item.Excluded}
	}
	return assess.Statement{
		Source: record.Source, SourceRecordID: record.SourceRecordID, VulnerabilityID: record.VulnerabilityID,
		Ecosystem: record.Ecosystem, ProductKey: record.ProductSelector, Ranges: ranges, FixedVersions: append([]string(nil), record.FixedVersions...),
		PlatformConstraints: append(json.RawMessage(nil), record.PlatformConstraints...), ConfigurationConstraints: append(json.RawMessage(nil), record.ConfigurationConstraints...),
		SeverityData: append(json.RawMessage(nil), record.SeverityData...), Severity: record.Severity, KEV: record.KEV, EPSS: record.EPSS,
		PublishedAt: record.PublishedAt, ModifiedAt: record.ModifiedAt, ImportedAt: now, RawRecordDigest: hex.EncodeToString(sum[:]),
		NormalizationVersion: intel.NormalizationVersion,
	}, nil
}

func (s *Service) publishSnapshot(now time.Time) (IntelSnapshot, error) {
	current := currentStatements(s.statements)
	digest := snapshotDigest(current)
	if latest, ok := s.latestSnapshot(); ok && latest.ContentDigest == digest {
		return latest, nil
	}
	snapshotID, err := id.New()
	if err != nil {
		return IntelSnapshot{}, err
	}
	batchID, err := id.New()
	if err != nil {
		return IntelSnapshot{}, err
	}
	publishedAt := now
	if latest, ok := s.latestSnapshot(); ok && !publishedAt.After(latest.PublishedAt) {
		publishedAt = latest.PublishedAt.Add(time.Nanosecond)
	}
	snapshot := IntelSnapshot{
		ID: snapshotID, NormalizationVersion: intel.NormalizationVersion, ContentDigest: digest,
		Sources: snapshotSources(current), ImportBatchID: batchID, StatementIDs: statementIDs(current), PublishedAt: publishedAt,
	}
	s.snapshots = append(s.snapshots, snapshot)
	return snapshot, nil
}

func (s *Service) latestSnapshotID() id.ID {
	latest, ok := s.latestSnapshot()
	if !ok {
		return id.ID{}
	}
	return latest.ID
}

func (s *Service) latestSnapshot() (IntelSnapshot, bool) {
	if len(s.snapshots) == 0 {
		return IntelSnapshot{}, false
	}
	latest := s.snapshots[0]
	for _, item := range s.snapshots[1:] {
		if item.PublishedAt.After(latest.PublishedAt) || (item.PublishedAt.Equal(latest.PublishedAt) && item.ID.String() > latest.ID.String()) {
			latest = item
		}
	}
	return latest, true
}

func (s *Service) snapshotByID(snapshotID id.ID) (IntelSnapshot, bool) {
	for _, item := range s.snapshots {
		if item.ID == snapshotID {
			return item, true
		}
	}
	return IntelSnapshot{}, false
}

func (s *Service) statementsIn(snapshotID id.ID) []assess.Statement {
	snapshot, ok := s.snapshotByID(snapshotID)
	if !ok {
		return nil
	}
	member := map[id.ID]struct{}{}
	for _, statementID := range snapshot.StatementIDs {
		member[statementID] = struct{}{}
	}
	var out []assess.Statement
	for _, item := range s.statements {
		if _, ok := member[item.ID]; ok {
			out = append(out, item)
		}
	}
	return out
}

func (s *Service) withdrawVulnerability(record intel.Record, now time.Time) error {
	latest := map[string]assess.Statement{}
	for _, item := range s.statements {
		if item.Source != record.Source || item.VulnerabilityID != record.VulnerabilityID || item.SourceRecordID == "" {
			continue
		}
		previous, ok := latest[item.SourceRecordID]
		if !ok || item.ImportedAt.After(previous.ImportedAt) || (item.ImportedAt.Equal(previous.ImportedAt) && item.ID.String() > previous.ID.String()) {
			latest[item.SourceRecordID] = item
		}
	}
	sum := sha256.Sum256(record.Raw)
	digest := hex.EncodeToString(sum[:])
	if len(latest) == 0 {
		record.WithdrawsPrior = false
		record.Ranges = nil
		record.FixedVersions = nil
		record.PlatformConstraints = nil
		record.ConfigurationConstraints = nil
		if record.SourceRecordID == "" {
			record.SourceRecordID = record.VulnerabilityID
		}
		statement, err := statementFromRecord(record, now)
		if err != nil {
			return err
		}
		statement.ID, err = id.New()
		if err != nil {
			return err
		}
		s.statements = append(s.statements, statement)
		return nil
	}
	for _, previous := range latest {
		if previous.RawRecordDigest == digest && len(previous.Ranges) == 0 && !hasConstraint(previous.PlatformConstraints) && !hasConstraint(previous.ConfigurationConstraints) {
			continue
		}
		next := previous
		next.Ranges = nil
		next.FixedVersions = nil
		next.PlatformConstraints = nil
		next.ConfigurationConstraints = nil
		next.Severity = record.Severity
		next.SeverityData = append(json.RawMessage(nil), record.SeverityData...)
		next.KEV = false
		next.EPSS = nil
		next.SupersedesID = previous.ID
		next.RawRecordDigest = digest
		next.ImportedAt = now
		if !next.ImportedAt.After(previous.ImportedAt) {
			next.ImportedAt = previous.ImportedAt.Add(time.Nanosecond)
		}
		var err error
		next.ID, err = id.New()
		if err != nil {
			return err
		}
		s.statements = append(s.statements, next)
	}
	return nil
}

func (s *Service) latestStatement(source, sourceRecordID string) (assess.Statement, bool) {
	var found assess.Statement
	ok := false
	for _, item := range s.statements {
		if item.Source != source || item.SourceRecordID != sourceRecordID {
			continue
		}
		if !ok || item.ImportedAt.After(found.ImportedAt) || (item.ImportedAt.Equal(found.ImportedAt) && item.ID.String() > found.ID.String()) {
			found = item
			ok = true
		}
	}
	return found, ok
}

func (s *Service) judgeHypothesis(snapshotID id.ID, item identity.Hypothesis) error {
	if item.ProductIdentityID == nil || item.RawVersion == "" {
		return nil
	}
	product, ok := s.products[*item.ProductIdentityID]
	if !ok {
		return nil
	}
	var batch []serviceJudgment
	for _, statement := range s.statementsIn(snapshotID) {
		if len(statement.Ranges) == 0 || !statementApplies(product, s.aliases, statement) {
			continue
		}
		ecosystem := statement.Ecosystem
		if ecosystem == "" || ecosystem == "cpe" {
			ecosystem = product.Ecosystem
		}
		version := item.RawVersion
		result := applicabilityFor(ecosystem, version, statement)
		if result == assess.InsufficientEvidence && item.NormalizedVersion != "" && item.NormalizedVersion != version {
			if again := applicabilityFor(ecosystem, item.NormalizedVersion, statement); again != assess.InsufficientEvidence {
				result = again
				version = item.NormalizedVersion
			}
		}
		if item.IdentityStatus == "conflict" && result == assess.Affected {
			result = assess.Conflict
		}
		batch = append(batch, serviceJudgment{
			statement: statement, result: result, version: version, evidence: s.verifiedEvidence(item.SupportingObservationIDs),
		})
	}
	markServiceContradictions(batch)
	if len(batch) == 0 {
		return nil
	}
	assessmentID, err := id.New()
	if err != nil {
		return err
	}
	for _, judged := range batch {
		detection := Detection{
			AssessmentRunID: assessmentID, EndpointID: item.EndpointID, SubjectType: "endpoint", SubjectID: item.EndpointID,
			VulnerabilityID: judged.statement.VulnerabilityID, ResultStatus: mapApplicability(judged.result), Severity: judged.statement.Severity,
			Summary: judged.result, EvidenceIDs: judged.evidence, InputObservationIDs: append([]id.ID(nil), item.SupportingObservationIDs...),
			IntelSnapshotID: snapshotID, EvaluatedAt: s.now(),
		}
		if s.duplicateDetection(detection) {
			continue
		}
		detectionID, err := id.New()
		if err != nil {
			return err
		}
		detection.ID = detectionID
		s.detections = append(s.detections, detection)
		if detection.ResultStatus != "confirmed" {
			continue
		}
		s.mergeFinding(item.EndpointID, id.ID{}, judged.statement.VulnerabilityID, detectionID, assessmentID, judged.version, "vulnerability", judged.statement.Severity, judged.evidence, id.ID{}, derefID(item.ProductIdentityID))
	}
	return nil
}

type serviceJudgment struct {
	statement assess.Statement
	result    string
	version   string
	evidence  []id.ID
}

func markServiceContradictions(batch []serviceJudgment) {
	type flags struct{ affected, clear bool }
	groups := map[string]*flags{}
	for i := range batch {
		key := batch[i].statement.VulnerabilityID
		group := groups[key]
		if group == nil {
			group = &flags{}
			groups[key] = group
		}
		switch batch[i].result {
		case assess.Affected:
			group.affected = true
		case assess.NotAffected:
			group.clear = true
		}
	}
	for i := range batch {
		group := groups[batch[i].statement.VulnerabilityID]
		if group.affected && group.clear && (batch[i].result == assess.Affected || batch[i].result == assess.NotAffected) {
			batch[i].result = assess.Conflict
		}
	}
}

func applicabilityFor(ecosystem, version string, statement assess.Statement) string {
	judged := statement
	if statement.Ecosystem == "cpe" {
		judged.Ecosystem = ""
		judged.Ranges = append([]assess.Range(nil), statement.Ranges...)
		for i := range judged.Ranges {
			if judged.Ranges[i].Ecosystem == "" || judged.Ranges[i].Ecosystem == "cpe" {
				judged.Ranges[i].Ecosystem = "generic"
			}
		}
	}
	result := assess.Judge(ecosystem, version, judged)
	if result == assess.Affected && (hasConstraint(statement.ConfigurationConstraints) || hasConstraint(statement.PlatformConstraints)) {
		return assess.InsufficientEvidence
	}
	return result
}

func hasConstraint(raw json.RawMessage) bool {
	text := bytes.TrimSpace(raw)
	return len(text) > 0 && string(text) != "null" && string(text) != "{}" && string(text) != "[]"
}

func statementApplies(product Product, aliases []identity.Alias, statement assess.Statement) bool {
	if statement.ProductKey == "" {
		return false
	}
	if statement.ProductKey == product.CanonicalKey {
		return true
	}
	for _, alias := range aliases {
		if alias.ProductID == product.ID && alias.Value == statement.ProductKey {
			return true
		}
	}
	return false
}

func currentStatements(statements []assess.Statement) []assess.Statement {
	latest := map[string]assess.Statement{}
	var legacy []assess.Statement
	for _, item := range statements {
		if item.SourceRecordID == "" {
			legacy = append(legacy, item)
			continue
		}
		key := item.Source + "\x00" + item.SourceRecordID
		previous, ok := latest[key]
		if !ok || item.ImportedAt.After(previous.ImportedAt) || (item.ImportedAt.Equal(previous.ImportedAt) && item.ID.String() > previous.ID.String()) {
			latest[key] = item
		}
	}
	out := append([]assess.Statement(nil), legacy...)
	for _, item := range latest {
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Source != out[j].Source {
			return out[i].Source < out[j].Source
		}
		if out[i].SourceRecordID != out[j].SourceRecordID {
			return out[i].SourceRecordID < out[j].SourceRecordID
		}
		return out[i].ID.String() < out[j].ID.String()
	})
	return out
}

func snapshotDigest(statements []assess.Statement) string {
	var buf bytes.Buffer
	for _, item := range statements {
		fmt.Fprintf(&buf, "%s\t%s\t%s\n", item.Source, item.SourceRecordID, item.RawRecordDigest)
	}
	sum := sha256.Sum256(buf.Bytes())
	return hex.EncodeToString(sum[:])
}

func snapshotSources(statements []assess.Statement) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, item := range statements {
		source := item.Source
		if source == "" {
			source = "local"
		}
		if _, ok := seen[source]; ok {
			continue
		}
		seen[source] = struct{}{}
		out = append(out, source)
	}
	sort.Strings(out)
	return out
}

func statementIDs(statements []assess.Statement) []id.ID {
	out := make([]id.ID, len(statements))
	for i, item := range statements {
		out[i] = item.ID
	}
	return out
}

func localStatement(statement assess.Statement, now time.Time) (assess.Statement, error) {
	if statement.VulnerabilityID == "" {
		return assess.Statement{}, fmt.Errorf("add statement: vulnerability id is required")
	}
	if statement.Severity != "" && !intel.ValidSeverity(statement.Severity) {
		return assess.Statement{}, fmt.Errorf("add statement: severity %s is not supported", statement.Severity)
	}
	if statement.Source == "" {
		statement.Source = "local"
	}
	if statement.NormalizationVersion == "" {
		statement.NormalizationVersion = intel.NormalizationVersion
	}
	if statement.ImportedAt.IsZero() {
		statement.ImportedAt = now
	}
	if statement.RawRecordDigest == "" {
		raw, err := json.Marshal(struct {
			VulnerabilityID string         `json:"vulnerability_id"`
			Ecosystem       string         `json:"ecosystem"`
			ProductKey      string         `json:"product_selector"`
			Ranges          []assess.Range `json:"affected_ranges"`
			Severity        string         `json:"severity"`
			KEV             bool           `json:"kev_status"`
		}{statement.VulnerabilityID, statement.Ecosystem, statement.ProductKey, statement.Ranges, statement.Severity, statement.KEV})
		if err != nil {
			return assess.Statement{}, err
		}
		sum := sha256.Sum256(raw)
		statement.RawRecordDigest = hex.EncodeToString(sum[:])
	}
	if statement.SourceRecordID == "" {
		statement.SourceRecordID = statement.RawRecordDigest
	}
	return statement, nil
}
