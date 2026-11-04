package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"

	"github.com/zodirc/Vesper/internal/activedetect"
	"github.com/zodirc/Vesper/internal/id"
	"github.com/zodirc/Vesper/internal/rule"
	"github.com/zodirc/Vesper/internal/scope"
	"github.com/zodirc/Vesper/internal/task"
	"github.com/zodirc/Vesper/pkg/probesdk"
)

type activeTemplate struct {
	ID           id.ID
	PackID       id.ID
	Key          string
	Name         string
	Severity     string
	CVE          string
	Digest       string
	RequestBound int
	Body         []byte
	Enabled      bool
}

type frozenTemplate struct {
	ID           string `json:"id"`
	Key          string `json:"key"`
	Name         string `json:"name"`
	Severity     string `json:"severity"`
	CVE          string `json:"cve_id,omitempty"`
	Digest       string `json:"digest"`
	RequestBound int    `json:"request_bound"`
}

type activeInput struct {
	Address  string         `json:"address"`
	Port     int            `json:"port"`
	Hostname string         `json:"hostname"`
	Template frozenTemplate `json:"template"`
}

// ActiveTemplate 是控制面保存的一份主动检测模板。
// ActiveTemplate is one active-detection template stored by the control plane.
type ActiveTemplate struct {
	ID           id.ID
	Key          string
	Name         string
	Severity     string
	CVE          string
	Digest       string
	RequestBound int
	Status       string
	Enabled      bool
}

var runActiveDetection = activedetect.Execute

var activeReady = func() error {
	if activedetect.Availability() != "available" {
		return activedetect.ErrIsolation
	}
	_, err := activedetect.Binary()
	return err
}

// ImportActiveTemplate 校验并保存一份模板。相同摘要再次导入时返回已有记录，不改写正文。
// ImportActiveTemplate validates and stores one template. Importing the same digest again returns the existing record and does not rewrite the body.
func (s *Service) ImportActiveTemplate(ctx context.Context, body []byte) (ActiveTemplate, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	admitted, err := activedetect.Admit(body)
	if err != nil {
		return ActiveTemplate{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, item := range s.active {
		if item.Digest == admitted.Digest {
			return s.publicTemplate(item), nil
		}
	}
	templateID, err := id.New()
	if err != nil {
		return ActiveTemplate{}, err
	}
	packID, err := id.New()
	if err != nil {
		return ActiveTemplate{}, err
	}
	now := s.now().UTC()
	item := activeTemplate{
		ID: templateID, PackID: packID, Key: admitted.Key, Name: admitted.Name, Severity: admitted.Severity,
		CVE: admitted.CVE, Digest: admitted.Digest, RequestBound: admitted.RequestBound, Body: admitted.Body,
	}
	pack := rule.Pack{
		ID: packID, Type: "active_detection", Version: admitted.Digest, ContentDigest: admitted.Digest,
		SchemaVersion: rule.SchemaVersion, Source: "nuclei", Status: "validated", CreatedAt: now,
		License: json.RawMessage(`{}`), Compatibility: json.RawMessage(`{}`),
	}
	if err := s.commitState(ctx, func() error {
		s.packs = append(s.packs, pack)
		s.active = append(s.active, item)
		return nil
	}); err != nil {
		return ActiveTemplate{}, err
	}
	return s.publicTemplate(item), nil
}

// PublishActiveTemplate 把已通过结构校验的模板标为已发布并允许新扫描选用。
// PublishActiveTemplate marks a structurally valid template published and selectable by new scans.
func (s *Service) PublishActiveTemplate(ctx context.Context, templateID id.ID) (ActiveTemplate, error) {
	return s.setTemplateState(ctx, templateID, true)
}

// DisableActiveTemplate 停止新扫描选用这份模板。已经冻结的扫描仍使用当时的副本，复核仍可按规则标识执行。
// DisableActiveTemplate stops new scans from selecting this template. A scan that already froze it keeps that copy, and verification can still run it by rule identifier.
func (s *Service) DisableActiveTemplate(ctx context.Context, templateID id.ID) (ActiveTemplate, error) {
	return s.setTemplateState(ctx, templateID, false)
}

func (s *Service) setTemplateState(ctx context.Context, templateID id.ID, publish bool) (ActiveTemplate, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	index := -1
	for i := range s.active {
		if s.active[i].ID == templateID {
			index = i
			break
		}
	}
	if index < 0 {
		return ActiveTemplate{}, fmt.Errorf("active template %s: not found", templateID)
	}
	var published ActiveTemplate
	err := s.commitState(ctx, func() error {
		for i := range s.packs {
			if s.packs[i].ID != s.active[index].PackID {
				continue
			}
			if publish {
				if s.packs[i].Status != "validated" && s.packs[i].Status != "published" {
					return fmt.Errorf("active template %s: status %s", templateID, s.packs[i].Status)
				}
				now := s.now().UTC()
				s.packs[i].Status = "published"
				if s.packs[i].PublishedAt == nil {
					s.packs[i].PublishedAt = &now
				}
				s.active[index].Enabled = true
			} else {
				s.active[index].Enabled = false
			}
			published = s.publicTemplate(s.active[index])
			return nil
		}
		return fmt.Errorf("active template %s: pack not found", templateID)
	})
	if err != nil {
		return ActiveTemplate{}, err
	}
	return published, nil
}

// ActiveTemplates 返回模板元数据副本，不返回模板正文。
// ActiveTemplates returns copies of template metadata and does not return template bodies.
func (s *Service) ActiveTemplates() []ActiveTemplate {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]ActiveTemplate, 0, len(s.active))
	for _, item := range s.active {
		out = append(out, s.publicTemplate(item))
	}
	return out
}

func (s *Service) publicTemplate(item activeTemplate) ActiveTemplate {
	status := "validated"
	for _, pack := range s.packs {
		if pack.ID == item.PackID {
			status = pack.Status
			break
		}
	}
	return ActiveTemplate{
		ID: item.ID, Key: item.Key, Name: item.Name, Severity: item.Severity, CVE: item.CVE,
		Digest: item.Digest, RequestBound: item.RequestBound, Status: status, Enabled: item.Enabled,
	}
}

func (s *Service) selectActiveTemplates(grant scope.Grant, verification bool, ruleID id.ID) ([]frozenTemplate, error) {
	if verification {
		if ruleID.IsZero() {
			return nil, nil
		}
		item, ok := s.findActive(ruleID)
		if !ok || !s.packPublished(item.PackID) {
			return nil, nil
		}
		if !containsOperation(grant, scope.OpActiveCheck) {
			return nil, planFailure{summary: "operation_denied"}
		}
		return []frozenTemplate{freezeTemplate(item)}, nil
	}
	if !containsOperation(grant, scope.OpActiveCheck) {
		return nil, nil
	}
	var out []frozenTemplate
	for _, item := range s.active {
		if !item.Enabled || !s.packPublished(item.PackID) {
			continue
		}
		out = append(out, freezeTemplate(item))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}

func (s *Service) findActive(templateID id.ID) (activeTemplate, bool) {
	for _, item := range s.active {
		if item.ID == templateID {
			return item, true
		}
	}
	return activeTemplate{}, false
}

func (s *Service) packPublished(packID id.ID) bool {
	for _, pack := range s.packs {
		if pack.ID == packID {
			return pack.Status == "published"
		}
	}
	return false
}

func freezeTemplate(item activeTemplate) frozenTemplate {
	return frozenTemplate{
		ID: item.ID.String(), Key: item.Key, Name: item.Name, Severity: item.Severity, CVE: item.CVE,
		Digest: item.Digest, RequestBound: item.RequestBound,
	}
}

func (s *Service) scheduleActiveDetection(lease task.Lease, addr netip.Addr, port int, hostname string) error {
	run, _, err := s.tasks.Snapshot(lease.RunID)
	if err != nil {
		return err
	}
	var plan planBody
	if err := json.Unmarshal(run.Plan, &plan); err != nil {
		return err
	}
	for _, template := range plan.ActiveTemplates {
		payload, err := json.Marshal(activeInput{Address: addr.String(), Port: port, Hostname: hostname, Template: template})
		if err != nil {
			return err
		}
		unit := task.Unit{
			ScanRunID: lease.RunID, TargetID: lease.TargetID, ObservationPointID: lease.ObservationPointID,
			UnitType: "active_detection", StageKey: fmt.Sprintf("active_detection:%s:%d:%s", addr.String(), port, template.ID),
			DependsOn: []id.ID{lease.UnitID}, RequiredCapabilities: []string{"active_detection"}, Input: payload, Priority: 3, CreatedAt: s.now(),
		}
		if err := s.tasks.AddUnit(unit); err != nil && !errors.Is(err, task.ErrDuplicateStage) {
			return err
		}
	}
	return nil
}

func (s *Service) executeActive(ctx context.Context, lease task.Lease, account *scope.Account) error {
	var input activeInput
	if err := json.Unmarshal(lease.Input, &input); err != nil {
		return err
	}
	addr, err := netip.ParseAddr(input.Address)
	if err != nil {
		return err
	}
	templateID, err := id.Parse(input.Template.ID)
	if err != nil {
		return err
	}
	s.mu.Lock()
	grant, granted := s.frozen[lease.RunID]
	stored, ok := s.findActive(templateID)
	endpointID := s.endpointID(addr, input.Port)
	observationID := s.httpObservation(lease.RunID, endpointID)
	s.mu.Unlock()
	if !granted || !ok || stored.Digest != input.Template.Digest || stored.RequestBound != input.Template.RequestBound {
		return s.finishActive(ctx, lease, endpointID, observationID, input.Template, "conflict", "", nil, "frozen template does not match the stored body")
	}
	decision := grant.Check(scope.CheckInput{
		IP: addr, Hostname: input.Hostname, Port: input.Port, Transport: "tcp", Operation: scope.OpActiveCheck,
		ObservationPointID: lease.ObservationPointID, Now: s.now(),
	})
	if !decision.Allowed {
		return s.finishActive(ctx, lease, endpointID, observationID, input.Template, "skipped", "", nil, decision.Code)
	}
	if err := activeReady(); err != nil {
		return s.finishActive(ctx, lease, endpointID, observationID, input.Template, "skipped", "", nil, err.Error())
	}
	if err := s.reserveActive(ctx, lease, account, input.Template.RequestBound); err != nil {
		return err
	}
	output, err := runActiveDetection(ctx, activedetect.Policy{AllowedIP: addr, AllowedPort: input.Port}, input.Hostname, int(grant.MaxRatePerSecond), []activedetect.Template{{
		Key: stored.Key, Name: stored.Name, Severity: stored.Severity, CVE: stored.CVE, RequestBound: stored.RequestBound,
		Digest: stored.Digest, Body: stored.Body,
	}})
	if err != nil {
		if errors.Is(err, activedetect.ErrNotStarted) || errors.Is(err, activedetect.ErrIsolation) || errors.Is(err, activedetect.ErrExecutorMissing) {
			s.releaseActive(account, input.Template.RequestBound)
			status := "skipped"
			if errors.Is(err, activedetect.ErrNotStarted) {
				status = "execution_error"
			}
			return s.finishActive(ctx, lease, endpointID, observationID, input.Template, status, "", output, err.Error())
		}
		return s.finishActive(ctx, lease, endpointID, observationID, input.Template, "execution_error", "", output, err.Error())
	}
	verdict, err := activedetect.ParseOutput(output, stored.Key, addr, input.Port, input.Hostname)
	if err != nil {
		return s.finishActive(ctx, lease, endpointID, observationID, input.Template, "execution_error", "", output, err.Error())
	}
	return s.finishActive(ctx, lease, endpointID, observationID, input.Template, verdict.Status, verdict.MatchedAt, output, "")
}

func (s *Service) reserveActive(ctx context.Context, lease task.Lease, account *scope.Account, count int) error {
	for i := 0; i < count; i++ {
		if err := func() error {
			s.mu.Lock()
			defer s.mu.Unlock()
			if err := s.commitState(ctx, func() error { return s.tasks.Renew(lease, s.now()) }); err != nil {
				return err
			}
			run, _, err := s.tasks.Snapshot(lease.RunID)
			if err != nil {
				return err
			}
			if run.Status == task.RunCancelling || run.Status == task.RunCancelled {
				return context.Canceled
			}
			return account.AcquireRequest(ctx, s.now())
		}(); err != nil {
			s.releaseActive(account, i)
			if errors.Is(err, context.Canceled) {
				return err
			}
			var budget *scope.BudgetError
			if errors.As(err, &budget) {
				return &probesdk.Error{Class: probesdk.ClassBudget, Message: err.Error()}
			}
			return err
		}
	}
	if err := s.persistBudget(ctx, lease.RunID); err != nil {
		s.releaseActive(account, count)
		return err
	}
	return nil
}

func (s *Service) releaseActive(account *scope.Account, count int) {
	for i := 0; i < count; i++ {
		account.ReleaseReservation(false)
	}
}

func (s *Service) finishActive(ctx context.Context, lease task.Lease, endpointID, observationID id.ID, template frozenTemplate, status, matchedAt string, output []byte, summary string) error {
	var evidenceIDs []id.ID
	var record *EvidenceRecord
	if len(output) > 0 {
		if err := s.accounts[lease.RunID].TryEvidence(int64(len(output))); err != nil {
			return &probesdk.Error{Class: probesdk.ClassBudget, Message: err.Error()}
		}
		object, err := s.evidence.Put(s.now(), output)
		if err != nil {
			return &probesdk.Error{Class: probesdk.ClassEvidence, Message: err.Error()}
		}
		evidenceID, err := id.New()
		if err != nil {
			return err
		}
		storedAt := s.now().UTC()
		record = &EvidenceRecord{
			ID: evidenceID, EvidenceType: "tool_output", StorageKey: object.StorageKey, SizeBytes: object.SizeBytes,
			DigestAlgorithm: object.DigestAlgorithm, ContentDigest: object.ContentDigest, ContentType: "application/x-ndjson",
			ContentEncoding: "identity", SourceModule: "nuclei", SourceAttemptID: lease.AttemptID, IntegrityStatus: "verified",
			Sensitivity: "internal", CapturedAt: storedAt, StoredAt: &storedAt,
		}
		evidenceIDs = []id.ID{evidenceID}
	}
	if summary == "" {
		summary = template.Name
	}
	vulnerabilityID := template.Key
	if template.CVE != "" {
		vulnerabilityID = template.CVE
	}
	matched, err := json.Marshal(map[string]any{"template_id": template.Key, "matched_at": matchedAt, "request_bound": template.RequestBound})
	if err != nil {
		return err
	}
	var unmatched json.RawMessage
	if status != "confirmed" {
		raw, err := json.Marshal(map[string]string{"result": status, "summary": summary})
		if err != nil {
			return err
		}
		unmatched = raw
	}
	ruleID, err := id.Parse(template.ID)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if record != nil {
		s.evidenceRows = append(s.evidenceRows, *record)
	}
	assessmentID, err := id.New()
	if err != nil {
		return err
	}
	detectionID, err := id.New()
	if err != nil {
		return err
	}
	var inputs []id.ID
	if !observationID.IsZero() {
		inputs = []id.ID{observationID}
	}
	s.detections = append(s.detections, Detection{
		ID: detectionID, AssessmentRunID: assessmentID, EndpointID: endpointID, Executor: "nuclei",
		SubjectType: "endpoint", SubjectID: endpointID, RuleID: ruleID, RuleVersion: template.Digest,
		VulnerabilityID: vulnerabilityID, ResultStatus: status, Severity: template.Severity, Summary: summary,
		Matched: matched, Unmatched: unmatched, EvidenceIDs: evidenceIDs, InputObservationIDs: inputs, EvaluatedAt: s.now(),
	})
	if status == "confirmed" && len(evidenceIDs) > 0 {
		s.mergeFinding(endpointID, id.ID{}, vulnerabilityID, detectionID, assessmentID, template.Digest, "vulnerability", findingSeverity(template.Severity), evidenceIDs, ruleID, id.ID{})
		if finding := s.findings[endpointID.String()+"|"+vulnerabilityID]; finding != nil && template.Name != "" {
			finding.Title = template.Name
		}
	}
	return s.flush(ctx)
}

func findingSeverity(severity string) string {
	switch severity {
	case "low", "medium", "high", "critical":
		return severity
	default:
		return ""
	}
}

func (s *Service) endpointID(addr netip.Addr, port int) id.ID {
	for _, endpoint := range s.catalog.Endpoints {
		if endpoint.Address == addr && endpoint.Port == port && endpoint.Transport == "tcp" {
			return endpoint.ID
		}
	}
	return id.ID{}
}

func (s *Service) httpObservation(runID, endpointID id.ID) id.ID {
	if endpointID.IsZero() {
		return id.ID{}
	}
	for _, item := range s.observations {
		if item.ScanRunID == runID && item.EndpointID != nil && *item.EndpointID == endpointID && item.Type == "protocol_response" {
			if protocol, _ := item.Value["protocol"].(string); protocol == "http" {
				return item.ID
			}
		}
	}
	return id.ID{}
}
