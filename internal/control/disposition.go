package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/zodirc/Vesper/internal/id"
)

const (
	DispositionAcceptRisk    = "accept_risk"
	DispositionSuppress      = "suppress"
	DispositionFalsePositive = "false_positive"
	DispositionException     = "exception"
	DispositionReopen        = "reopen"
	DispositionResolve       = "resolve"
)

var (
	// ErrFindingNotFound 表示处置指向的 Finding 不存在。
	// ErrFindingNotFound means the disposition refers to a finding that does not exist.
	ErrFindingNotFound = errors.New("finding not found")
	// ErrDispositionVerification 表示 resolve 没有晚于最近一次确认发生、且带有已校验证据的 not_vulnerable 检测结果。
	// ErrDispositionVerification means resolve lacks a not_vulnerable detection that is later than the latest confirming occurrence and cites verified evidence.
	ErrDispositionVerification = errors.New("resolve requires later not_vulnerable evidence")
	// ErrDispositionState 表示 reopen 作用在尚未被接受、抑制或解决的 Finding 上。
	// ErrDispositionState means reopen was applied to a finding that is not accepted, suppressed, or resolved.
	ErrDispositionState = errors.New("reopen requires an accepted, suppressed, or resolved finding")
	// ErrVerificationUnavailable 表示 Finding 没有可复测的发生记录、端点或配置操作。
	// ErrVerificationUnavailable means the finding has no occurrence, endpoint, or configuration operation that can be retested.
	ErrVerificationUnavailable = errors.New("verification subject is unavailable")
)

// DispositionInput 是一次处置请求。
// DispositionInput is one disposition request.
type DispositionInput struct {
	Type        string
	Reason      string
	Scope       json.RawMessage
	ValidFrom   *time.Time
	ValidUntil  *time.Time
	DetectionID id.ID
}

// Disposition 是一条追加的处置审计记录。它不改写检测结果和发生记录。
// Disposition is one appended disposition audit record. It does not rewrite detection results or occurrences.
type Disposition struct {
	ID         id.ID
	FindingID  id.ID
	Type       string
	Reason     string
	Scope      json.RawMessage
	CreatedBy  id.ID
	ApprovedBy id.ID
	ValidFrom  time.Time
	ValidUntil *time.Time
	CreatedAt  time.Time
}

// AddDisposition 追加一条处置，并按检测事实和当前仍有效的处置重算 Finding 状态。
// AddDisposition appends one disposition and recomputes the finding status from detection facts and dispositions that are still valid.
//
// findingID 必须存在。actor 是登录会话中的操作者。reason 不能为空白。
// type 只能是 accept_risk、suppress、false_positive、exception、reopen、resolve。
// validUntil 为空表示不设到期；有值时必须晚于 validFrom。scope 为空或 JSON 对象；数组、字符串和数字不接受。
// reopen 只接受当前投影为 accepted、suppressed、resolved 或 reopened 的 Finding。open 和 confirmed 上的 reopen 不写入。
// resolve 必须给出同一漏洞、同一主体上的 not_vulnerable 检测。该检测必须晚于最近一次确认发生，并且每条证据的完整性都是 verified。
// not_applicable、insufficient_evidence、unknown、conflict、execution_error 和 skipped 不能作为关闭依据。没有新的检测结果也不能关闭。
// 没有生效处置时，已有发生记录的状态是 confirmed，没有发生记录的状态是 open。
// approved_by 留空。设计没有规定独立于当前会话的审批步骤。
// findingID must exist. actor is the operator from the login session. reason must not be blank.
// type must be accept_risk, suppress, false_positive, exception, reopen, or resolve.
// An empty validUntil means the disposition does not expire. A value must be later than validFrom. scope is empty or a JSON object; arrays, strings, and numbers are rejected.
// reopen is accepted only when the current projection is accepted, suppressed, resolved, or reopened. A reopen on open or confirmed is not stored.
// resolve requires a not_vulnerable detection for the same vulnerability and subject. That detection must be later than the latest confirming occurrence, and every cited evidence record must have verified integrity.
// not_applicable, insufficient_evidence, unknown, conflict, execution_error, and skipped cannot close a finding. The absence of a new detection cannot close one either.
// With no disposition in effect, a finding that has an occurrence is confirmed, and a finding with no occurrence is open.
// approved_by stays empty. The design does not define an approval step separate from the current session.
//
// 成功时返回已保存的处置。Finding 不存在、输入不合法、当前状态不允许该处置或复核证据不足时返回错误，并且不写入处置。
// On success it returns the stored disposition. It returns an error and writes nothing when the finding does not exist, the input is invalid, the current status does not allow the disposition, or the verification evidence is insufficient.
func (s *Service) AddDisposition(findingID, actor id.ID, input DispositionInput) (Disposition, error) {
	record, err := normalizeDisposition(findingID, actor, input, s.now().UTC())
	if err != nil {
		return Disposition{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	err = s.commitState(context.Background(), func() error {
		finding := s.findingByID(findingID)
		if finding == nil {
			return ErrFindingNotFound
		}
		s.projectFinding(finding, s.now().UTC())
		if record.Type == DispositionReopen {
			switch finding.Status {
			case "accepted", "suppressed", "resolved", "reopened":
			default:
				return ErrDispositionState
			}
		}
		if record.Type == DispositionResolve {
			scope, verifyErr := s.verifiedResolve(finding, input.DetectionID, record.Scope)
			if verifyErr != nil {
				return verifyErr
			}
			record.Scope = scope
		}
		s.dispositions = append(s.dispositions, record)
		s.projectFinding(finding, s.now().UTC())
		return nil
	})
	if err != nil {
		return Disposition{}, err
	}
	return record, nil
}

// Dispositions 返回某个 Finding 的处置副本。记录保持追加顺序。
// Dispositions returns copies of one finding's dispositions. The records stay in append order.
func (s *Service) Dispositions(findingID id.ID) []Disposition {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Disposition
	for _, item := range s.dispositions {
		if item.FindingID == findingID {
			out = append(out, copyDisposition(item))
		}
	}
	return out
}

func normalizeDisposition(findingID, actor id.ID, input DispositionInput, now time.Time) (Disposition, error) {
	if findingID.IsZero() {
		return Disposition{}, ErrFindingNotFound
	}
	if actor.IsZero() {
		return Disposition{}, fmt.Errorf("add disposition: actor is empty")
	}
	reason := strings.TrimSpace(input.Reason)
	if reason == "" {
		return Disposition{}, fmt.Errorf("add disposition: reason is empty")
	}
	switch input.Type {
	case DispositionAcceptRisk, DispositionSuppress, DispositionFalsePositive, DispositionException, DispositionReopen, DispositionResolve:
	default:
		return Disposition{}, fmt.Errorf("add disposition: type %q", input.Type)
	}
	validFrom := now
	if input.ValidFrom != nil {
		validFrom = input.ValidFrom.UTC()
	}
	var validUntil *time.Time
	if input.ValidUntil != nil {
		until := input.ValidUntil.UTC()
		if !until.After(validFrom) {
			return Disposition{}, fmt.Errorf("add disposition: valid_until is not after valid_from")
		}
		validUntil = &until
	}
	var scope json.RawMessage
	trimmed := bytesTrim(input.Scope)
	if len(trimmed) > 0 && string(trimmed) != "null" {
		if !json.Valid(trimmed) {
			return Disposition{}, fmt.Errorf("add disposition: scope is not json")
		}
		var object map[string]json.RawMessage
		if err := json.Unmarshal(trimmed, &object); err != nil {
			return Disposition{}, fmt.Errorf("add disposition: scope must be an object")
		}
		scope = append(json.RawMessage(nil), trimmed...)
	}
	recordID, err := id.New()
	if err != nil {
		return Disposition{}, err
	}
	return Disposition{
		ID: recordID, FindingID: findingID, Type: input.Type, Reason: reason, Scope: scope,
		CreatedBy: actor, ValidFrom: validFrom, ValidUntil: validUntil, CreatedAt: now,
	}, nil
}

func (s *Service) verifiedResolve(finding *Finding, detectionID id.ID, scope json.RawMessage) (json.RawMessage, error) {
	if detectionID.IsZero() {
		return nil, ErrDispositionVerification
	}
	var detection *Detection
	for i := range s.detections {
		if s.detections[i].ID == detectionID {
			detection = &s.detections[i]
			break
		}
	}
	if detection == nil || detection.ResultStatus != "not_vulnerable" || detection.VulnerabilityID != finding.VulnerabilityID || !sameFindingSubject(finding, detection) {
		return nil, ErrDispositionVerification
	}
	var latest *Occurrence
	for i := range s.occurrences {
		item := &s.occurrences[i]
		if item.FindingID != finding.ID {
			continue
		}
		if latest == nil || item.ObservedAt.After(latest.ObservedAt) {
			latest = item
		}
	}
	if latest == nil || detection.ID == latest.DetectionID || !detection.EvaluatedAt.After(latest.ObservedAt) {
		return nil, ErrDispositionVerification
	}
	if len(detection.EvidenceIDs) == 0 {
		return nil, ErrDispositionVerification
	}
	verified := map[id.ID]struct{}{}
	for _, row := range s.evidenceRows {
		if row.IntegrityStatus == "verified" {
			verified[row.ID] = struct{}{}
		}
	}
	for _, evidenceID := range detection.EvidenceIDs {
		if _, ok := verified[evidenceID]; !ok {
			return nil, ErrDispositionVerification
		}
	}
	payload := map[string]any{}
	if len(scope) > 0 {
		if err := json.Unmarshal(scope, &payload); err != nil {
			return nil, fmt.Errorf("add disposition: resolve scope must be an object")
		}
	}
	payload["verification_detection_id"] = detectionID.String()
	encoded, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	return encoded, nil
}

func sameFindingSubject(finding *Finding, detection *Detection) bool {
	if !finding.EndpointID.IsZero() {
		return detection.EndpointID == finding.EndpointID || (detection.SubjectType == "endpoint" && detection.SubjectID == finding.EndpointID)
	}
	if !finding.AssetID.IsZero() {
		return detection.SubjectType == "asset" && detection.SubjectID == finding.AssetID
	}
	return false
}

func (s *Service) findingByID(findingID id.ID) *Finding {
	for _, item := range s.findings {
		if item.ID == findingID {
			return item
		}
	}
	return nil
}

func (s *Service) projectFindings(now time.Time) {
	for _, item := range s.findings {
		s.projectFinding(item, now)
	}
}

func (s *Service) projectFinding(finding *Finding, now time.Time) {
	now = now.UTC()
	var winner *Disposition
	for i := range s.dispositions {
		item := &s.dispositions[i]
		if item.FindingID != finding.ID || item.ValidFrom.After(now) {
			continue
		}
		if item.ValidUntil != nil && !now.Before(item.ValidUntil.UTC()) {
			continue
		}
		if winner == nil || !item.CreatedAt.Before(winner.CreatedAt) {
			winner = item
		}
	}
	finding.ResolvedAt = nil
	finding.ActiveDispositionID = id.ID{}
	finding.ActiveDispositionType = ""
	if winner == nil {
		finding.Status = "open"
		if hasOccurrence(s.occurrences, finding.ID) {
			finding.Status = "confirmed"
		}
		return
	}
	finding.ActiveDispositionID = winner.ID
	finding.ActiveDispositionType = winner.Type
	if winner.Type == DispositionResolve && occurrenceAfter(s.occurrences, finding.ID, winner.ValidFrom) {
		finding.Status = "reopened"
		return
	}
	switch winner.Type {
	case DispositionAcceptRisk, DispositionException:
		finding.Status = "accepted"
	case DispositionSuppress, DispositionFalsePositive:
		finding.Status = "suppressed"
	case DispositionReopen:
		finding.Status = "reopened"
	case DispositionResolve:
		finding.Status = "resolved"
		at := winner.ValidFrom
		finding.ResolvedAt = &at
	default:
		finding.Status = "open"
	}
}

func hasOccurrence(items []Occurrence, findingID id.ID) bool {
	for _, item := range items {
		if item.FindingID == findingID {
			return true
		}
	}
	return false
}

func latestOccurrence(items []Occurrence, findingID id.ID) *Occurrence {
	var latest *Occurrence
	for i := range items {
		item := &items[i]
		if item.FindingID != findingID {
			continue
		}
		if latest == nil || item.ObservedAt.After(latest.ObservedAt) {
			latest = item
		}
	}
	return latest
}

func occurrenceAfter(occurrences []Occurrence, findingID id.ID, at time.Time) bool {
	for _, item := range occurrences {
		if item.FindingID == findingID && item.ObservedAt.After(at) {
			return true
		}
	}
	return false
}

func copyDisposition(item Disposition) Disposition {
	item.Scope = append(json.RawMessage(nil), item.Scope...)
	if item.ValidUntil != nil {
		until := item.ValidUntil.UTC()
		item.ValidUntil = &until
	}
	return item
}

func bytesTrim(raw []byte) []byte {
	return []byte(strings.TrimSpace(string(raw)))
}
