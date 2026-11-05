// Package api 提供本机 HTTP 管理入口。处理函数只创建任务和读取结果，不在请求路径中执行探测。
// Package api provides the local HTTP management entry. Handlers only create tasks and read results; they do not run probes on the request path.
package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/zodirc/Vesper/internal/activedetect"
	"github.com/zodirc/Vesper/internal/configrule"
	"github.com/zodirc/Vesper/internal/control"
	"github.com/zodirc/Vesper/internal/id"
	"github.com/zodirc/Vesper/internal/identity"
	"github.com/zodirc/Vesper/internal/nmapfinger"
	"github.com/zodirc/Vesper/internal/scope"
)

// Server 是带会话认证的管理 API。
// Server is the management API with session authentication.
//
// 同一个 Server 的登录会话共用服务保存的管理员标识。创建、审批、撤销和处置写入这个标识。
// Login sessions on one Server share the administrator identifier stored by the service. Grant creation, approval, revocation, and disposition write that identifier.
//
// 配置了数据库时，Restore 从数据库装入未到期会话。会话写入失败时不会把令牌交给调用方。
// When a database is configured, Restore loads unexpired sessions from it. A failed session write does not hand the token to the caller.
type Server struct {
	Service  *control.Service
	User     string
	Password string
	Now      func() time.Time
	mu       sync.Mutex
	sessions map[string]session
}

const sessionLifetime = 12 * time.Hour

type session struct {
	UserID  id.ID
	Expires time.Time
}

type actorContextKey struct{}

// Restore 从数据库装入未到期会话。vesperd 在开始监听前调用。
// Restore loads unexpired sessions from the database. vesperd calls it before listening.
//
// 没有数据库时会话索引为空。已经到期的数据库会话在装入时删除。
// Without a database the session index is empty. Expired database sessions are deleted during the load.
func (s *Server) Restore(ctx context.Context) error {
	s.prepare()
	loaded, err := s.Service.RestoreAPISessions(ctx, s.Now())
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions = map[string]session{}
	for _, item := range loaded {
		s.sessions[item.Token.String()] = session{UserID: item.PrincipalID, Expires: item.ExpiresAt}
	}
	return nil
}

func (s *Server) prepare() {
	if s.Now == nil {
		s.Now = func() time.Time { return time.Now().UTC() }
	}
	s.mu.Lock()
	if s.sessions == nil {
		s.sessions = map[string]session{}
	}
	s.mu.Unlock()
}

// Handler 返回管理路由。
// Handler returns the management routes.
func (s *Server) Handler() http.Handler {
	s.prepare()
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/sessions", s.createSession)
	mux.HandleFunc("DELETE /api/v1/sessions", s.authenticated(s.deleteSession))
	mux.HandleFunc("GET /api/v1/observation-points", s.authenticated(s.observationPoints))
	mux.HandleFunc("GET /api/v1/grants", s.authenticated(s.listGrants))
	mux.HandleFunc("GET /api/v1/grants/{id}/revisions", s.authenticated(s.listGrantRevisions))
	mux.HandleFunc("POST /api/v1/grants", s.authenticated(s.createGrant))
	mux.HandleFunc("POST /api/v1/grants/{id}/approve", s.authenticated(s.approveGrant))
	mux.HandleFunc("POST /api/v1/grants/{id}/revoke", s.authenticated(s.revokeGrant))
	mux.HandleFunc("GET /api/v1/scan-runs", s.authenticated(s.listScans))
	mux.HandleFunc("POST /api/v1/scan-runs", s.authenticated(s.createScan))
	mux.HandleFunc("GET /api/v1/scan-runs/{id}", s.authenticated(s.getScan))
	mux.HandleFunc("POST /api/v1/scan-runs/{id}/cancel", s.authenticated(s.cancelScan))
	mux.HandleFunc("GET /api/v1/scan-runs/{id}/observations", s.authenticated(s.listObservations))
	mux.HandleFunc("GET /api/v1/scan-schedules", s.authenticated(s.listSchedules))
	mux.HandleFunc("POST /api/v1/scan-schedules", s.authenticated(s.createSchedule))
	mux.HandleFunc("POST /api/v1/scan-schedules/{id}/disable", s.authenticated(s.disableSchedule))
	mux.HandleFunc("POST /api/v1/scan-schedules/{id}/enable", s.authenticated(s.enableSchedule))
	mux.HandleFunc("GET /api/v1/assets", s.authenticated(s.listAssets))
	mux.HandleFunc("GET /api/v1/endpoints", s.authenticated(s.listEndpoints))
	mux.HandleFunc("GET /api/v1/targets", s.authenticated(s.listTargets))
	mux.HandleFunc("GET /api/v1/hypotheses", s.authenticated(s.listHypotheses))
	mux.HandleFunc("GET /api/v1/findings", s.authenticated(s.listFindings))
	mux.HandleFunc("GET /api/v1/findings/{id}/dispositions", s.authenticated(s.listDispositions))
	mux.HandleFunc("POST /api/v1/findings/{id}/dispositions", s.authenticated(s.createDisposition))
	mux.HandleFunc("POST /api/v1/findings/{id}/verification", s.authenticated(s.createVerification))
	mux.HandleFunc("POST /api/v1/fingerprint-packs", s.authenticated(s.importFingerprintPack))
	mux.HandleFunc("GET /api/v1/fingerprint-packs", s.authenticated(s.listFingerprintPacks))
	mux.HandleFunc("POST /api/v1/fingerprint-packs/{id}/publish", s.authenticated(s.publishFingerprintPack))
	mux.HandleFunc("POST /api/v1/fingerprint-packs/{id}/deprecate", s.authenticated(s.deprecateFingerprintPack))
	mux.HandleFunc("POST /api/v1/config-packs", s.authenticated(s.importConfigPack))
	mux.HandleFunc("GET /api/v1/config-packs", s.authenticated(s.listConfigPacks))
	mux.HandleFunc("POST /api/v1/config-packs/{id}/publish", s.authenticated(s.publishConfigPack))
	mux.HandleFunc("POST /api/v1/config-packs/{id}/deprecate", s.authenticated(s.deprecateConfigPack))
	mux.HandleFunc("POST /api/v1/active-templates", s.authenticated(s.importActiveTemplate))
	mux.HandleFunc("GET /api/v1/active-templates", s.authenticated(s.listActiveTemplates))
	mux.HandleFunc("POST /api/v1/active-templates/{id}/publish", s.authenticated(s.publishActiveTemplate))
	mux.HandleFunc("POST /api/v1/active-templates/{id}/disable", s.authenticated(s.disableActiveTemplate))
	mux.HandleFunc("POST /api/v1/intel/imports", s.authenticated(s.importIntel))
	mux.HandleFunc("GET /api/v1/intel/feeds", s.authenticated(s.listFeeds))
	mux.HandleFunc("POST /api/v1/intel/feeds/{source}/sync", s.authenticated(s.syncFeed))
	mux.HandleFunc("GET /api/v1/intel/snapshots", s.authenticated(s.listIntelSnapshots))
	mux.HandleFunc("POST /api/v1/intel/snapshots/{id}/reassess", s.authenticated(s.reassessIntel))
	mux.Handle("GET /", s.userInterface())
	return mux
}

func (s *Server) createSession(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body", err.Error())
		return
	}
	userOK := subtle.ConstantTimeCompare([]byte(body.Username), []byte(s.User)) == 1
	passOK := subtle.ConstantTimeCompare([]byte(body.Password), []byte(s.Password)) == 1
	if !userOK || !passOK {
		writeError(w, http.StatusUnauthorized, "authentication_failed", "authentication failed")
		return
	}
	token, err := id.New()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "session_error", err.Error())
		return
	}
	expires := s.Now().Add(sessionLifetime)
	item := session{UserID: s.Service.PrincipalID(), Expires: expires}
	if err := s.commitSession(token.String(), item, func() error {
		return s.Service.StoreAPISession(r.Context(), control.APISession{Token: token, PrincipalID: item.UserID, ExpiresAt: expires}, s.Now())
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "session_error", err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"token": token.String(), "expires_at": expires})
}

// commitSession 先持久化会话，成功后再放入进程内索引。
// commitSession persists a session first and adds it to the in-process index only after that succeeds.
func (s *Server) commitSession(token string, item session, persist func() error) error {
	if err := persist(); err != nil {
		return err
	}
	s.mu.Lock()
	s.sessions[token] = item
	s.mu.Unlock()
	return nil
}

func (s *Server) authenticated(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		s.mu.Lock()
		item, ok := s.sessions[token]
		s.mu.Unlock()
		if ok && !item.Expires.After(s.Now()) {
			parsed, err := id.Parse(token)
			if err != nil {
				writeError(w, http.StatusUnauthorized, "authentication_required", "authentication required")
				return
			}
			if err := s.Service.DropAPISession(r.Context(), parsed); err != nil {
				writeError(w, http.StatusInternalServerError, "session_error", err.Error())
				return
			}
			s.mu.Lock()
			delete(s.sessions, token)
			s.mu.Unlock()
			ok = false
		}
		if !ok {
			writeError(w, http.StatusUnauthorized, "authentication_required", "authentication required")
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), actorContextKey{}, item.UserID)))
	}
}

func actorFrom(r *http.Request) (id.ID, bool) {
	actor, ok := r.Context().Value(actorContextKey{}).(id.ID)
	return actor, ok && !actor.IsZero()
}

func (s *Server) deleteSession(w http.ResponseWriter, r *http.Request) {
	tokenText := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	token, err := id.Parse(tokenText)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "authentication_required", "authentication required")
		return
	}
	if err := s.Service.DropAPISession(r.Context(), token); err != nil {
		writeError(w, http.StatusInternalServerError, "session_error", err.Error())
		return
	}
	s.mu.Lock()
	delete(s.sessions, tokenText)
	s.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listGrants(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"grants": s.Service.Grants()})
}

func (s *Server) listGrantRevisions(w http.ResponseWriter, r *http.Request) {
	grantID, err := id.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", err.Error())
		return
	}
	if _, err := s.Service.Grant(grantID); err != nil {
		writeError(w, http.StatusNotFound, "not_found", err.Error())
		return
	}
	revisions := s.Service.Revisions(grantID)
	if revisions == nil {
		revisions = []control.Revision{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"revisions": revisions})
}

func (s *Server) listScans(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"scan_runs": s.Service.Runs()})
}

func (s *Server) listAssets(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"assets": s.Service.Assets()})
}

func (s *Server) listEndpoints(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"endpoints": s.Service.Endpoints()})
}

func (s *Server) listTargets(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"targets": s.Service.Targets()})
}

func (s *Server) listHypotheses(w http.ResponseWriter, r *http.Request) {
	items := s.Service.Hypotheses()
	if items == nil {
		items = []identity.Hypothesis{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"hypotheses": items})
}

func (s *Server) observationPoints(w http.ResponseWriter, r *http.Request) {
	point := s.Service.ObservationPointView()
	writeJSON(w, http.StatusOK, map[string]any{"observation_points": []map[string]any{{
		"id": point.ID.String(), "node_type": point.NodeType, "platform": point.Platform, "architecture": point.Architecture,
		"network_interfaces": point.Interfaces, "capability_snapshot_id": point.CapabilitySnapshotID.String(),
		"location_label": point.LocationLabel, "capabilities": point.Capabilities, "privileges": point.Privileges,
		"network_isolation": point.NetworkIsolation, "probe_compatibility": point.ProbeCompatibility,
	}}})
}

func (s *Server) createGrant(w http.ResponseWriter, r *http.Request) {
	var body control.GrantInput
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body", err.Error())
		return
	}
	actor, ok := actorFrom(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "authentication_required", "authentication required")
		return
	}
	grant, err := s.Service.CreateGrant(body, actor)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_grant", err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"id": grant.ID.String(), "status": grant.Status})
}

func (s *Server) approveGrant(w http.ResponseWriter, r *http.Request) {
	grantID, err := id.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", err.Error())
		return
	}
	actor, ok := actorFrom(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "authentication_required", "authentication required")
		return
	}
	if err := s.Service.ApproveGrant(grantID, actor); err != nil {
		writeError(w, http.StatusConflict, "approve_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": scope.StatusActive})
}

func (s *Server) revokeGrant(w http.ResponseWriter, r *http.Request) {
	actor, ok := actorFrom(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "authentication_required", "authentication required")
		return
	}
	grantID, err := id.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", err.Error())
		return
	}
	var body struct {
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body", err.Error())
		return
	}
	if strings.TrimSpace(body.Reason) == "" {
		writeError(w, http.StatusBadRequest, "invalid_body", "revoke reason is empty")
		return
	}
	if err := s.Service.RevokeGrant(grantID, actor, body.Reason); err != nil {
		writeError(w, http.StatusConflict, "revoke_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": scope.StatusRevoked})
}

func (s *Server) listSchedules(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"scan_schedules": s.Service.Schedules()})
}

func (s *Server) createSchedule(w http.ResponseWriter, r *http.Request) {
	var body control.ScheduleInput
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body", err.Error())
		return
	}
	item, err := s.Service.CreateSchedule(r.Context(), body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "schedule_rejected", err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, item)
}

func (s *Server) disableSchedule(w http.ResponseWriter, r *http.Request) {
	s.setSchedule(w, r, false)
}

func (s *Server) enableSchedule(w http.ResponseWriter, r *http.Request) {
	s.setSchedule(w, r, true)
}

func (s *Server) setSchedule(w http.ResponseWriter, r *http.Request, enabled bool) {
	scheduleID, err := id.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", err.Error())
		return
	}
	var item control.Schedule
	if enabled {
		item, err = s.Service.EnableSchedule(r.Context(), scheduleID)
	} else {
		item, err = s.Service.DisableSchedule(r.Context(), scheduleID)
	}
	if errors.Is(err, control.ErrScheduleNotFound) {
		writeError(w, http.StatusNotFound, "not_found", err.Error())
		return
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, "schedule_rejected", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) createScan(w http.ResponseWriter, r *http.Request) {
	var body control.ScanInput
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body", err.Error())
		return
	}
	run, err := s.Service.CreateScan(r.Context(), body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "scan_rejected", err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"id": run.ID.String(), "status": run.Status})
}

func (s *Server) getScan(w http.ResponseWriter, r *http.Request) {
	runID, err := id.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", err.Error())
		return
	}
	run, err := s.Service.Run(runID)
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, run)
}

func (s *Server) cancelScan(w http.ResponseWriter, r *http.Request) {
	runID, err := id.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", err.Error())
		return
	}
	if err := s.Service.Cancel(runID); err != nil {
		status := http.StatusConflict
		if errors.Is(err, errors.ErrUnsupported) {
			status = http.StatusBadRequest
		}
		writeError(w, status, "cancel_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "cancelling"})
}

func (s *Server) listObservations(w http.ResponseWriter, r *http.Request) {
	runID, err := id.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"observations": s.Service.Observations(runID)})
}

func (s *Server) listFindings(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"findings": s.Service.Findings()})
}

func (s *Server) listDispositions(w http.ResponseWriter, r *http.Request) {
	findingID, err := id.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"dispositions": s.Service.Dispositions(findingID)})
}

func (s *Server) createDisposition(w http.ResponseWriter, r *http.Request) {
	actor, ok := actorFrom(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "authentication_required", "authentication required")
		return
	}
	findingID, err := id.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", err.Error())
		return
	}
	var body struct {
		Type        string          `json:"disposition_type"`
		Reason      string          `json:"reason"`
		Scope       json.RawMessage `json:"scope"`
		ValidFrom   *time.Time      `json:"valid_from"`
		ValidUntil  *time.Time      `json:"valid_until"`
		DetectionID string          `json:"detection_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body", err.Error())
		return
	}
	var detectionID id.ID
	if body.DetectionID != "" {
		detectionID, err = id.Parse(body.DetectionID)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_id", err.Error())
			return
		}
	}
	record, err := s.Service.AddDisposition(findingID, actor, control.DispositionInput{
		Type: body.Type, Reason: body.Reason, Scope: body.Scope, ValidFrom: body.ValidFrom, ValidUntil: body.ValidUntil, DetectionID: detectionID,
	})
	if err != nil {
		switch {
		case errors.Is(err, control.ErrFindingNotFound):
			writeError(w, http.StatusNotFound, "not_found", err.Error())
		case errors.Is(err, control.ErrDispositionVerification):
			writeError(w, http.StatusConflict, "verification_required", err.Error())
		case errors.Is(err, control.ErrDispositionState):
			writeError(w, http.StatusConflict, "disposition_conflict", err.Error())
		default:
			writeError(w, http.StatusBadRequest, "disposition_rejected", err.Error())
		}
		return
	}
	writeJSON(w, http.StatusCreated, record)
}

func (s *Server) createVerification(w http.ResponseWriter, r *http.Request) {
	findingID, err := id.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", err.Error())
		return
	}
	var body struct {
		GrantID string `json:"grant_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body", err.Error())
		return
	}
	grantID, err := id.Parse(body.GrantID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", err.Error())
		return
	}
	run, err := s.Service.CreateVerification(r.Context(), findingID, grantID)
	if err != nil {
		switch {
		case errors.Is(err, control.ErrFindingNotFound):
			writeError(w, http.StatusNotFound, "not_found", err.Error())
		case errors.Is(err, control.ErrVerificationUnavailable):
			writeError(w, http.StatusConflict, "verification_unavailable", err.Error())
		default:
			writeError(w, http.StatusBadRequest, "verification_rejected", err.Error())
		}
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"id": run.ID.String(), "status": run.Status, "trigger_type": run.TriggerType})
}

func (s *Server) importFingerprintPack(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, nmapfinger.MaxDocumentBytes+65536)
	var body struct {
		Format   string `json:"format"`
		Document string `json:"document"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body", err.Error())
		return
	}
	if body.Format != "nmap-service-probes" {
		writeError(w, http.StatusBadRequest, "format_rejected", "format must be nmap-service-probes")
		return
	}
	item, err := s.Service.ImportNmapFingerprints(r.Context(), []byte(body.Document))
	if err != nil {
		writeError(w, http.StatusBadRequest, "fingerprint_rejected", err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, fingerprintPackJSON(item))
}

func (s *Server) listFingerprintPacks(w http.ResponseWriter, r *http.Request) {
	items := s.Service.NmapFingerprintPacks()
	out := make([]map[string]any, len(items))
	for i, item := range items {
		out[i] = fingerprintPackJSON(item)
	}
	writeJSON(w, http.StatusOK, map[string]any{"packs": out})
}

func (s *Server) publishFingerprintPack(w http.ResponseWriter, r *http.Request) {
	s.changeFingerprintPack(w, r, true)
}

func (s *Server) deprecateFingerprintPack(w http.ResponseWriter, r *http.Request) {
	s.changeFingerprintPack(w, r, false)
}

func (s *Server) changeFingerprintPack(w http.ResponseWriter, r *http.Request, publish bool) {
	packID, err := id.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", err.Error())
		return
	}
	var item control.NmapFingerprintPack
	if publish {
		item, err = s.Service.PublishNmapFingerprints(r.Context(), packID)
	} else {
		item, err = s.Service.DeprecateNmapFingerprints(r.Context(), packID)
	}
	if err != nil {
		writeError(w, http.StatusNotFound, "pack_not_found", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, fingerprintPackJSON(item))
}

func (s *Server) importConfigPack(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, configrule.MaxDocumentBytes+65536)
	var body struct {
		Format   string `json:"format"`
		Document string `json:"document"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body", err.Error())
		return
	}
	if body.Format != "vesper-config" {
		writeError(w, http.StatusBadRequest, "format_rejected", "format must be vesper-config")
		return
	}
	item, err := s.Service.ImportConfigPack(r.Context(), []byte(body.Document))
	if err != nil {
		writeError(w, http.StatusBadRequest, "config_rejected", err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, configPackJSON(item))
}

func (s *Server) listConfigPacks(w http.ResponseWriter, r *http.Request) {
	items := s.Service.ConfigPacks()
	out := make([]map[string]any, len(items))
	for i, item := range items {
		out[i] = configPackJSON(item)
	}
	writeJSON(w, http.StatusOK, map[string]any{"packs": out})
}

func (s *Server) publishConfigPack(w http.ResponseWriter, r *http.Request) {
	s.changeConfigPack(w, r, true)
}

func (s *Server) deprecateConfigPack(w http.ResponseWriter, r *http.Request) {
	s.changeConfigPack(w, r, false)
}

func (s *Server) changeConfigPack(w http.ResponseWriter, r *http.Request, publish bool) {
	packID, err := id.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", err.Error())
		return
	}
	var item control.ConfigPack
	if publish {
		item, err = s.Service.PublishConfigPack(r.Context(), packID)
	} else {
		item, err = s.Service.DeprecateConfigPack(r.Context(), packID)
	}
	if err != nil {
		if errors.Is(err, control.ErrConfigPackNotFound) {
			writeError(w, http.StatusNotFound, "pack_not_found", err.Error())
			return
		}
		writeError(w, http.StatusBadRequest, "config_rejected", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, configPackJSON(item))
}

func configPackJSON(item control.ConfigPack) map[string]any {
	return map[string]any{
		"id": item.ID.String(), "version": item.Version, "status": item.Status,
		"rules": item.Rules, "license_recorded": item.LicenseRecorded,
	}
}

func fingerprintPackJSON(item control.NmapFingerprintPack) map[string]any {
	return map[string]any{
		"id": item.ID.String(), "version": item.Version, "status": item.Status,
		"accepted": item.Accepted, "skipped": item.Skipped, "license_recorded": item.LicenseRecorded,
	}
}

func (s *Server) importActiveTemplate(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, activedetect.MaxTemplateBytes+4096)
	var body struct {
		Template string `json:"template"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body", err.Error())
		return
	}
	item, err := s.Service.ImportActiveTemplate(r.Context(), []byte(body.Template))
	if err != nil {
		writeError(w, http.StatusBadRequest, "template_rejected", err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, activeTemplateJSON(item))
}

func (s *Server) listActiveTemplates(w http.ResponseWriter, r *http.Request) {
	items := s.Service.ActiveTemplates()
	out := make([]map[string]any, len(items))
	for i, item := range items {
		out[i] = activeTemplateJSON(item)
	}
	writeJSON(w, http.StatusOK, map[string]any{"templates": out})
}

func (s *Server) publishActiveTemplate(w http.ResponseWriter, r *http.Request) {
	s.changeActiveTemplate(w, r, true)
}

func (s *Server) disableActiveTemplate(w http.ResponseWriter, r *http.Request) {
	s.changeActiveTemplate(w, r, false)
}

func (s *Server) changeActiveTemplate(w http.ResponseWriter, r *http.Request, publish bool) {
	templateID, err := id.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", err.Error())
		return
	}
	var item control.ActiveTemplate
	if publish {
		item, err = s.Service.PublishActiveTemplate(r.Context(), templateID)
	} else {
		item, err = s.Service.DisableActiveTemplate(r.Context(), templateID)
	}
	if err != nil {
		writeError(w, http.StatusNotFound, "template_not_found", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, activeTemplateJSON(item))
}

func activeTemplateJSON(item control.ActiveTemplate) map[string]any {
	return map[string]any{
		"id": item.ID.String(), "key": item.Key, "name": item.Name, "severity": item.Severity,
		"cve_id": item.CVE, "digest": item.Digest, "request_bound": item.RequestBound,
		"status": item.Status, "enabled": item.Enabled,
	}
}

func (s *Server) importIntel(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 33<<20)
	var body struct {
		Source   string          `json:"source"`
		Document json.RawMessage `json:"document"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body", err.Error())
		return
	}
	document, err := intelDocument(body.Document)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_document", err.Error())
		return
	}
	snapshot, err := s.Service.ImportIntel(r.Context(), body.Source, document)
	if err != nil {
		writeError(w, http.StatusBadRequest, "intel_rejected", err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"id": snapshot.ID.String(), "content_digest": snapshot.ContentDigest,
		"sources": snapshot.Sources, "statement_count": len(snapshot.StatementIDs), "published_at": snapshot.PublishedAt,
	})
}

func (s *Server) listFeeds(w http.ResponseWriter, r *http.Request) {
	feeds := s.Service.Feeds()
	if feeds == nil {
		feeds = []control.FeedStatus{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"feeds": feeds})
}

func (s *Server) syncFeed(w http.ResponseWriter, r *http.Request) {
	snapshot, status, err := s.Service.SyncFeed(r.Context(), r.PathValue("source"))
	if err != nil {
		writeError(w, http.StatusBadGateway, "feed_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id": snapshot.ID.String(), "content_digest": snapshot.ContentDigest, "sources": snapshot.Sources,
		"statement_count": len(snapshot.StatementIDs), "published_at": snapshot.PublishedAt,
		"source": status.Source, "cursor": status.Cursor, "last_result": status.LastResult,
	})
}

func (s *Server) listIntelSnapshots(w http.ResponseWriter, r *http.Request) {
	snapshots := s.Service.Snapshots()
	out := make([]map[string]any, len(snapshots))
	for i, item := range snapshots {
		out[i] = map[string]any{
			"id": item.ID.String(), "content_digest": item.ContentDigest, "sources": item.Sources,
			"statement_count": len(item.StatementIDs), "published_at": item.PublishedAt,
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"snapshots": out})
}

func (s *Server) reassessIntel(w http.ResponseWriter, r *http.Request) {
	snapshotID, err := id.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", err.Error())
		return
	}
	added, err := s.Service.Reassess(r.Context(), snapshotID)
	if err != nil {
		writeError(w, http.StatusNotFound, "reassess_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"snapshot_id": snapshotID.String(), "detections": added})
}

func intelDocument(raw json.RawMessage) ([]byte, error) {
	raw = bytesTrimSpace(raw)
	if len(raw) == 0 || string(raw) == "null" {
		return nil, errors.New("document is empty")
	}
	if raw[0] == '"' {
		var text string
		if err := json.Unmarshal(raw, &text); err != nil {
			return nil, err
		}
		return []byte(text), nil
	}
	return append([]byte(nil), raw...), nil
}

func bytesTrimSpace(raw []byte) []byte {
	return []byte(strings.TrimSpace(string(raw)))
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": message}})
}
