// Package api 提供本机 HTTP 管理入口。处理函数只创建任务和读取结果，不在请求路径中执行探测。
// Package api provides the local HTTP management entry. Handlers only create tasks and read results; they do not run probes on the request path.
package api

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/zodirc/Vesper/internal/control"
	"github.com/zodirc/Vesper/internal/id"
	"github.com/zodirc/Vesper/internal/scope"
)

// Server 是带会话认证的管理 API。
// Server is the management API with session authentication.
type Server struct {
	Service  *control.Service
	User     string
	Password string
	Now      func() time.Time
	mu       sync.Mutex
	sessions map[string]session
}

type session struct {
	UserID  id.ID
	Expires time.Time
}

// Handler 返回管理路由。
// Handler returns the management routes.
func (s *Server) Handler() http.Handler {
	if s.sessions == nil {
		s.sessions = map[string]session{}
	}
	if s.Now == nil {
		s.Now = func() time.Time { return time.Now().UTC() }
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/sessions", s.createSession)
	mux.HandleFunc("GET /api/v1/observation-points", s.authenticated(s.observationPoints))
	mux.HandleFunc("POST /api/v1/grants", s.authenticated(s.createGrant))
	mux.HandleFunc("POST /api/v1/grants/{id}/approve", s.authenticated(s.approveGrant))
	mux.HandleFunc("POST /api/v1/scan-runs", s.authenticated(s.createScan))
	mux.HandleFunc("GET /api/v1/scan-runs/{id}", s.authenticated(s.getScan))
	mux.HandleFunc("POST /api/v1/scan-runs/{id}/cancel", s.authenticated(s.cancelScan))
	mux.HandleFunc("GET /api/v1/scan-runs/{id}/observations", s.authenticated(s.listObservations))
	mux.HandleFunc("GET /api/v1/findings", s.authenticated(s.listFindings))
	mux.HandleFunc("POST /api/v1/intel/imports", s.authenticated(s.importIntel))
	mux.HandleFunc("GET /api/v1/intel/snapshots", s.authenticated(s.listIntelSnapshots))
	mux.HandleFunc("POST /api/v1/intel/snapshots/{id}/reassess", s.authenticated(s.reassessIntel))
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
	s.mu.Lock()
	s.sessions[token.String()] = session{UserID: id.MustNew(), Expires: s.Now().Add(12 * time.Hour)}
	s.mu.Unlock()
	writeJSON(w, http.StatusCreated, map[string]any{"token": token.String(), "expires_at": s.Now().Add(12 * time.Hour)})
}

func (s *Server) authenticated(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		s.mu.Lock()
		item, ok := s.sessions[token]
		s.mu.Unlock()
		if !ok || !item.Expires.After(s.Now()) {
			writeError(w, http.StatusUnauthorized, "authentication_required", "authentication required")
			return
		}
		next(w, r)
	}
}

func (s *Server) observationPoints(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"observation_points": []map[string]string{{"id": s.Service.ObservationPointID().String(), "node_type": "local_worker"}}})
}

func (s *Server) createGrant(w http.ResponseWriter, r *http.Request) {
	var body control.GrantInput
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body", err.Error())
		return
	}
	grant, err := s.Service.CreateGrant(body, id.MustNew())
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
	if err := s.Service.ApproveGrant(grantID, id.MustNew()); err != nil {
		writeError(w, http.StatusConflict, "approve_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": scope.StatusActive})
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
