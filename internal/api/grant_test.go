package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/zodirc/Vesper/internal/control"
	"github.com/zodirc/Vesper/internal/id"
	"github.com/zodirc/Vesper/internal/scope"
)

func TestGrantAuditUsesTheSessionActor(t *testing.T) {
	now := time.Date(2026, 11, 3, 1, 0, 0, 0, time.UTC)
	svc, err := control.New(t.TempDir(), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{Service: svc, User: "admin", Password: "secret", Now: func() time.Time { return now }}
	handler := server.Handler()
	token := login(t, handler)
	point := svc.ObservationPointID().String()
	body := []byte(`{
		"name":"lab","subject_type":"user",
		"target_selectors":[{"kind":"ip","value":"203.0.113.10"}],
		"allowed_transports":["tcp"],
		"allowed_ports":[{"start":80,"end":80}],
		"allowed_operations":["connect"],
		"observation_point_ids":["` + point + `"],
		"valid_from":"2026-11-03T00:00:00Z",
		"max_targets":1,"max_addresses":1,"max_connections":1,"max_requests":1,
		"max_concurrency":1,"max_rate_per_second":1,"max_runtime_seconds":60,"max_evidence_bytes":1000
	}`)
	response := call(t, handler, http.MethodPost, "/api/v1/grants", token, body)
	if response.Code != http.StatusCreated {
		t.Fatalf("create status = %d body = %s", response.Code, response.Body.String())
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	grantID, err := id.Parse(created.ID)
	if err != nil {
		t.Fatal(err)
	}
	second := login(t, handler)
	approved := call(t, handler, http.MethodPost, "/api/v1/grants/"+created.ID+"/approve", second, []byte(`{}`))
	if approved.Code != http.StatusOK {
		t.Fatalf("approve status = %d body = %s", approved.Code, approved.Body.String())
	}
	revoked := call(t, handler, http.MethodPost, "/api/v1/grants/"+created.ID+"/revoke", token, []byte(`{"reason":"withdrawn"}`))
	if revoked.Code != http.StatusOK {
		t.Fatalf("revoke status = %d body = %s", revoked.Code, revoked.Body.String())
	}
	empty := call(t, handler, http.MethodPost, "/api/v1/grants/"+created.ID+"/revoke", token, []byte(`{"reason":" "}`))
	if empty.Code != http.StatusBadRequest {
		t.Fatalf("empty revoke status = %d", empty.Code)
	}
	revisions := svc.Revisions(grantID)
	if len(revisions) != 3 {
		t.Fatalf("revisions = %+v", revisions)
	}
	actor := revisions[0].ActorID
	for _, item := range revisions {
		if item.ActorID != actor || item.ActorID.IsZero() {
			t.Fatalf("actor = %s", item.ActorID)
		}
	}
	stored, err := svc.Grant(grantID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != scope.StatusRevoked {
		t.Fatalf("status = %s", stored.Status)
	}
}

func TestDispositionRouteRejectsMissingFindingAndBlankReason(t *testing.T) {
	now := time.Date(2026, 11, 4, 4, 0, 0, 0, time.UTC)
	svc, err := control.New(t.TempDir(), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	handler := (&Server{Service: svc, User: "admin", Password: "secret", Now: func() time.Time { return now }}).Handler()
	token := login(t, handler)
	findingID := id.MustNew().String()
	missing := call(t, handler, http.MethodPost, "/api/v1/findings/"+findingID+"/dispositions", token, []byte(`{"disposition_type":"reopen","reason":"back"}`))
	if missing.Code != http.StatusNotFound {
		t.Fatalf("missing status = %d body = %s", missing.Code, missing.Body.String())
	}
	blank := call(t, handler, http.MethodPost, "/api/v1/findings/"+findingID+"/dispositions", token, []byte(`{"disposition_type":"accept_risk","reason":" "}`))
	if blank.Code != http.StatusBadRequest {
		t.Fatalf("blank status = %d body = %s", blank.Code, blank.Body.String())
	}
	listed := call(t, handler, http.MethodGet, "/api/v1/findings/"+findingID+"/dispositions", token, nil)
	if listed.Code != http.StatusOK || !strings.Contains(listed.Body.String(), `"dispositions":null`) {
		t.Fatalf("list status = %d body = %s", listed.Code, listed.Body.String())
	}
}

func TestVerificationRouteRejectsAMissingFinding(t *testing.T) {
	now := time.Date(2026, 11, 4, 8, 0, 0, 0, time.UTC)
	svc, err := control.New(t.TempDir(), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	handler := (&Server{Service: svc, User: "admin", Password: "secret", Now: func() time.Time { return now }}).Handler()
	token := login(t, handler)
	findingID := id.MustNew().String()
	missing := call(t, handler, http.MethodPost, "/api/v1/findings/"+findingID+"/verification", token, []byte(`{"grant_id":"`+id.MustNew().String()+`"}`))
	if missing.Code != http.StatusNotFound {
		t.Fatalf("missing status = %d body = %s", missing.Code, missing.Body.String())
	}
	blank := call(t, handler, http.MethodPost, "/api/v1/findings/"+findingID+"/verification", token, []byte(`{"grant_id":" "}`))
	if blank.Code != http.StatusBadRequest {
		t.Fatalf("blank status = %d body = %s", blank.Code, blank.Body.String())
	}
	anonymous := httptest.NewRecorder()
	handler.ServeHTTP(anonymous, httptest.NewRequest(http.MethodPost, "/api/v1/findings/"+findingID+"/verification", bytes.NewReader([]byte(`{"grant_id":"`+id.MustNew().String()+`"}`))))
	if anonymous.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous status = %d", anonymous.Code)
	}
}

func login(t *testing.T, handler http.Handler) string {
	t.Helper()
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/api/v1/sessions", bytes.NewReader([]byte(`{"username":"admin","password":"secret"}`))))
	if response.Code != http.StatusCreated {
		t.Fatalf("session status = %d body = %s", response.Code, response.Body.String())
	}
	var session struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &session); err != nil {
		t.Fatal(err)
	}
	return session.Token
}

func call(t *testing.T, handler http.Handler, method, path, token string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, path, bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}
