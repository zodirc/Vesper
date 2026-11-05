package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/zodirc/Vesper/internal/control"
	"github.com/zodirc/Vesper/internal/id"
)

func TestManagementUIAndLists(t *testing.T) {
	now := time.Date(2026, 11, 5, 3, 0, 0, 0, time.UTC)
	svc, err := control.New(t.TempDir(), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{Service: svc, User: "admin", Password: "secret", Now: func() time.Time { return now }}
	handler := server.Handler()

	page := call(t, handler, http.MethodGet, "/", "", nil)
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), `id="root"`) {
		t.Fatalf("ui status = %d body = %s", page.Code, page.Body.String())
	}
	if !strings.Contains(page.Header().Get("Content-Security-Policy"), "default-src 'self'") {
		t.Fatalf("csp = %s", page.Header().Get("Content-Security-Policy"))
	}
	routed := call(t, handler, http.MethodGet, "/grants", "", nil)
	if routed.Code != http.StatusOK || !strings.Contains(routed.Body.String(), `id="root"`) {
		t.Fatalf("route status = %d", routed.Code)
	}
	missingAsset := call(t, handler, http.MethodGet, "/assets/missing.js", "", nil)
	if missingAsset.Code != http.StatusNotFound {
		t.Fatalf("missing asset = %d", missingAsset.Code)
	}
	anonymous := call(t, handler, http.MethodGet, "/api/v1/grants", "", nil)
	if anonymous.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous = %d", anonymous.Code)
	}

	token := login(t, handler)
	empty := call(t, handler, http.MethodGet, "/api/v1/scan-runs", token, nil)
	if empty.Code != http.StatusOK || !strings.Contains(empty.Body.String(), `"scan_runs":[]`) {
		t.Fatalf("scans = %d %s", empty.Code, empty.Body.String())
	}
	for _, path := range []string{"/api/v1/assets", "/api/v1/endpoints", "/api/v1/targets", "/api/v1/hypotheses"} {
		response := call(t, handler, http.MethodGet, path, token, nil)
		if response.Code != http.StatusOK {
			t.Fatalf("%s = %d %s", path, response.Code, response.Body.String())
		}
	}

	created := call(t, handler, http.MethodPost, "/api/v1/grants", token, []byte(`{
		"name":"lab","subject_type":"user",
		"target_selectors":[{"kind":"ip","value":"127.0.0.1"}],
		"allowed_transports":["tcp"],"allowed_ports":[{"start":80,"end":80}],
		"allowed_operations":["discovery","connect"],
		"observation_point_ids":["`+svc.ObservationPointID().String()+`"],
		"valid_from":"2026-11-05T02:00:00Z",
		"max_targets":4,"max_addresses":4,"max_connections":10,"max_requests":10,
		"max_concurrency":2,"max_rate_per_second":10,"max_runtime_seconds":60,"max_evidence_bytes":1048576
	}`))
	if created.Code != http.StatusCreated {
		t.Fatalf("create = %d %s", created.Code, created.Body.String())
	}
	var grant struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &grant); err != nil {
		t.Fatal(err)
	}
	listed := call(t, handler, http.MethodGet, "/api/v1/grants", token, nil)
	if listed.Code != http.StatusOK || !strings.Contains(listed.Body.String(), `"Name":"lab"`) || !strings.Contains(listed.Body.String(), `"Status":"draft"`) {
		t.Fatalf("grants = %s", listed.Body.String())
	}
	revisions := call(t, handler, http.MethodGet, "/api/v1/grants/"+grant.ID+"/revisions", token, nil)
	if revisions.Code != http.StatusOK || !strings.Contains(revisions.Body.String(), `"Action":"draft"`) {
		t.Fatalf("revisions = %d %s", revisions.Code, revisions.Body.String())
	}
	missing := call(t, handler, http.MethodGet, "/api/v1/grants/"+id.MustNew().String()+"/revisions", token, nil)
	if missing.Code != http.StatusNotFound {
		t.Fatalf("missing revisions = %d", missing.Code)
	}

	ended := call(t, handler, http.MethodDelete, "/api/v1/sessions", token, nil)
	if ended.Code != http.StatusNoContent {
		t.Fatalf("logout = %d %s", ended.Code, ended.Body.String())
	}
	again := call(t, handler, http.MethodGet, "/api/v1/grants", token, nil)
	if again.Code != http.StatusUnauthorized {
		t.Fatalf("after logout = %d", again.Code)
	}
}
