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

func TestActiveTemplateAPIRejectsThenPublishesWithoutReturningTheBody(t *testing.T) {
	now := time.Date(2026, 11, 4, 1, 0, 0, 0, time.UTC)
	svc, err := control.New(t.TempDir(), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{Service: svc, User: "admin", Password: "secret", Now: func() time.Time { return now }}
	handler := server.Handler()
	token := login(t, handler)
	rejected := call(t, handler, http.MethodPost, "/api/v1/active-templates", token, []byte(`{"template":"id: x\ncode:\n  - engine: sh\n"}`))
	if rejected.Code != http.StatusBadRequest {
		t.Fatalf("reject status = %d body = %s", rejected.Code, rejected.Body.String())
	}
	if len(svc.ActiveTemplates()) != 0 {
		t.Fatal("rejected template was stored")
	}
	payload, err := json.Marshal(map[string]string{"template": "id: example-check\ninfo:\n  name: Example\n  severity: high\nhttp:\n  - path:\n      - \"/health\"\n"})
	if err != nil {
		t.Fatal(err)
	}
	created := call(t, handler, http.MethodPost, "/api/v1/active-templates", token, payload)
	if created.Code != http.StatusCreated {
		t.Fatalf("create status = %d body = %s", created.Code, created.Body.String())
	}
	if strings.Contains(created.Body.String(), "/health") || strings.Contains(created.Body.String(), "http:") {
		t.Fatalf("response returned the template body: %s", created.Body.String())
	}
	var item struct {
		ID      string `json:"id"`
		Status  string `json:"status"`
		Enabled bool   `json:"enabled"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &item); err != nil {
		t.Fatal(err)
	}
	if item.Status != "validated" || item.Enabled {
		t.Fatalf("item = %+v", item)
	}
	missing := call(t, handler, http.MethodPost, "/api/v1/active-templates/"+id.MustNew().String()+"/publish", token, nil)
	if missing.Code != http.StatusNotFound {
		t.Fatalf("missing status = %d", missing.Code)
	}
	published := call(t, handler, http.MethodPost, "/api/v1/active-templates/"+item.ID+"/publish", token, nil)
	if published.Code != http.StatusOK || !strings.Contains(published.Body.String(), `"enabled":true`) {
		t.Fatalf("publish status = %d body = %s", published.Code, published.Body.String())
	}
	listed := call(t, handler, http.MethodGet, "/api/v1/active-templates", token, nil)
	if listed.Code != http.StatusOK || strings.Contains(listed.Body.String(), "/health") {
		t.Fatalf("list status = %d body = %s", listed.Code, listed.Body.String())
	}
}
