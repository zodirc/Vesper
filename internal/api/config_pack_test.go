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

func TestConfigPackAPIRejectsInvalidRulesAndHidesTheDocument(t *testing.T) {
	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	svc, err := control.New(t.TempDir(), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{Service: svc, User: "admin", Password: "secret", Now: func() time.Time { return now }}
	handler := server.Handler()
	token := login(t, handler)
	rejected := call(t, handler, http.MethodPost, "/api/v1/config-packs", token, []byte(`{"format":"xccdf","document":"rules: []"}`))
	if rejected.Code != http.StatusBadRequest || len(svc.ConfigPacks()) != 0 {
		t.Fatalf("format status = %d packs = %+v", rejected.Code, svc.ConfigPacks())
	}
	invalid := call(t, handler, http.MethodPost, "/api/v1/config-packs", token, []byte(`{"format":"vesper-config","document":"rules:\n  - id: bad\n    title: Bad subject\n    severity: low\n    subject: endpoint\n    operation: collect_os_info\n    pass:\n      - field: name\n        op: exists\n"}`))
	if invalid.Code != http.StatusBadRequest || len(svc.ConfigPacks()) != 0 {
		t.Fatalf("invalid status = %d packs = %+v body = %s", invalid.Code, svc.ConfigPacks(), invalid.Body.String())
	}
	payload, err := json.Marshal(map[string]string{
		"format":   "vesper-config",
		"document": "license: caller supplied\nrules:\n  - id: not_this_os\n    title: Operating system is not the marker\n    severity: low\n    operation: collect_os_info\n    pass:\n      - field: name\n        op: exists\n",
	})
	if err != nil {
		t.Fatal(err)
	}
	created := call(t, handler, http.MethodPost, "/api/v1/config-packs", token, payload)
	if created.Code != http.StatusCreated || strings.Contains(created.Body.String(), "not_this_os") || strings.Contains(created.Body.String(), "exists") {
		t.Fatalf("create status = %d body = %s", created.Code, created.Body.String())
	}
	var item struct {
		ID     string `json:"id"`
		Status string `json:"status"`
		Rules  int    `json:"rules"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &item); err != nil {
		t.Fatal(err)
	}
	if item.Status != "validated" || item.Rules != 1 {
		t.Fatalf("item = %+v", item)
	}
	missing := call(t, handler, http.MethodPost, "/api/v1/config-packs/"+id.MustNew().String()+"/publish", token, nil)
	if missing.Code != http.StatusNotFound {
		t.Fatalf("missing status = %d", missing.Code)
	}
	published := call(t, handler, http.MethodPost, "/api/v1/config-packs/"+item.ID+"/publish", token, nil)
	if published.Code != http.StatusOK || !strings.Contains(published.Body.String(), `"status":"published"`) || strings.Contains(published.Body.String(), "Operating system") {
		t.Fatalf("publish status = %d body = %s", published.Code, published.Body.String())
	}
}
