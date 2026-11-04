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

func TestFingerprintPackAPIRejectsTheWrongFormatAndHidesRules(t *testing.T) {
	now := time.Date(2026, 11, 4, 9, 0, 0, 0, time.UTC)
	svc, err := control.New(t.TempDir(), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{Service: svc, User: "admin", Password: "secret", Now: func() time.Time { return now }}
	handler := server.Handler()
	token := login(t, handler)
	rejected := call(t, handler, http.MethodPost, "/api/v1/fingerprint-packs", token, []byte(`{"format":"nmap-os-db","document":"# License: x\n"}`))
	if rejected.Code != http.StatusBadRequest || len(svc.NmapFingerprintPacks()) != 0 {
		t.Fatalf("reject status = %d packs = %+v", rejected.Code, svc.NmapFingerprintPacks())
	}
	payload, err := json.Marshal(map[string]string{
		"format":   "nmap-service-probes",
		"document": "# License: caller supplied\nProbe TCP NULL q||\nmatch ftp m|^220[- ].*FileZilla| p/FileZilla ftpd/\n",
	})
	if err != nil {
		t.Fatal(err)
	}
	created := call(t, handler, http.MethodPost, "/api/v1/fingerprint-packs", token, payload)
	if created.Code != http.StatusCreated || strings.Contains(created.Body.String(), "FileZilla") || strings.Contains(created.Body.String(), "match ") {
		t.Fatalf("create status = %d body = %s", created.Code, created.Body.String())
	}
	var item struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &item); err != nil {
		t.Fatal(err)
	}
	if item.Status != "validated" {
		t.Fatalf("item = %+v", item)
	}
	missing := call(t, handler, http.MethodPost, "/api/v1/fingerprint-packs/"+id.MustNew().String()+"/publish", token, nil)
	if missing.Code != http.StatusNotFound {
		t.Fatalf("missing status = %d", missing.Code)
	}
	published := call(t, handler, http.MethodPost, "/api/v1/fingerprint-packs/"+item.ID+"/publish", token, nil)
	if published.Code != http.StatusOK || !strings.Contains(published.Body.String(), `"status":"published"`) {
		t.Fatalf("publish status = %d body = %s", published.Code, published.Body.String())
	}
}
