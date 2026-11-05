package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/zodirc/Vesper/internal/control"
)

func TestImportIntelRejectsUnknownSource(t *testing.T) {
	svc, err := control.New(t.TempDir(), func() time.Time { return time.Date(2026, 11, 3, 1, 0, 0, 0, time.UTC) })
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{Service: svc, User: "admin", Password: "secret", Now: func() time.Time { return time.Date(2026, 11, 3, 1, 0, 0, 0, time.UTC) }}
	body := []byte(`{"username":"admin","password":"secret"}`)
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/api/v1/sessions", bytes.NewReader(body)))
	if response.Code != http.StatusCreated {
		t.Fatalf("session status = %d body = %s", response.Code, response.Body.String())
	}
	var session struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &session); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/intel/imports", bytes.NewReader([]byte(`{"source":"exploitdb","document":{}}`)))
	request.Header.Set("Authorization", "Bearer "+session.Token)
	response = httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("import status = %d body = %s", response.Code, response.Body.String())
	}
	if len(svc.Snapshots()) != 0 {
		t.Fatalf("snapshots = %+v", svc.Snapshots())
	}
}
