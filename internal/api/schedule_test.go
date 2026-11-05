package api

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/zodirc/Vesper/internal/control"
)

func TestScheduleRouteRejectsReassessmentTarget(t *testing.T) {
	now := time.Date(2026, 11, 5, 8, 0, 0, 0, time.UTC)
	svc, err := control.New(t.TempDir(), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{Service: svc, User: "admin", Password: "secret", Now: func() time.Time { return now }}
	handler := server.Handler()
	token := login(t, handler)
	created := call(t, handler, http.MethodPost, "/api/v1/grants", token, []byte(`{
		"name":"lab","subject_type":"user",
		"target_selectors":[{"kind":"ip","value":"127.0.0.1"}],
		"allowed_transports":["tcp"],"allowed_ports":[{"start":9,"end":9}],
		"allowed_operations":["discovery","connect"],
		"observation_point_ids":["`+svc.ObservationPointID().String()+`"],
		"valid_from":"2026-11-05T07:00:00Z",
		"max_targets":2,"max_addresses":2,"max_connections":4,"max_requests":4,
		"max_concurrency":1,"max_rate_per_second":10,"max_runtime_seconds":60,"max_evidence_bytes":1048576
	}`))
	if created.Code != http.StatusCreated {
		t.Fatalf("grant = %d %s", created.Code, created.Body.String())
	}
	grantID := created.Body.String()
	start := strings.Index(grantID, `"id":"`)
	if start < 0 {
		t.Fatalf("grant body = %s", grantID)
	}
	grantID = grantID[start+6:]
	grantID = grantID[:strings.Index(grantID, `"`)]
	approved := call(t, handler, http.MethodPost, "/api/v1/grants/"+grantID+"/approve", token, nil)
	if approved.Code != http.StatusOK {
		t.Fatalf("approve = %d %s", approved.Code, approved.Body.String())
	}
	rejected := call(t, handler, http.MethodPost, "/api/v1/scan-schedules", token, []byte(`{
		"name":"rejudge","trigger_type":"reassessment","interval_seconds":3600,"grant_id":"`+grantID+`","target":"127.0.0.1","type":"ip"
	}`))
	if rejected.Code != http.StatusBadRequest {
		t.Fatalf("rejected = %d %s", rejected.Code, rejected.Body.String())
	}
	accepted := call(t, handler, http.MethodPost, "/api/v1/scan-schedules", token, []byte(`{
		"name":"rejudge","trigger_type":"reassessment","interval_seconds":3600,"grant_id":"`+grantID+`"
	}`))
	if accepted.Code != http.StatusCreated || !strings.Contains(accepted.Body.String(), `"trigger_type":"reassessment"`) {
		t.Fatalf("accepted = %d %s", accepted.Code, accepted.Body.String())
	}
	listed := call(t, handler, http.MethodGet, "/api/v1/scan-schedules", token, nil)
	if listed.Code != http.StatusOK || !strings.Contains(listed.Body.String(), `"name":"rejudge"`) {
		t.Fatalf("list = %d %s", listed.Code, listed.Body.String())
	}
	scheduleID := accepted.Body.String()
	marker := strings.Index(scheduleID, `"id":"`)
	scheduleID = scheduleID[marker+6:]
	scheduleID = scheduleID[:strings.Index(scheduleID, `"`)]
	missing := call(t, handler, http.MethodPost, "/api/v1/scan-schedules/00000000-0000-4000-8000-000000000000/disable", token, nil)
	if missing.Code != http.StatusNotFound {
		t.Fatalf("missing = %d %s", missing.Code, missing.Body.String())
	}
	disabled := call(t, handler, http.MethodPost, "/api/v1/scan-schedules/"+scheduleID+"/disable", token, nil)
	if disabled.Code != http.StatusOK || !strings.Contains(disabled.Body.String(), `"status":"disabled"`) {
		t.Fatalf("disable = %d %s", disabled.Code, disabled.Body.String())
	}
}
