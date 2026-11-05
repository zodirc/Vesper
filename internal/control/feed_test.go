package control

import (
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/zodirc/Vesper/internal/id"
	"github.com/zodirc/Vesper/internal/identity"
	"github.com/zodirc/Vesper/internal/intel"
)

func TestNVDImportConfirmsTheListedVersionOnly(t *testing.T) {
	now := time.Date(2026, 11, 5, 9, 0, 0, 0, time.UTC)
	svc, err := New(t.TempDir(), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	criteria := "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*"
	product, err := svc.AddProductIdentity(Product{
		Ecosystem: "generic", ProductName: "nginx", CanonicalKey: "generic:nginx",
	}, []identity.Alias{{Source: "catalog", AliasType: "cpe", Value: criteria}})
	if err != nil {
		t.Fatal(err)
	}
	document := []byte(`{
	  "vulnerabilities": [{
	    "cve": {
	      "id": "CVE-2026-3000",
	      "metrics": {"cvssMetricV31": [{"type": "Primary", "cvssData": {"baseSeverity": "HIGH", "baseScore": 7.5}}]},
	      "configurations": [{"nodes": [{"cpeMatch": [{
	        "vulnerable": true, "criteria": "` + criteria + `",
	        "versionStartIncluding": "1.0.0", "versionEndExcluding": "1.26.0"
	      }]}]}]
	    }
	  }]
	}`)
	snapshot, err := svc.ImportIntel(context.Background(), "nvd", document)
	if err != nil {
		t.Fatal(err)
	}
	productID := product.ID
	endpoint := id.MustNew()
	svc.hypotheses = append(svc.hypotheses, identity.Hypothesis{
		ID: id.MustNew(), EndpointID: endpoint, ProductIdentityID: &productID, RawVersion: "1.24.0", EvaluatedAt: now,
	})
	added, err := svc.Reassess(context.Background(), snapshot.ID, ReassessOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if added.Detections != 1 || svc.detections[0].ResultStatus != "confirmed" || svc.detections[0].VulnerabilityID != "CVE-2026-3000" {
		t.Fatalf("added = %d detections = %+v", added.Detections, svc.detections)
	}
	svc.hypotheses[0].RawVersion = "1.26.0"
	added, err = svc.Reassess(context.Background(), snapshot.ID, ReassessOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if added.Detections != 1 || svc.detections[len(svc.detections)-1].ResultStatus == "confirmed" {
		t.Fatalf("fixed version was confirmed: %+v", svc.detections[len(svc.detections)-1])
	}
	rejected, err := svc.ImportIntel(context.Background(), "nvd", []byte(`{"vulnerabilities":[{"cve":{"id":"CVE-2026-3000","vulnStatus":"Rejected"}}]}`))
	if err != nil {
		t.Fatal(err)
	}
	svc.hypotheses[0].RawVersion = "1.24.0"
	if _, err := svc.Reassess(context.Background(), rejected.ID, ReassessOptions{}); err != nil {
		t.Fatal(err)
	}
	for _, detection := range svc.detections {
		if detection.IntelSnapshotID == rejected.ID && detection.ResultStatus == "confirmed" {
			t.Fatalf("rejected cve confirmed: %+v", detection)
		}
	}
}

func TestFeedSyncImportsOneNVDPageAndSkipsUnchangedKEV(t *testing.T) {
	now := time.Date(2026, 11, 5, 10, 0, 0, 0, time.UTC)
	svc, err := New(t.TempDir(), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	nvdHits := 0
	kevHits := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/nvd":
			nvdHits++
			if r.URL.Query().Get("startIndex") != "0" || r.URL.Query().Get("resultsPerPage") != "100" {
				http.Error(w, "bad query", http.StatusBadRequest)
				return
			}
			_, _ = w.Write([]byte(`{"totalResults":1,"vulnerabilities":[{"cve":{"id":"CVE-2026-4000"}}]}`))
		case "/kev":
			kevHits++
			_, _ = w.Write([]byte(`{"catalogVersion":"2026.11.05","count":1,"vulnerabilities":[{"cveID":"CVE-2026-4000","dateAdded":"2026-11-05"}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	svc.feedClient = server.Client()
	svc.nvdFeedURL = server.URL + "/nvd"
	svc.kevFeedURL = server.URL + "/kev"
	first, status, err := svc.SyncFeed(context.Background(), "nvd")
	if err != nil {
		t.Fatal(err)
	}
	if status.LastResult != "imported" || first.ID.IsZero() || nvdHits != 1 {
		t.Fatalf("status = %+v hits = %d", status, nvdHits)
	}
	if _, status, err = svc.SyncFeed(context.Background(), "kev"); err != nil {
		t.Fatal(err)
	}
	if status.LastResult != "imported" {
		t.Fatalf("kev = %+v", status)
	}
	if _, status, err = svc.SyncFeed(context.Background(), "kev"); err != nil {
		t.Fatal(err)
	}
	if status.LastResult != "unchanged" || kevHits != 2 {
		t.Fatalf("second kev = %+v hits = %d", status, kevHits)
	}
	if _, _, err := svc.SyncFeed(context.Background(), "osv"); err == nil {
		t.Fatal("osv feed was fetched")
	}
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	_, _ = writer.Write([]byte("cve,epss,percentile\nCVE-2026-4000,0.5,0.9\n"))
	_ = writer.Close()
	epss := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(compressed.Bytes())
	}))
	defer epss.Close()
	svc.epssFeedURL = epss.URL
	if _, status, err = svc.SyncFeed(context.Background(), "epss"); err != nil {
		t.Fatal(err)
	}
	if status.LastResult != "imported" {
		t.Fatalf("epss = %+v", status)
	}
	found := false
	for _, statement := range svc.statements {
		if statement.Source == intel.SourceEPSS && statement.EPSS != nil && *statement.EPSS == 0.5 {
			found = true
		}
	}
	if !found {
		t.Fatal("epss statement was not stored")
	}
}
