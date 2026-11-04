package control

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/zodirc/Vesper/internal/probe/ftpprobe"
	"github.com/zodirc/Vesper/internal/task"
)

const nmapServiceProbes = `# Service probes submitted by the caller.
# License: supplied for conversion, not distributed with the program.
Probe TCP NULL q||
match ftp m|^220[- ].*FileZilla| p/FileZilla ftpd/
match telnet m|^telnet| p/Telnet/
Probe TCP Help q|HELP\r\n|
match ftp m|^220| p/Help/
`

func TestNmapFingerprintStaysUnusedUntilPublishedAndSurvivesDeprecation(t *testing.T) {
	now := time.Date(2026, 11, 4, 9, 0, 0, 0, time.UTC)
	svc, err := New(t.TempDir(), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	imported, err := svc.ImportNmapFingerprints(context.Background(), []byte(nmapServiceProbes))
	if err != nil {
		t.Fatal(err)
	}
	if imported.Status != "validated" || imported.Accepted != 1 || imported.Skipped["service"] != 1 || imported.Skipped["stimulus"] != 1 || !imported.LicenseRecorded {
		t.Fatalf("imported = %+v", imported)
	}
	again, err := svc.ImportNmapFingerprints(context.Background(), []byte(nmapServiceProbes))
	if err != nil || again.ID != imported.ID || len(svc.NmapFingerprintPacks()) != 1 {
		t.Fatalf("again = %+v packs = %+v err = %v", again, svc.NmapFingerprintPacks(), err)
	}
	port := serveGreeting(t, "220 FileZilla Server\r\n")
	restore := ftpProbeForPort
	ftpProbeForPort = func(candidate int) string {
		if candidate == port {
			return ftpprobe.Name
		}
		return ""
	}
	t.Cleanup(func() { ftpProbeForPort = restore })
	if _, err := scanOnePort(t, svc, port, now); err != nil {
		t.Fatal(err)
	}
	finishRun(t, svc)
	if hasProduct(svc, "FileZilla ftpd") {
		t.Fatal("unpublished pack produced a product")
	}
	if _, err := svc.PublishNmapFingerprints(context.Background(), imported.ID); err != nil {
		t.Fatal(err)
	}
	frozen, err := scanOnePort(t, svc, port, now)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(frozen.Plan), imported.Version) {
		t.Fatalf("plan = %s", frozen.Plan)
	}
	if _, err := svc.DeprecateNmapFingerprints(context.Background(), imported.ID); err != nil {
		t.Fatal(err)
	}
	finishRun(t, svc)
	if !hasProduct(svc, "FileZilla ftpd") {
		t.Fatalf("hypotheses = %+v", svc.Hypotheses())
	}
	for _, item := range svc.Hypotheses() {
		if item.RawProductName == "FileZilla ftpd" && item.FingerprintPackVersion != imported.Version {
			t.Fatalf("pack version = %s", item.FingerprintPackVersion)
		}
	}
	later, err := scanOnePort(t, svc, port, now)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(later.Plan), "nmap:") {
		t.Fatalf("deprecated pack was frozen: %s", later.Plan)
	}
}

func scanOnePort(t *testing.T, svc *Service, port int, now time.Time) (task.Run, error) {
	t.Helper()
	return svc.CreateScan(context.Background(), ScanInput{Name: "ftp", Target: "127.0.0.1", Type: "ip", Ports: []int{port}, GrantID: approveTCPGrant(t, svc, "127.0.0.1", port, now)})
}

func hasProduct(svc *Service, product string) bool {
	for _, item := range svc.Hypotheses() {
		if item.RawProductName == product {
			return true
		}
	}
	return false
}
