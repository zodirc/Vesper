package nmapfinger

import (
	"strings"
	"testing"
)

const sampleDocument = `# Nmap service probe sample
# License: supplied by the caller for conversion.
Exclude T:9100

Probe TCP NULL q||
rarity 1
ports 21,22,25

match ssh m|^SSH-2\.0-OpenSSH_([\d.]+)| p/OpenSSH/ v/$1/ cpe:/a:openbsd:openssh:$1/
match ftp m|^220[- ].*FileZilla| p/FileZilla ftpd/
match telnet m|^telnet| p/Telnet/
match ssh m|^SSH-(?=\d)| p/Broken/

Probe TCP GetRequest q|GET / HTTP/1.0\r\n\r\n|
match http m|^HTTP/1\.[01].*Server: Caddy/([\d.]+)|s p/Caddy/ v/$1/

Probe TCP Help q|HELP\r\n|
match smtp m|^214| p/Help/
`

func TestConvertKeepsOnlyEquivalentStimuli(t *testing.T) {
	rules, report, err := Convert([]byte(sampleDocument))
	if err != nil {
		t.Fatal(err)
	}
	if report.Probes != 3 || report.Accepted != 3 || !report.ExcludedPorts || report.Skipped["service"] != 1 || report.Skipped["regex"] != 1 || report.Skipped["stimulus"] != 1 {
		t.Fatalf("report = %+v", report)
	}
	if len(rules) != 3 || rules[0].Protocol != "ssh" || rules[0].Product != "OpenSSH" || rules[0].Version != "$1" || !strings.Contains(rules[0].Pattern, `OpenSSH_`) {
		t.Fatalf("ssh = %+v", rules[0])
	}
	if rules[1].Protocol != "ftp" || rules[1].Product != "FileZilla ftpd" {
		t.Fatalf("ftp = %+v", rules[1])
	}
	if rules[2].Protocol != "http" || rules[2].Product != "Caddy" || !strings.HasPrefix(rules[2].Pattern, "(?s)") {
		t.Fatalf("http = %+v", rules[2])
	}
}

func TestConvertRejectsAMissingLicenseAndTheWrongDatabase(t *testing.T) {
	if _, _, err := Convert([]byte("Probe TCP NULL q||\nmatch ssh m|^SSH-| p/OpenSSH/\n")); err == nil {
		t.Fatal("missing license was accepted")
	}
	document := "# License: test\nFingerprint Apple Mac OS X\nClass Apple | Mac OS X | general purpose\n"
	if _, _, err := Convert([]byte(document)); err == nil {
		t.Fatal("operating-system fingerprint was accepted")
	}
}
