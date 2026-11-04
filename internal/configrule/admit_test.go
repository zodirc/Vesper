package configrule

import (
	"strings"
	"testing"
)

const validDocument = `license: caller supplied
rules:
  - id: no_telnet
    title: Telnet package is absent
    category: host
    severity: medium
    operation: collect_packages
    applies_when:
      - observation: collect_os_info
        field: id
        op: equals
        value: fedora
    pass:
      - field: packages
        op: none
        match:
          - field: name
            op: equals
            value: telnet
    fail:
      - field: packages
        op: any
        match:
          - field: name
            op: equals
            value: telnet
    remediation: Remove the telnet package.
`

func TestAdmitAcceptsClosedComparisons(t *testing.T) {
	doc, err := Admit([]byte(validDocument))
	if err != nil {
		t.Fatal(err)
	}
	if doc.License != "caller supplied" || len(doc.Rules) != 1 || doc.Rules[0].Key != "no_telnet" || doc.Rules[0].Pass[0].Op != "none" {
		t.Fatalf("doc = %+v", doc)
	}
	again, err := Admit([]byte(validDocument))
	if err != nil || again.Digest != doc.Digest {
		t.Fatalf("digest = %s err = %v", again.Digest, err)
	}
}

func TestAdmitRejectsUnboundSubjectsCommandsAndUnknownFields(t *testing.T) {
	cases := []string{
		strings.Replace(validDocument, "operation: collect_packages", "operation: collect_packages\n    subject: service", 1),
		strings.Replace(validDocument, "operation: collect_packages", "operation: collect_packages\n    subject: software_package", 1),
		strings.Replace(validDocument, "operation: collect_packages", "operation: collect_packages\n    unknown_condition: pass", 1),
		strings.Replace(validDocument, "op: equals", "op: equals\n        command: rpm -q telnet", 1),
		strings.Replace(validDocument, "field: id", "field: pretty_name", 1),
		"rules:\n  - id: name_pattern\n    title: Name matches a pattern\n    severity: low\n    operation: collect_os_info\n    pass:\n      - field: name\n        op: regex\n        value: (?=Fedora)\n",
		"rules:\n  - id: name_pattern\n    title: Name matches a pattern\n    severity: low\n    operation: collect_os_info\n    pass:\n      - field: name\n        op: regex\n        value: (Fedora)\\1\n",
		strings.Replace(validDocument, "pass:\n      - field: packages\n        op: none\n        match:\n          - field: name\n            op: equals\n            value: telnet\n", "pass: []\n", 1),
		strings.Replace(validDocument, "id: no_telnet", "id: NoTelnet", 1),
		"rules:\n  - id: no_telnet\n    title: Telnet package is absent\n    severity: info\n    operation: collect_packages\n    pass:\n      - field: packages\n        op: exists\n",
	}
	for _, item := range cases {
		if _, err := Admit([]byte(item)); err == nil {
			t.Errorf("accepted %s", item)
		}
	}
	oversized := make([]byte, MaxDocumentBytes+1)
	for i := range oversized {
		oversized[i] = ' '
	}
	if _, err := Admit(oversized); err == nil {
		t.Fatal("accepted an oversized document")
	}
}
