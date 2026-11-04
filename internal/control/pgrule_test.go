package control

import (
	"testing"

	"github.com/zodirc/Vesper/internal/rule"
)

func TestEmptyFingerprintListsStayAbsent(t *testing.T) {
	var negative []rule.Condition
	for _, raw := range []string{"", "null", "{}", "[]", "  []  "} {
		negative = nil
		if err := decodeJSONList([]byte(raw), &negative); err != nil {
			t.Fatal(err)
		}
		if negative != nil {
			t.Fatalf("%q decoded to %+v", raw, negative)
		}
	}
	if err := decodeJSONList([]byte(`[{"field":"protocol","op":"equals","value":"http"}]`), &negative); err != nil {
		t.Fatal(err)
	}
	if len(negative) != 1 || negative[0].Field != "protocol" || negative[0].Op != "equals" || negative[0].Value != "http" {
		t.Fatalf("%+v", negative)
	}
	text, err := jsonList([]rule.Condition(nil))
	if err != nil || text != "[]" {
		t.Fatalf("json = %s err = %v", text, err)
	}
	var evidence []string
	if err := decodeJSONList([]byte(`["tls_certificate"]`), &evidence); err != nil {
		t.Fatal(err)
	}
	if len(evidence) != 1 || evidence[0] != "tls_certificate" {
		t.Fatalf("%+v", evidence)
	}
}
