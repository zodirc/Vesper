package control

import (
	"testing"

	"github.com/zodirc/Vesper/internal/rule"
)

func TestAdoptBuiltinPacksKeepsStoredBodies(t *testing.T) {
	stored := rule.Pack{Type: "fingerprint", Version: "builtin-14", ContentDigest: "stored", Source: "builtin"}
	caller := rule.Pack{Type: "fingerprint", Version: "caller-1", ContentDigest: "caller", Source: "nmap"}
	fresh := rule.Pack{Type: "fingerprint", Version: "builtin-14", ContentDigest: "fresh", Source: "builtin"}
	added := rule.Pack{Type: "fingerprint", Version: "builtin-15", ContentDigest: "new", Source: "builtin"}
	other := rule.Pack{Type: "fingerprint", Version: "extra", ContentDigest: "extra", Source: "nmap"}
	got := adoptBuiltinPacks([]rule.Pack{stored, caller}, []rule.Pack{fresh, added, other})
	if len(got) != 3 || got[0].ContentDigest != "stored" || got[1].ContentDigest != "caller" || got[2].Version != "builtin-15" || got[2].ContentDigest != "new" {
		t.Fatalf("packs = %+v", got)
	}
}
