//go:build linux

package collect

import "testing"

func TestLinuxProcessCollectionReadsProc(t *testing.T) {
	result, err := collectProcesses()
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != StatusCollected {
		t.Fatalf("status = %s value = %+v", result.Status, result.Value)
	}
	records, ok := result.Value["processes"].([]map[string]any)
	if !ok || len(records) == 0 {
		t.Fatalf("processes = %#v", result.Value["processes"])
	}
}

func TestLinuxInventoryOperationsReturnACollectionStatus(t *testing.T) {
	for _, operation := range []string{"collect_services", "collect_packages", "collect_firewall_config"} {
		result, err := collectPlatform(operation)
		if err != nil {
			t.Fatal(err)
		}
		switch result.Status {
		case StatusCollected, StatusEmpty, StatusPermissionDenied, StatusUnsupported, StatusError:
		default:
			t.Fatalf("%s status = %s", operation, result.Status)
		}
		if result.Operation != operation {
			t.Fatalf("operation = %s", result.Operation)
		}
	}
}
