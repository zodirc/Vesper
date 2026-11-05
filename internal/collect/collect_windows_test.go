//go:build windows

package collect

import "testing"

func TestWindowsProcessInformationLayout(t *testing.T) {
	if !processBasicInformationOK() {
		t.Fatal("PROCESS_BASIC_INFORMATION layout does not match this architecture")
	}
	if _, _, _, ok := nativeCommandOffsets(); !ok {
		t.Fatal("command-line offsets are not defined for this architecture")
	}
}
