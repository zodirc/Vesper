package collect

import (
	"strings"
	"testing"
)

func TestParseProcNetIPv4Listen(t *testing.T) {
	input := "  sl  local_address rem_address   st\n   0: 0100007F:1F90 00000000:0000 0A\n   1: 0100007F:0050 00000000:0000 01\n"
	sockets, err := ParseProcNet(strings.NewReader(input), "tcp")
	if err != nil {
		t.Fatal(err)
	}
	if len(sockets) != 1 || sockets[0].Address.String() != "127.0.0.1" || sockets[0].Port != 8080 {
		t.Fatalf("sockets = %+v", sockets)
	}
}
