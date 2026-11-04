package assess

import "testing"

func TestDebianVersionOrder(t *testing.T) {
	cases := []struct {
		left, right string
		want        int
	}{
		{"1.0-1", "1.0-1", 0},
		{"1.0-1", "1.0-2", -1},
		{"1.0", "1.0-1", -1},
		{"1.0~rc1-1", "1.0-1", -1},
		{"1.10", "1.9", 1},
		{"1:1.0-1", "2.0-1", 1},
		{"0:1.0-1", "1.0-1", 0},
		{"1.0a", "1.0b", -1},
	}
	for _, item := range cases {
		got, ok := compareDeb(item.left, item.right)
		if !ok || got != item.want {
			t.Fatalf("compareDeb(%s, %s) = %d %v", item.left, item.right, got, ok)
		}
	}
	if _, ok := compareDeb("1.0 beta", "1.0"); ok {
		t.Fatal("illegal debian version was compared")
	}
}

func TestRPMVersionOrder(t *testing.T) {
	cases := []struct {
		left, right string
		want        int
	}{
		{"1.0-1", "1.0-1", 0},
		{"1.0-1", "1.0-2", -1},
		{"1.0", "1.0-1", -1},
		{"1.0~rc1", "1.0", -1},
		{"1.0", "1.0^git1", -1},
		{"1.0^git1", "1.0.1", -1},
		{"1.01", "1.1", 0},
		{"1:0.1-1", "2.0-1", 1},
		{"0:1.0-1", "1.0-1", 0},
		{"1.0-1.el8", "1.0-1.el9", -1},
	}
	for _, item := range cases {
		got, ok := compareRPM(item.left, item.right)
		if !ok || got != item.want {
			t.Fatalf("compareRPM(%s, %s) = %d %v", item.left, item.right, got, ok)
		}
	}
	if _, ok := compareRPM("1.0 1", "1.0"); ok {
		t.Fatal("illegal rpm version was compared")
	}
}
