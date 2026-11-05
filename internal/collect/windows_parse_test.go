package collect

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"strings"
	"testing"
)

func TestParseWindowsTCPListeners(t *testing.T) {
	buf := make([]byte, 4+ipv4RowSize*2)
	binary.LittleEndian.PutUint32(buf[:4], 2)
	putIPv4Row(buf[4:], 2, [4]byte{127, 0, 0, 1}, 80, 1234)
	putIPv4Row(buf[4+ipv4RowSize:], 5, [4]byte{10, 0, 0, 2}, 443, 9)
	listeners, err := ParseWindowsTCPListeners(buf, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(listeners) != 1 || listeners[0].Port != 80 || listeners[0].OwningPID != 1234 || listeners[0].Address != netip.MustParseAddr("127.0.0.1") {
		t.Fatalf("listeners = %+v", listeners)
	}
	if _, err := ParseWindowsTCPListeners(buf[:6], false); err == nil {
		t.Fatal("short table was accepted")
	}
	empty := make([]byte, 4)
	listeners, err = ParseWindowsTCPListeners(empty, false)
	if err != nil || len(listeners) != 0 {
		t.Fatalf("empty table = %+v %v", listeners, err)
	}

	v6 := make([]byte, 4+ipv6RowSize)
	binary.LittleEndian.PutUint32(v6[:4], 1)
	row := v6[4:]
	row[15] = 1
	row[20] = 0x01
	row[21] = 0xbb
	binary.LittleEndian.PutUint32(row[48:52], tcpListenerState)
	binary.LittleEndian.PutUint32(row[52:56], 44)
	listeners, err = ParseWindowsTCPListeners(v6, true)
	if err != nil || len(listeners) != 1 || listeners[0].Port != 443 || listeners[0].Address != netip.MustParseAddr("::1") || listeners[0].OwningPID != 44 {
		t.Fatalf("ipv6 listeners = %+v %v", listeners, err)
	}
}

func putIPv4Row(row []byte, state uint32, ip [4]byte, port uint16, pid uint32) {
	binary.LittleEndian.PutUint32(row[0:4], state)
	binary.LittleEndian.PutUint32(row[4:8], uint32(ip[0])|uint32(ip[1])<<8|uint32(ip[2])<<16|uint32(ip[3])<<24)
	row[8] = byte(port >> 8)
	row[9] = byte(port)
	binary.LittleEndian.PutUint32(row[20:24], pid)
}

func TestRemoteCommandLineParsing(t *testing.T) {
	header := make([]byte, 16)
	binary.LittleEndian.PutUint16(header[0:2], 4)
	binary.LittleEndian.PutUint64(header[8:16], 0x1000)
	n, buffer, ok := parseRemoteUnicodeString(header)
	if !ok || n != 4 || buffer != 0x1000 {
		t.Fatalf("header = %d %x %v", n, buffer, ok)
	}
	if _, _, ok := parseRemoteUnicodeString([]byte{1, 0, 0, 0, 0, 0, 0, 0}); ok {
		t.Fatal("odd length was accepted")
	}
	text, truncated, ok := decodeUTF16Command([]byte{'a', 0, 'b', 0})
	if !ok || truncated || text != "ab" {
		t.Fatalf("command = %q %v %v", text, truncated, ok)
	}
	long := bytes.Repeat([]byte{'a', 0}, cmdlineLimit+8)
	text, truncated, ok = decodeUTF16Command(long)
	if !ok || !truncated || len(text) != cmdlineLimit {
		t.Fatalf("truncated command len = %d %v %v", len(text), truncated, ok)
	}
}

func TestDecodePossibleText(t *testing.T) {
	text, ok := decodePossibleText([]byte{0xFF, 0xFE, 'A', 0})
	if !ok || text != "A" {
		t.Fatalf("utf16 = %q %v", text, ok)
	}
	text, ok = decodePossibleText([]byte("规则"))
	if !ok || text != "规则" {
		t.Fatalf("utf8 = %q %v", text, ok)
	}
	if _, ok := decodePossibleText([]byte{0xC3, 0x28}); ok {
		t.Fatal("invalid text was accepted")
	}
}

func TestWindowsIdentityAndServiceMapping(t *testing.T) {
	if windowsPlatformVersion(10, 0, 19045, 3803) != "10.0.19045.3803" {
		t.Fatal(windowsPlatformVersion(10, 0, 19045, 3803))
	}
	if windowsPlatformVersion(10, 0, 19045, 0) != "10.0.19045" {
		t.Fatal(windowsPlatformVersion(10, 0, 19045, 0))
	}
	if windowsVersionID("23H2", "2009", "10.0.19045.3803") != "23H2" || windowsVersionID("", "2009", "10.0.19045") != "2009" || windowsVersionID(" ", "", "10.0.19045") != "10.0.19045" {
		t.Fatal("version id selection")
	}
	running, ok := windowsServiceRecord("LanmanServer", "Server", `C:\Windows\System32\svchost.exe -k netsvcs`, "LocalSystem", 4, 2, true, true, 700)
	if !ok || running["active"] != "active" || running["sub"] != "running" || running["start_type"] != "automatic-delayed" || running["load"] != "loaded" || running["pid"] != 700 || running["account"] != "LocalSystem" {
		t.Fatalf("running = %+v", running)
	}
	stopped, ok := windowsServiceRecord("Spooler", "", "", "", 1, 4, true, false, 0)
	if !ok || stopped["active"] != "inactive" || stopped["sub"] != "stopped" || stopped["start_type"] != "disabled" {
		t.Fatalf("stopped = %+v", stopped)
	}
	if _, ok := stopped["pid"]; ok {
		t.Fatal("stopped service stored a pid")
	}
	pending, _ := windowsServiceRecord("wuauserv", "", "", "", 2, 3, true, false, 0)
	if pending["active"] != "activating" || pending["sub"] != "start-pending" || pending["start_type"] != "manual" {
		t.Fatalf("pending = %+v", pending)
	}
	paused, _ := windowsServiceRecord("paused", "", "", "", 7, 0, false, false, 0)
	if paused["active"] != "active" || paused["sub"] != "paused" {
		t.Fatalf("paused = %+v", paused)
	}
	if _, ok := paused["start_type"]; ok {
		t.Fatal("unknown start type was stored")
	}
	unknown, _ := windowsServiceRecord("custom", "", "", "", 9, 8, true, false, 0)
	if unknown["active"] != "unrecognized" || unknown["sub"] != "9" || unknown["start_type"] != "unrecognized:8" {
		t.Fatalf("unknown = %+v", unknown)
	}
	if _, ok := windowsServiceRecord("  ", "", "", "", 4, 2, true, false, 1); ok {
		t.Fatal("blank service name was accepted")
	}
}

func TestWindowsPackageMerge(t *testing.T) {
	if _, ok := windowsPackageRecord(" ", "1", "", "native", "machine", false); ok {
		t.Fatal("blank package name was accepted")
	}
	first, ok := windowsPackageRecord(" 中文 ", "1.0", "Publisher", "native", "machine", false)
	if !ok || first["name"] != "中文" || first["system_component"] != nil {
		t.Fatalf("package = %+v", first)
	}
	hidden, ok := windowsPackageRecord("Hidden", "", "", "wow64", "machine", true)
	if !ok || hidden["system_component"] != true || hidden["version"] != "" || hidden["registry_view"] != "wow64" {
		t.Fatalf("hidden = %+v", hidden)
	}
	duplicate, _ := windowsPackageRecord("中文", "1.0", "Publisher", "native", "machine", false)
	later, _ := windowsPackageRecord("Alpha", "2", "", "native", "user", false)
	status, value := mergePackageHives([]packageHive{
		{records: []map[string]any{first, duplicate, later}, status: StatusCollected},
		{status: StatusPermissionDenied},
		{status: StatusUnsupported},
	})
	if status != StatusCollected || value["unreadable"] != 1 || value["source"] != "registry" {
		t.Fatalf("status = %s value = %+v", status, value)
	}
	records := value["packages"].([]map[string]any)
	if len(records) != 2 || records[0]["name"] != "Alpha" || records[1]["name"] != "中文" {
		t.Fatalf("records = %+v", records)
	}
	fields := value["unsupported_fields"].([]string)
	if strings.Join(fields, ",") != "architecture,epoch,release" {
		t.Fatalf("fields = %+v", fields)
	}
	status, _ = mergePackageHives([]packageHive{{status: StatusPermissionDenied}, {status: StatusPermissionDenied}})
	if status != StatusPermissionDenied {
		t.Fatal(status)
	}
	status, value = mergePackageHives([]packageHive{{status: StatusEmpty}, {status: StatusUnsupported}})
	if status != StatusEmpty || len(value["packages"].([]map[string]any)) != 0 {
		t.Fatalf("empty = %s %+v", status, value)
	}
	status, _ = mergePackageHives([]packageHive{{status: StatusUnsupported}, {status: StatusError}})
	if status != StatusError {
		t.Fatal(status)
	}
	status, _ = mergePackageHives([]packageHive{{status: StatusUnsupported}})
	if status != StatusUnsupported {
		t.Fatal(status)
	}
	if clipText("中文", 4) != "中" || clipText("中", 1) != "" {
		t.Fatalf("clip = %q %q", clipText("中文", 4), clipText("中", 1))
	}
}

func TestWindowsFirewallAssembly(t *testing.T) {
	domain := windowsFirewallProfile("domain", true, 1, true, 0, true, 1)
	if domain["enabled"] != true || domain["default_inbound"] != "block" || domain["default_outbound"] != "allow" {
		t.Fatalf("domain = %+v", domain)
	}
	public := windowsFirewallProfile("public", true, 9, true, 4, false, 0)
	if _, ok := public["enabled"]; ok || public["enabled_raw"] != uint32(9) || public["default_inbound"] != "unrecognized:4" {
		t.Fatalf("public = %+v", public)
	}
	if _, ok := public["default_outbound"]; ok {
		t.Fatal("missing outbound action was stored")
	}
	status, value := assembleWindowsFirewall([]map[string]any{domain}, nil, "", false, false, 0, StatusCollected, StatusEmpty, StatusPermissionDenied)
	if status != StatusCollected || value["profile_status"] != nil || value["ruleset_status"] != StatusPermissionDenied || value["backend"] != "advfirewall" {
		t.Fatalf("partial = %s %+v", status, value)
	}
	status, value = assembleWindowsFirewall(nil, nil, "rule", true, false, 0, StatusEmpty, StatusEmpty, StatusCollected)
	if status != StatusCollected || value["ruleset"] != "rule" || value["truncated"] != true {
		t.Fatalf("ruleset = %s %+v", status, value)
	}
	rule, ok := parseWindowsFirewallRule("{rdp}", "v2.10|Action=Allow|Active=TRUE|Dir=In|Protocol=6|Profile=Public|LPort=3389|App=%SystemRoot%\\system32\\svchost.exe|Name=@FirewallAPI.dll,-28752|")
	if !ok || rule["action"] != "allow" || rule["direction"] != "in" || rule["protocol"] != "tcp" || rule["local_port"] != "3389" || rule["name_indirect"] != true || rule["enabled"] != true {
		t.Fatalf("rule = %+v %v", rule, ok)
	}
	anyRule, ok := parseWindowsFirewallRule("any", "v2.24|Action=Block|Active=FALSE|Dir=Out|Protocol=256|Name=Block outbound|")
	if !ok || anyRule["protocol"] != "any" || anyRule["enabled"] != false || anyRule["action"] != "block" {
		t.Fatalf("any rule = %+v %v", anyRule, ok)
	}
	if _, ok := parseWindowsFirewallRule("bad", "not-a-rule"); ok {
		t.Fatal("unrecognized rule was accepted")
	}
	rules, unparsed, truncated := collectFirewallRules([]struct{ ID, Text string }{
		{ID: "bad", Text: "legacy"},
		{ID: "any", Text: "v2.24|Action=Block|Active=FALSE|Dir=Out|Protocol=256|Name=Block outbound|"},
		{ID: "{rdp}", Text: "v2.10|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=3389|Name=@FirewallAPI.dll,-28752|"},
	})
	if unparsed != 1 || truncated || len(rules) != 2 || rules[0]["name"] != "@FirewallAPI.dll,-28752" {
		t.Fatalf("rules = %+v %d %v", rules, unparsed, truncated)
	}
	status, value = assembleWindowsFirewall(nil, rules, "", false, false, unparsed, StatusEmpty, StatusCollected, StatusUnsupported)
	if status != StatusCollected || value["rules_unparsed"] != 1 || len(value["rules"].([]map[string]any)) != 2 {
		t.Fatalf("structured = %s %+v", status, value)
	}
	status, _ = assembleWindowsFirewall(nil, nil, "", false, false, 0, StatusPermissionDenied, StatusPermissionDenied, StatusPermissionDenied)
	if status != StatusPermissionDenied {
		t.Fatal(status)
	}
	status, _ = assembleWindowsFirewall(nil, nil, "", false, false, 0, StatusError, StatusPermissionDenied, StatusEmpty)
	if status != StatusError {
		t.Fatal(status)
	}
	status, _ = assembleWindowsFirewall(nil, nil, "", false, false, 0, StatusUnsupported, StatusUnsupported, StatusUnsupported)
	if status != StatusUnsupported {
		t.Fatal(status)
	}
}
