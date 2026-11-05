package collect

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

const (
	tcpListenerState = 2
	ipv4RowSize      = 24
	ipv6RowSize      = 56
	maxTCPTableBytes = 32 << 20
)

// WindowsListener 是一条 Windows TCP 监听记录。
// WindowsListener is one Windows TCP listening record.
type WindowsListener struct {
	Address   netip.Addr
	Port      int
	OwningPID uint32
}

// ParseWindowsTCPListeners 解析 GetExtendedTcpTable 在 TCP_TABLE_OWNER_PID_LISTENER 类别下返回的表。
// ParseWindowsTCPListeners parses a GetExtendedTcpTable buffer for TCP_TABLE_OWNER_PID_LISTENER.
//
// ipv6 为 false 时按 MIB_TCPROW_OWNER_PID 解析，为 true 时按 MIB_TCP6ROW_OWNER_PID 解析。只保留状态为 LISTEN 的行。端口按网络字节序还原。表被截断或条目数与长度不符时返回错误。
// When ipv6 is false the rows are MIB_TCPROW_OWNER_PID. When ipv6 is true the rows are MIB_TCP6ROW_OWNER_PID. Only LISTEN rows are kept. Ports are converted from network byte order. A short table or a count that does not fit the buffer returns an error.
func ParseWindowsTCPListeners(buf []byte, ipv6 bool) ([]WindowsListener, error) {
	if len(buf) == 0 {
		return nil, nil
	}
	if len(buf) < 4 || len(buf) > maxTCPTableBytes {
		return nil, fmt.Errorf("parse windows tcp table: length %d", len(buf))
	}
	count := binary.LittleEndian.Uint32(buf[:4])
	rowSize := ipv4RowSize
	if ipv6 {
		rowSize = ipv6RowSize
	}
	if count > uint32((len(buf)-4)/rowSize) {
		return nil, fmt.Errorf("parse windows tcp table: count %d exceeds length %d", count, len(buf))
	}
	var listeners []WindowsListener
	for i := uint32(0); i < count; i++ {
		row := buf[4+int(i)*rowSize : 4+int(i+1)*rowSize]
		item, ok := parseTCPListenerRow(row, ipv6)
		if ok {
			listeners = append(listeners, item)
		}
	}
	return listeners, nil
}

func parseTCPListenerRow(row []byte, ipv6 bool) (WindowsListener, bool) {
	var state uint32
	var addr netip.Addr
	var port uint32
	var pid uint32
	if ipv6 {
		if len(row) < ipv6RowSize {
			return WindowsListener{}, false
		}
		var raw [16]byte
		copy(raw[:], row[:16])
		addr = netip.AddrFrom16(raw).Unmap()
		port = binary.LittleEndian.Uint32(row[20:24])
		state = binary.LittleEndian.Uint32(row[48:52])
		pid = binary.LittleEndian.Uint32(row[52:56])
	} else {
		if len(row) < ipv4RowSize {
			return WindowsListener{}, false
		}
		state = binary.LittleEndian.Uint32(row[0:4])
		raw := binary.LittleEndian.Uint32(row[4:8])
		addr = netip.AddrFrom4([4]byte{byte(raw), byte(raw >> 8), byte(raw >> 16), byte(raw >> 24)})
		port = binary.LittleEndian.Uint32(row[8:12])
		pid = binary.LittleEndian.Uint32(row[20:24])
	}
	if state != tcpListenerState {
		return WindowsListener{}, false
	}
	return WindowsListener{Address: addr, Port: ntohs(port), OwningPID: pid}, true
}

func ntohs(port uint32) int {
	return int((port&0xff)<<8 | (port>>8)&0xff)
}

// parseRemoteUnicodeString 读取远程进程中的 UNICODE_STRING 头。64 位头长 16 字节，32 位头长 8 字节。
// parseRemoteUnicodeString reads a UNICODE_STRING header from another process. A 64-bit header is 16 bytes and a 32-bit header is 8 bytes.
func parseRemoteUnicodeString(header []byte) (byteLen int, buffer uint64, ok bool) {
	if len(header) != 8 && len(header) != 16 {
		return 0, 0, false
	}
	n := int(binary.LittleEndian.Uint16(header[:2]))
	if n%2 != 0 {
		return 0, 0, false
	}
	if len(header) == 16 {
		return n, binary.LittleEndian.Uint64(header[8:16]), true
	}
	return n, uint64(binary.LittleEndian.Uint32(header[4:8])), true
}

func decodeUTF16Command(raw []byte) (string, bool, bool) {
	if len(raw)%2 != 0 {
		return "", false, false
	}
	units := make([]uint16, len(raw)/2)
	for i := range units {
		units[i] = binary.LittleEndian.Uint16(raw[i*2:])
	}
	text, truncated := boundCommandLine(string(utf16.Decode(units)))
	return text, truncated, true
}

func decodePossibleText(body []byte) (string, bool) {
	body = bytes.TrimSpace(body)
	if len(body) == 0 {
		return "", true
	}
	if bytes.HasPrefix(body, []byte{0xFF, 0xFE}) && (len(body)-2)%2 == 0 {
		units := make([]uint16, (len(body)-2)/2)
		for i := range units {
			units[i] = binary.LittleEndian.Uint16(body[2+i*2:])
		}
		return string(utf16.Decode(units)), true
	}
	if bytes.HasPrefix(body, []byte{0xFE, 0xFF}) && (len(body)-2)%2 == 0 {
		units := make([]uint16, (len(body)-2)/2)
		for i := range units {
			units[i] = binary.BigEndian.Uint16(body[2+i*2:])
		}
		return string(utf16.Decode(units)), true
	}
	body = bytes.TrimPrefix(body, []byte{0xEF, 0xBB, 0xBF})
	if utf8.Valid(body) {
		return string(body), true
	}
	return "", false
}

func windowsPlatformVersion(major, minor, build, ubr uint32) string {
	if ubr > 0 {
		return fmt.Sprintf("%d.%d.%d.%d", major, minor, build, ubr)
	}
	return fmt.Sprintf("%d.%d.%d", major, minor, build)
}

func windowsVersionID(display, release, numeric string) string {
	if text := strings.TrimSpace(display); text != "" {
		return text
	}
	if text := strings.TrimSpace(release); text != "" {
		return text
	}
	return numeric
}

func windowsServiceRecord(name, display, binaryPath, account string, state, start uint32, startKnown, delayed bool, pid uint32) (map[string]any, bool) {
	name = clipText(name, 256)
	if name == "" {
		return nil, false
	}
	active, sub := windowsServiceState(state)
	item := map[string]any{"name": name, "load": "loaded", "active": active, "sub": sub}
	if text := clipText(display, 512); text != "" {
		item["display_name"] = text
	}
	if startKnown {
		item["start_type"] = windowsStartType(start, delayed)
	}
	if pid > 0 {
		item["pid"] = int(pid)
	}
	if text := clipText(binaryPath, 2048); text != "" {
		item["binary_path"] = text
	}
	if text := clipText(account, 256); text != "" {
		item["account"] = text
	}
	return item, true
}

func windowsServiceState(state uint32) (string, string) {
	switch state {
	case 1:
		return "inactive", "stopped"
	case 2:
		return "activating", "start-pending"
	case 3:
		return "deactivating", "stop-pending"
	case 4:
		return "active", "running"
	case 5:
		return "activating", "continue-pending"
	case 6:
		return "deactivating", "pause-pending"
	case 7:
		return "active", "paused"
	default:
		return "unrecognized", fmt.Sprintf("%d", state)
	}
}

func windowsStartType(start uint32, delayed bool) string {
	switch start {
	case 0:
		return "boot"
	case 1:
		return "system"
	case 2:
		if delayed {
			return "automatic-delayed"
		}
		return "automatic"
	case 3:
		return "manual"
	case 4:
		return "disabled"
	default:
		return fmt.Sprintf("unrecognized:%d", start)
	}
}

func windowsPackageRecord(name, version, publisher, view, scope string, systemComponent bool) (map[string]any, bool) {
	name = clipText(name, 512)
	if name == "" {
		return nil, false
	}
	item := map[string]any{
		"name":          name,
		"version":       clipText(version, 512),
		"source":        "registry",
		"registry_view": view,
		"scope":         scope,
	}
	if text := clipText(publisher, 512); text != "" {
		item["publisher"] = text
	}
	if systemComponent {
		item["system_component"] = true
	}
	return item, true
}

type packageHive struct {
	records    []map[string]any
	status     string
	unreadable int
}

func mergePackageHives(groups []packageHive) (string, map[string]any) {
	seen := map[string]struct{}{}
	var records []map[string]any
	opened := false
	denied := 0
	failed := 0
	partial := 0
	for _, group := range groups {
		partial += group.unreadable
		switch group.status {
		case StatusCollected, StatusEmpty:
			opened = true
		case StatusPermissionDenied:
			denied++
		case StatusUnsupported:
		default:
			failed++
		}
		for _, item := range group.records {
			key := packageIdentity(item)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			records = append(records, item)
		}
	}
	sort.Slice(records, func(i, j int) bool {
		if mapString(records[i], "name") != mapString(records[j], "name") {
			return mapString(records[i], "name") < mapString(records[j], "name")
		}
		if mapString(records[i], "version") != mapString(records[j], "version") {
			return mapString(records[i], "version") < mapString(records[j], "version")
		}
		if mapString(records[i], "registry_view") != mapString(records[j], "registry_view") {
			return mapString(records[i], "registry_view") < mapString(records[j], "registry_view")
		}
		return mapString(records[i], "scope") < mapString(records[j], "scope")
	})
	if len(records) > 0 || opened {
		if records == nil {
			records = []map[string]any{}
		}
		value := map[string]any{
			"source":             "registry",
			"packages":           records,
			"unsupported_fields": []string{"architecture", "epoch", "release"},
		}
		if denied+failed+partial > 0 {
			value["unreadable"] = denied + failed + partial
		}
		if len(records) == 0 {
			return StatusEmpty, value
		}
		return StatusCollected, value
	}
	if failed > 0 {
		return StatusError, map[string]any{"error": "registry query failed", "source": "registry"}
	}
	if denied > 0 {
		return StatusPermissionDenied, map[string]any{"error": "permission denied", "source": "registry"}
	}
	return StatusUnsupported, map[string]any{"source": "registry"}
}

func packageIdentity(item map[string]any) string {
	return mapString(item, "name") + "\x00" + mapString(item, "version") + "\x00" + mapString(item, "publisher") + "\x00" + mapString(item, "registry_view") + "\x00" + mapString(item, "scope")
}

func mapString(item map[string]any, key string) string {
	text, _ := item[key].(string)
	return text
}

func windowsFirewallProfile(name string, enableOK bool, enable uint32, inboundOK bool, inbound uint32, outboundOK bool, outbound uint32) map[string]any {
	item := map[string]any{"name": name}
	if enableOK {
		switch enable {
		case 0:
			item["enabled"] = false
		case 1:
			item["enabled"] = true
		default:
			item["enabled_raw"] = enable
		}
	}
	if inboundOK {
		item["default_inbound"] = firewallAction(inbound)
	}
	if outboundOK {
		item["default_outbound"] = firewallAction(outbound)
	}
	return item
}

func firewallAction(value uint32) string {
	switch value {
	case 0:
		return "block"
	case 1:
		return "allow"
	default:
		return fmt.Sprintf("unrecognized:%d", value)
	}
}

const maxFirewallRules = 4096

func parseWindowsFirewallRule(id, text string) (map[string]any, bool) {
	text = strings.TrimSpace(text)
	if !strings.HasPrefix(text, "v2.") {
		return nil, false
	}
	fields := map[string]string{}
	for _, part := range strings.Split(text, "|") {
		key, value, ok := strings.Cut(part, "=")
		if !ok || key == "" {
			continue
		}
		fields[key] = value
	}
	name := clipText(fields["Name"], 512)
	if name == "" {
		return nil, false
	}
	item := map[string]any{"name": name}
	if id = clipText(id, 256); id != "" {
		item["id"] = id
	}
	if strings.HasPrefix(name, "@") {
		item["name_indirect"] = true
	}
	if action, ok := firewallToken(fields["Action"], "allow", "block"); ok {
		item["action"] = action
	}
	if direction, ok := firewallToken(fields["Dir"], "in", "out"); ok {
		item["direction"] = direction
	}
	switch strings.ToLower(fields["Active"]) {
	case "true", "1":
		item["enabled"] = true
	case "false", "0":
		item["enabled"] = false
	}
	if protocol := firewallProtocol(fields["Protocol"]); protocol != "" {
		item["protocol"] = protocol
	}
	assignClip(item, "profile", fields["Profile"], 128)
	assignClip(item, "local_port", fields["LPort"], 256)
	assignClip(item, "remote_port", fields["RPort"], 256)
	assignClip(item, "local_address", firstNonEmpty(fields["LA4"], fields["LA6"], fields["LA"]), 512)
	assignClip(item, "remote_address", firstNonEmpty(fields["RA4"], fields["RA6"], fields["RA"]), 512)
	assignClip(item, "app", fields["App"], 2048)
	assignClip(item, "service", fields["Svc"], 256)
	return item, true
}

func firewallToken(value string, accepted ...string) (string, bool) {
	token := strings.ToLower(strings.TrimSpace(value))
	if token == "" {
		return "", false
	}
	for _, item := range accepted {
		if token == item {
			return item, true
		}
	}
	return token, true
}

func firewallProtocol(value string) string {
	switch strings.TrimSpace(value) {
	case "":
		return ""
	case "256":
		return "any"
	case "6":
		return "tcp"
	case "17":
		return "udp"
	case "1":
		return "icmp"
	case "58":
		return "ipv6-icmp"
	default:
		return clipText(value, 32)
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func assignClip(item map[string]any, key, value string, limit int) {
	if text := clipText(value, limit); text != "" {
		item[key] = text
	}
}

func collectFirewallRules(entries []struct{ ID, Text string }) ([]map[string]any, int, bool) {
	var rules []map[string]any
	unparsed := 0
	truncated := false
	for _, entry := range entries {
		rule, ok := parseWindowsFirewallRule(entry.ID, entry.Text)
		if !ok {
			if strings.TrimSpace(entry.Text) != "" {
				unparsed++
			}
			continue
		}
		if len(rules) >= maxFirewallRules {
			truncated = true
			continue
		}
		rules = append(rules, rule)
	}
	sort.Slice(rules, func(i, j int) bool {
		if mapString(rules[i], "name") != mapString(rules[j], "name") {
			return mapString(rules[i], "name") < mapString(rules[j], "name")
		}
		return mapString(rules[i], "id") < mapString(rules[j], "id")
	})
	return rules, unparsed, truncated
}

func assembleWindowsFirewall(profiles, rules []map[string]any, ruleset string, textTruncated, rulesTruncated bool, rulesUnparsed int, profileStatus, ruleStatus, rulesetStatus string) (string, map[string]any) {
	value := map[string]any{"backend": "advfirewall"}
	if len(profiles) > 0 {
		value["profiles"] = profiles
	}
	if len(rules) > 0 {
		value["rules"] = rules
	}
	if rulesUnparsed > 0 {
		value["rules_unparsed"] = rulesUnparsed
	}
	if rulesTruncated {
		value["rules_truncated"] = true
	}
	if ruleset != "" {
		value["ruleset"] = ruleset
		if textTruncated {
			value["truncated"] = true
		}
	}
	if profileStatus != "" && profileStatus != StatusCollected && profileStatus != StatusEmpty {
		value["profile_status"] = profileStatus
	}
	if ruleStatus != "" && ruleStatus != StatusCollected && ruleStatus != StatusEmpty {
		value["rules_status"] = ruleStatus
	}
	if rulesetStatus != "" && rulesetStatus != StatusCollected && rulesetStatus != StatusEmpty {
		value["ruleset_status"] = rulesetStatus
	}
	if len(profiles) > 0 || len(rules) > 0 || ruleset != "" || rulesUnparsed > 0 {
		return StatusCollected, value
	}
	return combineCollectorStatus(profileStatus, ruleStatus, rulesetStatus), value
}

func combineCollectorStatus(statuses ...string) string {
	denied := false
	empty := false
	for _, status := range statuses {
		switch status {
		case StatusError:
			return StatusError
		case StatusPermissionDenied:
			denied = true
		case StatusEmpty:
			empty = true
		}
	}
	if denied {
		return StatusPermissionDenied
	}
	if empty {
		return StatusEmpty
	}
	return StatusUnsupported
}

func clipText(text string, limit int) string {
	text = strings.TrimSpace(text)
	if limit <= 0 || text == "" {
		return ""
	}
	if len(text) <= limit {
		return text
	}
	end := limit
	for end > 0 && !utf8.RuneStart(text[end]) {
		end--
	}
	return text[:end]
}
