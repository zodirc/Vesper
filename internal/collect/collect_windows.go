//go:build windows

package collect

import (
	"encoding/binary"
	"errors"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	// tcpTableOwnerPIDListener 是 TCP_TABLE_CLASS 中只返回监听套接字的类别。
	// tcpTableOwnerPIDListener is the TCP_TABLE_CLASS that returns listening sockets only.
	tcpTableOwnerPIDListener = 3
	// processWow64Information 是 NtQueryInformationProcess 的 ProcessWow64Information 类别。
	// processWow64Information is the ProcessWow64Information class for NtQueryInformationProcess.
	processWow64Information = 26
	maxCommandBytes         = 32768
	mbErrInvalidChars       = 0x00000008
	uninstallPath           = `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`
	wowUninstallPath        = `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`
	currentVersionPath      = `SOFTWARE\Microsoft\Windows NT\CurrentVersion`
	machineGUIDPath         = `SOFTWARE\Microsoft\Cryptography`
	firewallPolicyPath      = `SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy`
)

var (
	procGetExtendedTcpTable = windows.NewLazySystemDLL("iphlpapi.dll").NewProc("GetExtendedTcpTable")
	procGetOEMCP            = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetOEMCP")
)

// processBasicInformation 对应 32 位和 64 位的 PROCESS_BASIC_INFORMATION。
// processBasicInformation matches PROCESS_BASIC_INFORMATION on 32-bit and 64-bit Windows.
type processBasicInformation struct {
	exitStatus                   uint32
	pebBaseAddress               uintptr
	affinityMask                 uintptr
	basePriority                 int32
	uniqueProcessID              uintptr
	inheritedFromUniqueProcessID uintptr
}

func collectPlatform(operation string) (Result, error) {
	switch operation {
	case "collect_os_info":
		return collectWindowsOS()
	case "collect_interfaces":
		return collectInterfaces()
	case "collect_listening_sockets":
		return collectWindowsListening()
	case "collect_processes":
		return collectWindowsProcesses()
	case "collect_services":
		return collectWindowsServices()
	case "collect_packages":
		return collectWindowsPackages()
	case "collect_firewall_config":
		return collectWindowsFirewall()
	default:
		return Result{Operation: operation, Status: StatusUnsupported}, nil
	}
}

func collectWindowsOS() (Result, error) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, currentVersionPath, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return windowsFailure("collect_os_info", err), nil
	}
	defer key.Close()
	name, _, err := key.GetStringValue("ProductName")
	name = strings.TrimSpace(name)
	if err != nil {
		return windowsFailure("collect_os_info", err), nil
	}
	if name == "" {
		return Result{Operation: "collect_os_info", Status: StatusError, Value: map[string]any{"error": "ProductName is empty"}}, nil
	}
	display := optionalString(key, "DisplayVersion")
	release := optionalString(key, "ReleaseId")
	registryBuild := optionalString(key, "CurrentBuild")
	if registryBuild == "" {
		registryBuild = optionalString(key, "CurrentBuildNumber")
	}
	edition := optionalString(key, "EditionID")
	installType := optionalString(key, "InstallationType")
	var ubr uint32
	if value, _, err := key.GetIntegerValue("UBR"); err == nil && value <= 0xffffffff {
		ubr = uint32(value)
	}
	major, minor, build := windows.RtlGetNtVersionNumbers()
	numeric := windowsPlatformVersion(major, minor, build, ubr)
	hash := machineGUIDHash()
	value := map[string]any{
		"name":            name,
		"version":         numeric,
		"version_id":      windowsVersionID(display, release, numeric),
		"id":              "windows",
		"machine_id_hash": hash,
	}
	if text := clipText(registryBuild, 64); text != "" {
		value["registry_build"] = text
	}
	if text := clipText(edition, 128); text != "" {
		value["edition"] = text
	}
	if text := clipText(installType, 64); text != "" {
		value["installation_type"] = text
	}
	return Result{
		Operation: "collect_os_info", Status: StatusCollected,
		PlatformFamily: "windows", PlatformName: name, PlatformVersion: numeric, MachineIDHash: hash,
		Value: value,
	}, nil
}

func optionalString(key registry.Key, name string) string {
	value, _, err := key.GetStringValue(name)
	if err != nil {
		return ""
	}
	return value
}

func machineGUIDHash() string {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, machineGUIDPath, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return ""
	}
	defer key.Close()
	guid, _, err := key.GetStringValue("MachineGuid")
	guid = strings.TrimSpace(guid)
	if err != nil || guid == "" {
		return ""
	}
	return hashText(guid)
}

func collectWindowsListening() (Result, error) {
	if err := procGetExtendedTcpTable.Find(); err != nil {
		return Result{Operation: "collect_listening_sockets", Status: StatusUnsupported, Value: map[string]any{"error": "GetExtendedTcpTable is unavailable"}}, nil
	}
	v4, err4 := readTCPFamily(windows.AF_INET, false)
	v6, err6 := readTCPFamily(windows.AF_INET6, true)
	if err4 != nil && err6 != nil {
		return windowsFailure("collect_listening_sockets", err4), nil
	}
	listeners := append(v4, v6...)
	if len(listeners) == 0 && (err4 != nil || err6 != nil) {
		err := err4
		if err == nil {
			err = err6
		}
		return windowsFailure("collect_listening_sockets", err), nil
	}
	sort.Slice(listeners, func(i, j int) bool {
		if listeners[i].Port != listeners[j].Port {
			return listeners[i].Port < listeners[j].Port
		}
		if listeners[i].Address.String() != listeners[j].Address.String() {
			return listeners[i].Address.String() < listeners[j].Address.String()
		}
		return listeners[i].OwningPID < listeners[j].OwningPID
	})
	var items []map[string]any
	for _, item := range listeners {
		items = append(items, map[string]any{"address": item.Address.String(), "port": item.Port, "transport": "tcp", "owning_pid": int(item.OwningPID)})
	}
	status := StatusCollected
	if len(items) == 0 {
		status = StatusEmpty
	}
	return Result{Operation: "collect_listening_sockets", Status: status, Value: map[string]any{"sockets": items}}, nil
}

func readTCPFamily(family uint32, ipv6 bool) ([]WindowsListener, error) {
	buf, err := extendedTCPTable(family)
	if err != nil {
		return nil, err
	}
	return ParseWindowsTCPListeners(buf, ipv6)
}

func extendedTCPTable(family uint32) ([]byte, error) {
	size := uint32(4096)
	for attempt := 0; attempt < 5; attempt++ {
		if size == 0 || size > maxTCPTableBytes {
			return nil, errors.New("tcp table size is out of range")
		}
		buf := make([]byte, size)
		r1, _, _ := procGetExtendedTcpTable.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0, uintptr(family), tcpTableOwnerPIDListener, 0)
		if r1 == 0 {
			return buf, nil
		}
		if syscall.Errno(r1) != windows.ERROR_INSUFFICIENT_BUFFER {
			return nil, syscall.Errno(r1)
		}
		if size <= uint32(len(buf)) {
			return nil, windows.ERROR_INSUFFICIENT_BUFFER
		}
	}
	return nil, windows.ERROR_INSUFFICIENT_BUFFER
}

func collectWindowsProcesses() (Result, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return windowsFailure("collect_processes", err), nil
	}
	defer windows.CloseHandle(snapshot)
	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	if err := windows.Process32First(snapshot, &entry); err != nil {
		if errors.Is(err, windows.ERROR_NO_MORE_FILES) {
			return Result{Operation: "collect_processes", Status: StatusEmpty, Value: map[string]any{"processes": []map[string]any{}, "unsupported_fields": []string{"state"}}}, nil
		}
		return windowsFailure("collect_processes", err), nil
	}
	layoutOK := processBasicInformationOK()
	var records []map[string]any
	cmdlineUnreadable := 0
	for {
		if entry.ProcessID > 0 {
			command := windows.UTF16ToString(entry.ExeFile[:])
			parent := int(entry.ParentProcessID)
			item := map[string]any{"pid": int(entry.ProcessID), "ppid": parent, "command": command, "cmdline": ""}
			cmdline, truncated, executable, read := inspectProcess(entry.ProcessID)
			if layoutOK && !read {
				cmdlineUnreadable++
			}
			item["cmdline"] = cmdline
			if truncated {
				item["cmdline_truncated"] = true
			}
			if executable != "" {
				item["executable"] = executable
			}
			records = append(records, item)
		}
		err = windows.Process32Next(snapshot, &entry)
		if err != nil {
			if errors.Is(err, windows.ERROR_NO_MORE_FILES) {
				break
			}
			return windowsFailure("collect_processes", err), nil
		}
	}
	sort.Slice(records, func(i, j int) bool { return records[i]["pid"].(int) < records[j]["pid"].(int) })
	status := StatusCollected
	if len(records) == 0 {
		status = StatusEmpty
		records = []map[string]any{}
	}
	value := map[string]any{"processes": records, "unsupported_fields": []string{"state"}}
	if !layoutOK {
		value["cmdline_status"] = StatusUnsupported
	} else if cmdlineUnreadable > 0 {
		value["cmdline_unreadable"] = cmdlineUnreadable
	}
	return Result{Operation: "collect_processes", Status: status, Value: value}, nil
}

func processBasicInformationOK() bool {
	var info processBasicInformation
	switch runtime.GOARCH {
	case "amd64", "arm64":
		return unsafe.Sizeof(info) == 48 && unsafe.Offsetof(info.pebBaseAddress) == 8
	case "386", "arm":
		return unsafe.Sizeof(info) == 24 && unsafe.Offsetof(info.pebBaseAddress) == 4
	default:
		return false
	}
}

func inspectProcess(pid uint32) (string, bool, string, bool) {
	handle, limited, opened := openProcess(pid)
	if !opened {
		return "", false, "", false
	}
	defer windows.CloseHandle(handle)
	executable := processImagePath(handle)
	if limited || !processBasicInformationOK() {
		return "", false, executable, false
	}
	text, truncated, ok := readProcessCommandLine(handle)
	return text, truncated, executable, ok
}

func openProcess(pid uint32) (windows.Handle, bool, bool) {
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, pid)
	if err == nil {
		return handle, false, true
	}
	handle, err = windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return 0, false, false
	}
	return handle, true, true
}

func processImagePath(handle windows.Handle) string {
	size := uint32(windows.MAX_PATH)
	for attempt := 0; attempt < 3; attempt++ {
		if size == 0 || size > 32768 {
			return ""
		}
		buf := make([]uint16, size)
		err := windows.QueryFullProcessImageName(handle, 0, &buf[0], &size)
		if err == nil {
			return clipText(windows.UTF16ToString(buf), 2048)
		}
		if !errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) || size <= uint32(len(buf)) {
			return ""
		}
	}
	return ""
}

// readProcessCommandLine 从进程 PEB 的 RTL_USER_PROCESS_PARAMETERS.CommandLine 读取命令行。
// 64 位进程使用偏移 0x20 和 0x70；WOW64 进程改读 32 位 PEB，偏移是 0x10 和 0x40。
// readProcessCommandLine reads RTL_USER_PROCESS_PARAMETERS.CommandLine from the process PEB.
// A 64-bit process uses offsets 0x20 and 0x70. A WOW64 process uses the 32-bit PEB at offsets 0x10 and 0x40.
func readProcessCommandLine(handle windows.Handle) (string, bool, bool) {
	if unsafe.Sizeof(uintptr(0)) == 8 {
		var wow64 bool
		if err := windows.IsWow64Process(handle, &wow64); err == nil && wow64 {
			var peb32 uintptr
			var returned uint32
			err := windows.NtQueryInformationProcess(handle, processWow64Information, unsafe.Pointer(&peb32), uint32(unsafe.Sizeof(peb32)), &returned)
			if err == nil && peb32 != 0 {
				if text, truncated, ok := readCommandLineAt(handle, peb32, 0x10, 0x40, 4); ok {
					return text, truncated, true
				}
			}
		}
	}
	var info processBasicInformation
	var returned uint32
	err := windows.NtQueryInformationProcess(handle, 0, unsafe.Pointer(&info), uint32(unsafe.Sizeof(info)), &returned)
	if err != nil || info.pebBaseAddress == 0 {
		return "", false, false
	}
	paramsOffset, commandOffset, pointerSize, ok := nativeCommandOffsets()
	if !ok {
		return "", false, false
	}
	return readCommandLineAt(handle, info.pebBaseAddress, paramsOffset, commandOffset, pointerSize)
}

func nativeCommandOffsets() (uintptr, uintptr, uintptr, bool) {
	switch runtime.GOARCH {
	case "amd64", "arm64":
		return 0x20, 0x70, 8, true
	case "386", "arm":
		return 0x10, 0x40, 4, true
	default:
		return 0, 0, 0, false
	}
}

func readCommandLineAt(handle windows.Handle, peb, paramsOffset, commandOffset, pointerSize uintptr) (string, bool, bool) {
	params, err := readPointer(handle, peb+paramsOffset, pointerSize)
	if err != nil || params == 0 {
		return "", false, false
	}
	headerLen := uintptr(8)
	if pointerSize == 8 {
		headerLen = 16
	}
	header := make([]byte, headerLen)
	if err := readMemory(handle, params+commandOffset, header); err != nil {
		return "", false, false
	}
	byteLen, buffer, ok := parseRemoteUnicodeString(header)
	if !ok || buffer == 0 {
		return "", false, ok && byteLen == 0
	}
	if byteLen == 0 {
		return "", false, true
	}
	if byteLen > maxCommandBytes {
		byteLen = maxCommandBytes
	}
	raw := make([]byte, byteLen)
	if err := readMemory(handle, uintptr(buffer), raw); err != nil {
		return "", false, false
	}
	return decodeUTF16Command(raw)
}

func readPointer(handle windows.Handle, addr, size uintptr) (uintptr, error) {
	buf := make([]byte, size)
	if err := readMemory(handle, addr, buf); err != nil {
		return 0, err
	}
	if size == 8 {
		return uintptr(binary.LittleEndian.Uint64(buf)), nil
	}
	return uintptr(binary.LittleEndian.Uint32(buf)), nil
}

func readMemory(handle windows.Handle, addr uintptr, buf []byte) error {
	if len(buf) == 0 || addr == 0 {
		return errors.New("empty process memory read")
	}
	var read uintptr
	err := windows.ReadProcessMemory(handle, addr, &buf[0], uintptr(len(buf)), &read)
	if err != nil {
		return err
	}
	if read != uintptr(len(buf)) {
		return errors.New("short process memory read")
	}
	return nil
}

func collectWindowsServices() (Result, error) {
	manager, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT|windows.SC_MANAGER_ENUMERATE_SERVICE)
	if err != nil {
		return windowsFailure("collect_services", err), nil
	}
	defer windows.CloseServiceHandle(manager)
	services, err := enumWin32Services(manager)
	if err != nil {
		return windowsFailure("collect_services", err), nil
	}
	var records []map[string]any
	configUnreadable := 0
	for _, service := range services {
		start, binaryPath, account, delayed, known := uint32(0), "", "", false, false
		namePtr, err := windows.UTF16PtrFromString(service.name)
		if err != nil {
			configUnreadable++
		} else if handle, err := windows.OpenService(manager, namePtr, windows.SERVICE_QUERY_CONFIG); err != nil {
			configUnreadable++
		} else {
			start, binaryPath, account, delayed, known = serviceConfig(handle)
			windows.CloseServiceHandle(handle)
			if !known {
				configUnreadable++
			}
		}
		record, ok := windowsServiceRecord(service.name, service.display, binaryPath, account, service.state, start, known, delayed, service.pid)
		if ok {
			records = append(records, record)
		}
	}
	sort.Slice(records, func(i, j int) bool { return mapString(records[i], "name") < mapString(records[j], "name") })
	status := StatusCollected
	if len(records) == 0 {
		status = StatusEmpty
		records = []map[string]any{}
	}
	value := map[string]any{"services": records}
	if configUnreadable > 0 {
		value["config_unreadable"] = configUnreadable
	}
	return Result{Operation: "collect_services", Status: status, Value: value}, nil
}

type win32Service struct {
	name    string
	display string
	state   uint32
	pid     uint32
}

func enumWin32Services(manager windows.Handle) ([]win32Service, error) {
	var bytesNeeded, returned uint32
	var buf []byte
	for {
		var pointer *byte
		if len(buf) > 0 {
			pointer = &buf[0]
		}
		err := windows.EnumServicesStatusEx(manager, windows.SC_ENUM_PROCESS_INFO, windows.SERVICE_WIN32, windows.SERVICE_STATE_ALL, pointer, uint32(len(buf)), &bytesNeeded, &returned, nil, nil)
		if err == nil {
			break
		}
		if !errors.Is(err, windows.ERROR_MORE_DATA) || bytesNeeded <= uint32(len(buf)) {
			return nil, err
		}
		buf = make([]byte, bytesNeeded)
	}
	if returned == 0 {
		return nil, nil
	}
	entries := unsafe.Slice((*windows.ENUM_SERVICE_STATUS_PROCESS)(unsafe.Pointer(&buf[0])), int(returned))
	services := make([]win32Service, 0, len(entries))
	for _, entry := range entries {
		services = append(services, win32Service{
			name:    windows.UTF16PtrToString(entry.ServiceName),
			display: windows.UTF16PtrToString(entry.DisplayName),
			state:   entry.ServiceStatusProcess.CurrentState,
			pid:     entry.ServiceStatusProcess.ProcessId,
		})
	}
	runtime.KeepAlive(buf)
	return services, nil
}

func serviceConfig(handle windows.Handle) (uint32, string, string, bool, bool) {
	size := uint32(1024)
	var buf []byte
	var config *windows.QUERY_SERVICE_CONFIG
	for {
		buf = make([]byte, size)
		config = (*windows.QUERY_SERVICE_CONFIG)(unsafe.Pointer(&buf[0]))
		err := windows.QueryServiceConfig(handle, config, size, &size)
		if err == nil {
			break
		}
		if !errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) || size <= uint32(len(buf)) {
			return 0, "", "", false, false
		}
	}
	start := config.StartType
	binaryPath := windows.UTF16PtrToString(config.BinaryPathName)
	account := windows.UTF16PtrToString(config.ServiceStartName)
	runtime.KeepAlive(buf)
	return start, binaryPath, account, serviceDelayed(handle), true
}

func serviceDelayed(handle windows.Handle) bool {
	var info windows.SERVICE_DELAYED_AUTO_START_INFO
	var needed uint32
	err := windows.QueryServiceConfig2(handle, windows.SERVICE_CONFIG_DELAYED_AUTO_START_INFO, (*byte)(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info)), &needed)
	return err == nil && info.IsDelayedAutoStartUp != 0
}

func collectWindowsPackages() (Result, error) {
	machine := uint32(registry.READ | registry.WOW64_64KEY)
	groups := []packageHive{
		readUninstallHive(registry.LOCAL_MACHINE, uninstallPath, machine, "native", "machine"),
		readUninstallHive(registry.LOCAL_MACHINE, wowUninstallPath, machine, "wow64", "machine"),
		readUninstallHive(registry.CURRENT_USER, uninstallPath, registry.READ, "native", "user"),
		readUninstallHive(registry.CURRENT_USER, wowUninstallPath, registry.READ, "wow64", "user"),
	}
	status, value := mergePackageHives(groups)
	return Result{Operation: "collect_packages", Status: status, Value: value}, nil
}

func readUninstallHive(root registry.Key, path string, access uint32, view, scope string) packageHive {
	key, err := registry.OpenKey(root, path, access)
	if err != nil {
		return packageHive{status: windowsStatus(err)}
	}
	defer key.Close()
	names, err := key.ReadSubKeyNames(0)
	if err != nil {
		return packageHive{status: windowsStatus(err)}
	}
	var records []map[string]any
	denied := 0
	for _, name := range names {
		sub, err := registry.OpenKey(key, name, registry.QUERY_VALUE)
		if err != nil {
			if windowsStatus(err) == StatusPermissionDenied {
				denied++
			}
			continue
		}
		record, ok := readUninstallEntry(sub, view, scope)
		sub.Close()
		if ok {
			records = append(records, record)
		}
	}
	if len(records) == 0 && denied > 0 && denied == len(names) {
		return packageHive{status: StatusPermissionDenied}
	}
	status := StatusEmpty
	if len(records) > 0 {
		status = StatusCollected
	}
	return packageHive{records: records, status: status, unreadable: denied}
}

func readUninstallEntry(key registry.Key, view, scope string) (map[string]any, bool) {
	name, ok := registryString(key, "DisplayName")
	if !ok {
		return nil, false
	}
	version, _ := registryString(key, "DisplayVersion")
	publisher, _ := registryString(key, "Publisher")
	system, _ := registryDWORD(key, "SystemComponent")
	return windowsPackageRecord(name, version, publisher, view, scope, system == 1)
}

func registryString(key registry.Key, name string) (string, bool) {
	value, kind, err := key.GetStringValue(name)
	if err != nil {
		return "", false
	}
	if kind == registry.EXPAND_SZ && strings.Contains(value, "%") {
		if expanded, err := expandEnv(value); err == nil && strings.TrimSpace(expanded) != "" {
			value = expanded
		}
	}
	value = strings.TrimSpace(value)
	return value, value != ""
}

func registryDWORD(key registry.Key, name string) (uint32, bool) {
	value, _, err := key.GetIntegerValue(name)
	if err != nil || value > 0xffffffff {
		return 0, false
	}
	return uint32(value), true
}

func expandEnv(value string) (string, error) {
	source, err := windows.UTF16PtrFromString(value)
	if err != nil {
		return "", err
	}
	size, err := windows.ExpandEnvironmentStrings(source, nil, 0)
	if err != nil || size == 0 {
		return "", err
	}
	buf := make([]uint16, size)
	size, err = windows.ExpandEnvironmentStrings(source, &buf[0], uint32(len(buf)))
	if err != nil || size == 0 {
		return "", err
	}
	return windows.UTF16ToString(buf[:size]), nil
}

func collectWindowsFirewall() (Result, error) {
	profiles, profileStatus, rules, rulesTruncated, rulesUnparsed, ruleStatus := readFirewallPolicy()
	ruleset, textTruncated, rulesetStatus := readFirewallRuleset()
	status, value := assembleWindowsFirewall(profiles, rules, ruleset, textTruncated, rulesTruncated, rulesUnparsed, profileStatus, ruleStatus, rulesetStatus)
	if status == StatusPermissionDenied {
		value["error"] = "permission denied"
	}
	if status == StatusError {
		if _, ok := value["error"]; !ok {
			value["error"] = "firewall query failed"
		}
	}
	return Result{Operation: "collect_firewall_config", Status: status, Value: value}, nil
}

func readFirewallPolicy() ([]map[string]any, string, []map[string]any, bool, int, string) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, firewallPolicyPath, registry.READ|registry.WOW64_64KEY)
	if err != nil {
		status := windowsStatus(err)
		return nil, status, nil, false, 0, status
	}
	defer key.Close()
	profiles, profileStatus := readFirewallProfiles(key)
	rules, truncated, unparsed, ruleStatus := readFirewallRuleValues(key)
	return profiles, profileStatus, rules, truncated, unparsed, ruleStatus
}

func readFirewallProfiles(key registry.Key) ([]map[string]any, string) {
	specs := []struct {
		name string
		sub  string
	}{
		{name: "domain", sub: "DomainProfile"},
		{name: "private", sub: "StandardProfile"},
		{name: "public", sub: "PublicProfile"},
	}
	var profiles []map[string]any
	for _, spec := range specs {
		sub, err := registry.OpenKey(key, spec.sub, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		enabled, enabledOK := registryDWORD(sub, "EnableFirewall")
		inbound, inboundOK := registryDWORD(sub, "DefaultInboundAction")
		outbound, outboundOK := registryDWORD(sub, "DefaultOutboundAction")
		sub.Close()
		profiles = append(profiles, windowsFirewallProfile(spec.name, enabledOK, enabled, inboundOK, inbound, outboundOK, outbound))
	}
	if len(profiles) == 0 {
		return nil, StatusEmpty
	}
	return profiles, StatusCollected
}

func readFirewallRuleValues(key registry.Key) ([]map[string]any, bool, int, string) {
	rulesKey, err := registry.OpenKey(key, "FirewallRules", registry.QUERY_VALUE)
	if err != nil {
		return nil, false, 0, windowsStatus(err)
	}
	defer rulesKey.Close()
	names, err := rulesKey.ReadValueNames(0)
	if err != nil {
		return nil, false, 0, windowsStatus(err)
	}
	entries := make([]struct{ ID, Text string }, 0, len(names))
	for _, name := range names {
		text, _, err := rulesKey.GetStringValue(name)
		if err != nil {
			entries = append(entries, struct{ ID, Text string }{ID: name, Text: "unreadable"})
			continue
		}
		entries = append(entries, struct{ ID, Text string }{ID: name, Text: text})
	}
	rules, unparsed, truncated := collectFirewallRules(entries)
	if len(rules) == 0 && unparsed == 0 {
		return nil, false, 0, StatusEmpty
	}
	return rules, truncated, unparsed, StatusCollected
}

func readFirewallRuleset() (string, bool, string) {
	path, err := exec.LookPath("netsh")
	if err != nil {
		return "", false, StatusUnsupported
	}
	stdout, result, failed := runCommand("collect_firewall_config", path, "advfirewall", "firewall", "show", "rule", "name=all")
	if failed {
		return "", false, result.Status
	}
	return finishRuleset(stdout)
}

func finishRuleset(stdout string) (string, bool, string) {
	text, ok := decodePossibleText([]byte(stdout))
	if !ok {
		decoded, err := decodeConsoleBytes([]byte(stdout))
		if err != nil {
			return "", false, StatusError
		}
		text = decoded
	}
	text, truncated := BoundText(strings.TrimSpace(text))
	if text == "" {
		return "", false, StatusEmpty
	}
	return text, truncated, StatusCollected
}

func decodeConsoleBytes(body []byte) (string, error) {
	if text, err := decodeCodePage(oemCP(), body); err == nil {
		return text, nil
	}
	return decodeCodePage(windows.GetACP(), body)
}

func oemCP() uint32 {
	r1, _, _ := procGetOEMCP.Call()
	return uint32(r1)
}

func decodeCodePage(codePage uint32, body []byte) (string, error) {
	if codePage == 0 || len(body) == 0 {
		return "", errors.New("text code page is unavailable")
	}
	n, err := windows.MultiByteToWideChar(codePage, mbErrInvalidChars, &body[0], int32(len(body)), nil, 0)
	if err != nil || n <= 0 {
		n, err = windows.MultiByteToWideChar(codePage, 0, &body[0], int32(len(body)), nil, 0)
		if err != nil || n <= 0 {
			return "", errors.New("text code page conversion failed")
		}
	}
	buf := make([]uint16, n)
	flags := uint32(mbErrInvalidChars)
	n, err = windows.MultiByteToWideChar(codePage, flags, &body[0], int32(len(body)), &buf[0], int32(len(buf)))
	if err != nil || n <= 0 {
		n, err = windows.MultiByteToWideChar(codePage, 0, &body[0], int32(len(body)), &buf[0], int32(len(buf)))
		if err != nil || n <= 0 {
			return "", errors.New("text code page conversion failed")
		}
	}
	return windows.UTF16ToString(buf[:n]), nil
}

func windowsFailure(operation string, err error) Result {
	message := err.Error()
	if len(message) > 512 {
		message = message[:512]
	}
	return Result{Operation: operation, Status: windowsStatus(err), Value: map[string]any{"error": message}}
}

func windowsStatus(err error) string {
	if errors.Is(err, os.ErrPermission) || errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		return StatusPermissionDenied
	}
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, registry.ErrNotExist) || errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
		return StatusUnsupported
	}
	return StatusError
}
