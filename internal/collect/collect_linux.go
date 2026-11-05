//go:build linux

package collect

import (
	"bufio"
	"os"
	"strings"
)

func collectPlatform(operation string) (Result, error) {
	switch operation {
	case "collect_os_info":
		return collectOS()
	case "collect_interfaces":
		return collectInterfaces()
	case "collect_listening_sockets":
		return collectListening()
	case "collect_processes":
		return collectProcesses()
	case "collect_services":
		return collectServices()
	case "collect_packages":
		return collectPackages()
	case "collect_firewall_config":
		return collectFirewall()
	default:
		return Result{Operation: operation, Status: StatusUnsupported}, nil
	}
}

func collectOS() (Result, error) {
	file, err := os.Open("/etc/os-release")
	if err != nil {
		return deniedOrError("collect_os_info", err), nil
	}
	defer file.Close()
	values := map[string]string{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		name, value, ok := strings.Cut(scanner.Text(), "=")
		if !ok {
			continue
		}
		values[name] = strings.Trim(value, `"`)
	}
	if err := scanner.Err(); err != nil {
		return Result{Operation: "collect_os_info", Status: StatusError, Value: map[string]any{"error": err.Error()}}, nil
	}
	hash := ""
	machine, err := os.ReadFile("/etc/machine-id")
	if err == nil {
		hash = hashText(strings.TrimSpace(string(machine)))
	}
	return Result{
		Operation: "collect_os_info", Status: StatusCollected,
		PlatformFamily: "linux", PlatformName: values["NAME"], PlatformVersion: values["VERSION_ID"],
		MachineIDHash: hash,
		Value:         map[string]any{"name": values["NAME"], "version_id": values["VERSION_ID"], "id": values["ID"], "version_codename": values["VERSION_CODENAME"], "machine_id_hash": hash},
	}, nil
}

func collectListening() (Result, error) {
	v4, err4 := readProc("/proc/net/tcp", "tcp")
	v6, err6 := readProc("/proc/net/tcp6", "tcp")
	if err4 != nil && err6 != nil {
		return deniedOrError("collect_listening_sockets", err4), nil
	}
	sockets := append(v4, v6...)
	status := StatusCollected
	if len(sockets) == 0 {
		status = StatusEmpty
	}
	var items []map[string]any
	for _, socket := range sockets {
		items = append(items, map[string]any{"address": socket.Address.String(), "port": socket.Port, "transport": socket.Transport})
	}
	return Result{Operation: "collect_listening_sockets", Status: status, Value: map[string]any{"sockets": items}}, nil
}

func readProc(path, transport string) ([]Socket, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return ParseProcNet(file, transport)
}
