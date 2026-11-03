//go:build linux

package collect

import (
	"bufio"
	"errors"
	"net"
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
		Value:         map[string]any{"name": values["NAME"], "version_id": values["VERSION_ID"], "id": values["ID"], "machine_id_hash": hash},
	}, nil
}

func collectInterfaces() (Result, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return deniedOrError("collect_interfaces", err), nil
	}
	var items []map[string]any
	for _, iface := range ifaces {
		addrs, _ := iface.Addrs()
		var texts []string
		for _, addr := range addrs {
			texts = append(texts, addr.String())
		}
		items = append(items, map[string]any{"name": iface.Name, "hardware_addr": iface.HardwareAddr.String(), "addresses": texts})
	}
	status := StatusCollected
	if len(items) == 0 {
		status = StatusEmpty
	}
	return Result{Operation: "collect_interfaces", Status: status, Value: map[string]any{"interfaces": items}}, nil
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

func deniedOrError(operation string, err error) Result {
	status := StatusError
	if errors.Is(err, os.ErrPermission) {
		status = StatusPermissionDenied
	}
	if errors.Is(err, os.ErrNotExist) {
		status = StatusUnsupported
	}
	return Result{Operation: operation, Status: status, Value: map[string]any{"error": err.Error()}}
}
