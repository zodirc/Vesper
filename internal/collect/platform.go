package collect

import (
	"errors"
	"net"
	"os"
)

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
