//go:build linux

package collect

import (
	"io"
	"os"
	"os/exec"
	"strings"
)

func collectProcesses() (Result, error) {
	records, unreadable, err := ReadProcesses("/proc")
	if err != nil {
		return deniedOrError("collect_processes", err), nil
	}
	return inventoryResult("collect_processes", records, "processes", unreadable), nil
}

func collectServices() (Result, error) {
	path, err := exec.LookPath("systemctl")
	if err != nil {
		return Result{Operation: "collect_services", Status: StatusUnsupported}, nil
	}
	stdout, result, failed := runCommand("collect_services", path, "list-units", "--type=service", "--all", "--plain", "--no-legend", "--no-pager")
	if failed {
		return result, nil
	}
	records := ParseServiceList(stdout)
	return inventoryResult("collect_services", records, "services", 0), nil
}

func collectPackages() (Result, error) {
	if path, err := exec.LookPath("rpm"); err == nil {
		stdout, result, failed := runCommand("collect_packages", path, "-qa", "--queryformat", "%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\n")
		if failed {
			return result, nil
		}
		records, err := ParseRPMQuery(stdout)
		if err != nil {
			return Result{Operation: "collect_packages", Status: StatusError, Value: map[string]any{"error": err.Error(), "source": "rpm"}}, nil
		}
		item := inventoryResult("collect_packages", records, "packages", 0)
		item.Value["source"] = "rpm"
		return item, nil
	}
	file, err := os.Open("/var/lib/dpkg/status")
	if err != nil {
		if os.IsNotExist(err) {
			return Result{Operation: "collect_packages", Status: StatusUnsupported}, nil
		}
		return deniedOrError("collect_packages", err), nil
	}
	defer file.Close()
	body, err := io.ReadAll(io.LimitReader(file, 64<<20+1))
	if err != nil {
		return Result{Operation: "collect_packages", Status: StatusError, Value: map[string]any{"error": err.Error(), "source": "dpkg"}}, nil
	}
	if len(body) > 64<<20 {
		return Result{Operation: "collect_packages", Status: StatusError, Value: map[string]any{"error": "dpkg status exceeds 64MiB", "source": "dpkg"}}, nil
	}
	records := ParseDpkgStatus(string(body))
	item := inventoryResult("collect_packages", records, "packages", 0)
	item.Value["source"] = "dpkg"
	return item, nil
}

func collectFirewall() (Result, error) {
	if path, err := exec.LookPath("nft"); err == nil {
		return readFirewall("nft", path, "list", "ruleset")
	}
	if path, err := exec.LookPath("iptables-save"); err == nil {
		return readFirewall("iptables", path)
	}
	return Result{Operation: "collect_firewall_config", Status: StatusUnsupported}, nil
}

func readFirewall(backend, path string, args ...string) (Result, error) {
	stdout, result, failed := runCommand("collect_firewall_config", path, args...)
	if failed {
		return result, nil
	}
	text, truncated := BoundText(strings.TrimSpace(stdout))
	if text == "" {
		return Result{Operation: "collect_firewall_config", Status: StatusEmpty, Value: map[string]any{"backend": backend}}, nil
	}
	value := map[string]any{"backend": backend, "ruleset": text}
	if truncated {
		value["truncated"] = true
	}
	return Result{Operation: "collect_firewall_config", Status: StatusCollected, Value: value}, nil
}
