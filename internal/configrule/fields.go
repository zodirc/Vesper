package configrule

// collectedFields 是采集器实际写入的字段。规则只能引用这些字段，避免把不存在的名字判断成失败。
// collectedFields lists the fields collectors actually write. A rule can only reference these fields, so a name that is never collected is not judged as a failure.
type collectedSpec struct {
	scalars map[string]struct{}
	lists   map[string]map[string]struct{}
}

var collectedFields = map[string]collectedSpec{
	"collect_os_info": {
		scalars: set("name", "version_id", "id", "machine_id_hash"),
	},
	"collect_interfaces": {
		lists: map[string]map[string]struct{}{
			"interfaces": set("name", "hardware_addr", "addresses"),
		},
	},
	"collect_listening_sockets": {
		lists: map[string]map[string]struct{}{
			"sockets": set("address", "port", "transport"),
		},
	},
	"collect_processes": {
		lists: map[string]map[string]struct{}{
			"processes": set("pid", "command", "cmdline", "state", "cmdline_truncated"),
		},
	},
	"collect_services": {
		lists: map[string]map[string]struct{}{
			"services": set("name", "load", "active", "sub"),
		},
	},
	"collect_packages": {
		lists: map[string]map[string]struct{}{
			"packages": set("name", "version", "architecture", "source", "epoch", "release"),
		},
	},
	"collect_firewall_config": {
		scalars: set("backend", "ruleset", "truncated"),
	},
}

func set(items ...string) map[string]struct{} {
	out := make(map[string]struct{}, len(items))
	for _, item := range items {
		out[item] = struct{}{}
	}
	return out
}
