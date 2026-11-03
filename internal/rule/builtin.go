package rule

import "time"

const (
	// FingerprintVersion 是内置指纹包版本。
	// FingerprintVersion is the built-in fingerprint pack version.
	FingerprintVersion = "builtin-1"
	// ConfigVersion 是内置配置包版本。
	// ConfigVersion is the built-in configuration pack version.
	ConfigVersion = "builtin-1"
)

// Builtin 返回已发布的内置指纹包和配置包。
// Builtin returns the published built-in fingerprint and configuration packs.
func Builtin(now time.Time) ([]Pack, error) {
	fingerprint, err := Seal(Pack{
		ID: StableID("pack:fingerprint:" + FingerprintVersion), Type: "fingerprint", Version: FingerprintVersion,
		SchemaVersion: SchemaVersion, Source: "builtin", CreatedAt: now.UTC(),
		Fingerprints: []FingerprintRule{
			{
				ID: StableID("fingerprint:http"), Key: "http", Version: FingerprintVersion, Priority: 10,
				TargetProtocol: "http", ServiceType: "http",
				Conditions:        []Condition{{Field: "protocol", Op: "equals", Value: "http"}},
				Extractors:        []Extractor{{Target: "product", Source: "headers.server", Method: "server_token"}},
				ConfidenceMatched: "0.8500", ConfidenceEmpty: "0.7000",
			},
			{
				ID: StableID("fingerprint:tls"), Key: "tls", Version: FingerprintVersion, Priority: 10,
				TargetProtocol: "tls", ServiceType: "tls",
				Conditions:        []Condition{{Field: "protocol", Op: "equals", Value: "tls"}},
				ConfidenceMatched: "0.7000", ConfidenceEmpty: "0.7000",
			},
			{
				ID: StableID("fingerprint:ssh"), Key: "ssh", Version: FingerprintVersion, Priority: 10,
				TargetProtocol: "ssh", ServiceType: "ssh",
				Conditions: []Condition{
					{Field: "protocol", Op: "equals", Value: "ssh"},
					{Field: "banner", Op: "prefix", Value: "SSH-"},
				},
				Extractors:        []Extractor{{Target: "product", Source: "banner", Method: "ssh_software"}},
				ConfidenceMatched: "0.8500", ConfidenceEmpty: "0.7000",
			},
		},
	}, now)
	if err != nil {
		return nil, err
	}
	config, err := Seal(Pack{
		ID: StableID("pack:config:" + ConfigVersion), Type: "config", Version: ConfigVersion,
		SchemaVersion: SchemaVersion, Source: "builtin", CreatedAt: now.UTC(),
		Configs: []ConfigRule{{
			ID: StableID("config:host_identity_present"), Key: "host_identity_present", Version: ConfigVersion,
			SubjectType: "asset", RequiredObservationType: "host_inventory", Operation: "collect_os_info",
			PassField: "name", Severity: "low",
		}},
	}, now)
	if err != nil {
		return nil, err
	}
	return []Pack{fingerprint, config}, nil
}
