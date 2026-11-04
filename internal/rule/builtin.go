package rule

import (
	"time"

	"github.com/zodirc/Vesper/internal/id"
)

const (
	// FingerprintVersion 是新扫描使用的内置指纹包版本。
	// FingerprintVersion is the built-in fingerprint pack version used by new scans.
	FingerprintVersion = "builtin-14"
	// MemcachedFingerprintVersion 是加入 Memcached 规则时发布的指纹包。内容保持不变，其中没有 ClickHouse 规则。
	// MemcachedFingerprintVersion is the fingerprint pack published when the Memcached rule was added. Its content stays unchanged and it has no ClickHouse rule.
	MemcachedFingerprintVersion = "builtin-13"
	// BoltFingerprintVersion 是加入 Bolt 规则时发布的指纹包。内容保持不变，其中没有 Memcached 规则。
	// BoltFingerprintVersion is the fingerprint pack published when the Bolt rule was added. Its content stays unchanged and it has no Memcached rule.
	BoltFingerprintVersion = "builtin-12"
	// CQLFingerprintVersion 是加入 CQL 规则时发布的指纹包。内容保持不变，其中没有 Bolt 规则。
	// CQLFingerprintVersion is the fingerprint pack published when the CQL rule was added. Its content stays unchanged and it has no Bolt rule.
	CQLFingerprintVersion = "builtin-11"
	// TNSFingerprintVersion 是加入 TNS 规则时发布的指纹包。内容保持不变，其中没有 CQL 规则。
	// TNSFingerprintVersion is the fingerprint pack published when the TNS rule was added. Its content stays unchanged and it has no CQL rule.
	TNSFingerprintVersion = "builtin-10"
	// TDSFingerprintVersion 是加入 TDS 规则时发布的指纹包。内容保持不变，其中没有 TNS 规则。
	// TDSFingerprintVersion is the fingerprint pack published when the TDS rule was added. Its content stays unchanged and it has no TNS rule.
	TDSFingerprintVersion = "builtin-9"
	// MongoDBFingerprintVersion 是加入 MongoDB 规则时发布的指纹包。内容保持不变，其中没有 TDS 规则。
	// MongoDBFingerprintVersion is the fingerprint pack published when the MongoDB rule was added. Its content stays unchanged and it has no TDS rule.
	MongoDBFingerprintVersion = "builtin-8"
	// RedisFingerprintVersion 是加入 Redis 规则时发布的指纹包。内容保持不变，其中没有 MongoDB 规则。
	// RedisFingerprintVersion is the fingerprint pack published when the Redis rule was added. Its content stays unchanged and it has no MongoDB rule.
	RedisFingerprintVersion = "builtin-7"
	// PostgreSQLFingerprintVersion 是加入 PostgreSQL 规则时发布的指纹包。内容保持不变，其中没有 Redis 规则。
	// PostgreSQLFingerprintVersion is the fingerprint pack published when the PostgreSQL rule was added. Its content stays unchanged and it has no Redis rule.
	PostgreSQLFingerprintVersion = "builtin-6"
	// MySQLFingerprintVersion 是加入 MySQL 规则时发布的指纹包。内容保持不变，其中没有 PostgreSQL 规则。
	// MySQLFingerprintVersion is the fingerprint pack published when the MySQL rule was added. Its content stays unchanged and it has no PostgreSQL rule.
	MySQLFingerprintVersion = "builtin-5"
	// SMTPFingerprintVersion 是加入 SMTP 规则时发布的指纹包。内容保持不变，其中没有 MySQL 规则。
	// SMTPFingerprintVersion is the fingerprint pack published when the SMTP rule was added. Its content stays unchanged and it has no MySQL rule.
	SMTPFingerprintVersion = "builtin-4"
	// FTPFingerprintVersion 是加入 FTP 规则时发布的指纹包。内容保持不变，其中没有 SMTP 规则。
	// FTPFingerprintVersion is the fingerprint pack published when the FTP rule was added. Its content stays unchanged and it has no SMTP rule.
	FTPFingerprintVersion = "builtin-3"
	// DNSFingerprintVersion 是加入 DNS 规则时发布的指纹包。内容保持不变，其中没有 FTP 规则。
	// DNSFingerprintVersion is the fingerprint pack published when the DNS rule was added. Its content stays unchanged and it has no FTP rule.
	DNSFingerprintVersion = "builtin-2"
	// PreviousFingerprintVersion 是加入 DNS 规则之前的已发布指纹包。内容保持不变。
	// PreviousFingerprintVersion is the published fingerprint pack from before the DNS rule. Its content stays unchanged.
	PreviousFingerprintVersion = "builtin-1"
	// ConfigVersion 是内置配置包版本。
	// ConfigVersion is the built-in configuration pack version.
	ConfigVersion = "builtin-1"
)

// Builtin 返回已发布的内置指纹包和配置包。
// Builtin returns the published built-in fingerprint and configuration packs.
//
// builtin-1 到 builtin-13 仍可按版本读取，内容不改。新扫描写入 builtin-14。builtin-14 在 builtin-13 的规则之外增加 ClickHouse。
// ClickHouse 规则只确认线协议，不提取产品。带版本的规则标识避免与已发布规则的主键冲突。
// builtin-1 through builtin-13 remain readable by version and their content is unchanged. New scans record builtin-14. builtin-14 adds ClickHouse beside the builtin-13 rules.
// The ClickHouse rule confirms the wire protocol and does not extract a product. Versioned rule identifiers avoid collisions with primary keys of already published rules.
func Builtin(now time.Time) ([]Pack, error) {
	previous, err := sealFingerprints(PreviousFingerprintVersion, false, false, false, false, false, false, false, false, false, false, false, false, false, now)
	if err != nil {
		return nil, err
	}
	dns, err := sealFingerprints(DNSFingerprintVersion, true, false, false, false, false, false, false, false, false, false, false, false, false, now)
	if err != nil {
		return nil, err
	}
	ftp, err := sealFingerprints(FTPFingerprintVersion, true, true, false, false, false, false, false, false, false, false, false, false, false, now)
	if err != nil {
		return nil, err
	}
	smtp, err := sealFingerprints(SMTPFingerprintVersion, true, true, true, false, false, false, false, false, false, false, false, false, false, now)
	if err != nil {
		return nil, err
	}
	mysql, err := sealFingerprints(MySQLFingerprintVersion, true, true, true, true, false, false, false, false, false, false, false, false, false, now)
	if err != nil {
		return nil, err
	}
	postgresql, err := sealFingerprints(PostgreSQLFingerprintVersion, true, true, true, true, true, false, false, false, false, false, false, false, false, now)
	if err != nil {
		return nil, err
	}
	redisPack, err := sealFingerprints(RedisFingerprintVersion, true, true, true, true, true, true, false, false, false, false, false, false, false, now)
	if err != nil {
		return nil, err
	}
	mongoPack, err := sealFingerprints(MongoDBFingerprintVersion, true, true, true, true, true, true, true, false, false, false, false, false, false, now)
	if err != nil {
		return nil, err
	}
	tdsPack, err := sealFingerprints(TDSFingerprintVersion, true, true, true, true, true, true, true, true, false, false, false, false, false, now)
	if err != nil {
		return nil, err
	}
	tnsPack, err := sealFingerprints(TNSFingerprintVersion, true, true, true, true, true, true, true, true, true, false, false, false, false, now)
	if err != nil {
		return nil, err
	}
	cqlPack, err := sealFingerprints(CQLFingerprintVersion, true, true, true, true, true, true, true, true, true, true, false, false, false, now)
	if err != nil {
		return nil, err
	}
	boltPack, err := sealFingerprints(BoltFingerprintVersion, true, true, true, true, true, true, true, true, true, true, true, false, false, now)
	if err != nil {
		return nil, err
	}
	memcachedPack, err := sealFingerprints(MemcachedFingerprintVersion, true, true, true, true, true, true, true, true, true, true, true, true, false, now)
	if err != nil {
		return nil, err
	}
	current, err := sealFingerprints(FingerprintVersion, true, true, true, true, true, true, true, true, true, true, true, true, true, now)
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
	return []Pack{previous, dns, ftp, smtp, mysql, postgresql, redisPack, mongoPack, tdsPack, tnsPack, cqlPack, boltPack, memcachedPack, current, config}, nil
}

func sealFingerprints(version string, includeDNS, includeFTP, includeSMTP, includeMySQL, includePostgreSQL, includeRedis, includeMongoDB, includeTDS, includeTNS, includeCQL, includeBolt, includeMemcached, includeClickHouse bool, now time.Time) (Pack, error) {
	identifier := func(key string) id.ID {
		if includeFTP || includeSMTP || includeMySQL || includePostgreSQL || includeRedis || includeMongoDB || includeTDS || includeTNS || includeCQL || includeBolt || includeMemcached || includeClickHouse {
			return StableID("fingerprint:" + version + ":" + key)
		}
		return StableID("fingerprint:" + key)
	}
	rules := []FingerprintRule{
		{
			ID: identifier("http"), Key: "http", Version: version, Priority: 10,
			TargetProtocol: "http", ServiceType: "http",
			Conditions:        []Condition{{Field: "protocol", Op: "equals", Value: "http"}},
			Extractors:        []Extractor{{Target: "product", Source: "headers.server", Method: "server_token"}},
			ConfidenceMatched: "0.8500", ConfidenceEmpty: "0.7000",
		},
		{
			ID: identifier("tls"), Key: "tls", Version: version, Priority: 10,
			TargetProtocol: "tls", ServiceType: "tls",
			Conditions:        []Condition{{Field: "protocol", Op: "equals", Value: "tls"}},
			ConfidenceMatched: "0.7000", ConfidenceEmpty: "0.7000",
		},
		{
			ID: identifier("ssh"), Key: "ssh", Version: version, Priority: 10,
			TargetProtocol: "ssh", ServiceType: "ssh",
			Conditions: []Condition{
				{Field: "protocol", Op: "equals", Value: "ssh"},
				{Field: "banner", Op: "prefix", Value: "SSH-"},
			},
			Extractors:        []Extractor{{Target: "product", Source: "banner", Method: "ssh_software"}},
			ConfidenceMatched: "0.8500", ConfidenceEmpty: "0.7000",
		},
	}
	if includeDNS {
		rules = append(rules, FingerprintRule{
			ID: identifier("dns"), Key: "dns", Version: version, Priority: 10,
			TargetProtocol: "dns", ServiceType: "dns",
			Conditions:        []Condition{{Field: "protocol", Op: "equals", Value: "dns"}},
			ConfidenceMatched: "0.7000", ConfidenceEmpty: "0.7000",
		})
	}
	if includeFTP {
		rules = append(rules, FingerprintRule{
			ID: identifier("ftp"), Key: "ftp", Version: version, Priority: 10,
			TargetProtocol: "ftp", ServiceType: "ftp",
			Conditions:        []Condition{{Field: "protocol", Op: "equals", Value: "ftp"}},
			ConfidenceMatched: "0.7000", ConfidenceEmpty: "0.7000",
		})
	}
	if includeSMTP {
		rules = append(rules, FingerprintRule{
			ID: identifier("smtp"), Key: "smtp", Version: version, Priority: 10,
			TargetProtocol: "smtp", ServiceType: "smtp",
			Conditions:        []Condition{{Field: "protocol", Op: "equals", Value: "smtp"}},
			ConfidenceMatched: "0.7000", ConfidenceEmpty: "0.7000",
		})
	}
	if includeMySQL {
		rules = append(rules, FingerprintRule{
			ID: identifier("mysql"), Key: "mysql", Version: version, Priority: 10,
			TargetProtocol: "mysql", ServiceType: "mysql",
			Conditions:        []Condition{{Field: "protocol", Op: "equals", Value: "mysql"}},
			ConfidenceMatched: "0.7000", ConfidenceEmpty: "0.7000",
		})
	}
	if includePostgreSQL {
		rules = append(rules, FingerprintRule{
			ID: identifier("postgresql"), Key: "postgresql", Version: version, Priority: 10,
			TargetProtocol: "postgresql", ServiceType: "postgresql",
			Conditions:        []Condition{{Field: "protocol", Op: "equals", Value: "postgresql"}},
			ConfidenceMatched: "0.7000", ConfidenceEmpty: "0.7000",
		})
	}
	if includeRedis {
		rules = append(rules, FingerprintRule{
			ID: identifier("redis"), Key: "redis", Version: version, Priority: 10,
			TargetProtocol: "redis", ServiceType: "redis",
			Conditions:        []Condition{{Field: "protocol", Op: "equals", Value: "redis"}},
			ConfidenceMatched: "0.7000", ConfidenceEmpty: "0.7000",
		})
	}
	if includeMongoDB {
		rules = append(rules, FingerprintRule{
			ID: identifier("mongodb"), Key: "mongodb", Version: version, Priority: 10,
			TargetProtocol: "mongodb", ServiceType: "mongodb",
			Conditions:        []Condition{{Field: "protocol", Op: "equals", Value: "mongodb"}},
			ConfidenceMatched: "0.7000", ConfidenceEmpty: "0.7000",
		})
	}
	if includeTDS {
		rules = append(rules, FingerprintRule{
			ID: identifier("tds"), Key: "tds", Version: version, Priority: 10,
			TargetProtocol: "tds", ServiceType: "tds",
			Conditions:        []Condition{{Field: "protocol", Op: "equals", Value: "tds"}},
			ConfidenceMatched: "0.7000", ConfidenceEmpty: "0.7000",
		})
	}
	if includeTNS {
		rules = append(rules, FingerprintRule{
			ID: identifier("tns"), Key: "tns", Version: version, Priority: 10,
			TargetProtocol: "tns", ServiceType: "tns",
			Conditions:        []Condition{{Field: "protocol", Op: "equals", Value: "tns"}},
			ConfidenceMatched: "0.7000", ConfidenceEmpty: "0.7000",
		})
	}
	if includeCQL {
		rules = append(rules, FingerprintRule{
			ID: identifier("cql"), Key: "cql", Version: version, Priority: 10,
			TargetProtocol: "cql", ServiceType: "cql",
			Conditions:        []Condition{{Field: "protocol", Op: "equals", Value: "cql"}},
			ConfidenceMatched: "0.7000", ConfidenceEmpty: "0.7000",
		})
	}
	if includeBolt {
		rules = append(rules, FingerprintRule{
			ID: identifier("bolt"), Key: "bolt", Version: version, Priority: 10,
			TargetProtocol: "bolt", ServiceType: "bolt",
			Conditions:        []Condition{{Field: "protocol", Op: "equals", Value: "bolt"}},
			ConfidenceMatched: "0.7000", ConfidenceEmpty: "0.7000",
		})
	}
	if includeMemcached {
		rules = append(rules, FingerprintRule{
			ID: identifier("memcached"), Key: "memcached", Version: version, Priority: 10,
			TargetProtocol: "memcached", ServiceType: "memcached",
			Conditions:        []Condition{{Field: "protocol", Op: "equals", Value: "memcached"}},
			ConfidenceMatched: "0.7000", ConfidenceEmpty: "0.7000",
		})
	}
	if includeClickHouse {
		rules = append(rules, FingerprintRule{
			ID: identifier("clickhouse"), Key: "clickhouse", Version: version, Priority: 10,
			TargetProtocol: "clickhouse", ServiceType: "clickhouse",
			Conditions:        []Condition{{Field: "protocol", Op: "equals", Value: "clickhouse"}},
			ConfidenceMatched: "0.7000", ConfidenceEmpty: "0.7000",
		})
	}
	return Seal(Pack{
		ID: StableID("pack:fingerprint:" + version), Type: "fingerprint", Version: version,
		SchemaVersion: SchemaVersion, Source: "builtin", CreatedAt: now.UTC(), Fingerprints: rules,
	}, now)
}
