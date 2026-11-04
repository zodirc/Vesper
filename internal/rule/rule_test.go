package rule

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestFingerprintDoesNotInventProductFromPort(t *testing.T) {
	packs, err := Builtin(time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	rules := Fingerprints(packs, FingerprintVersion)
	hits := MatchFingerprints(rules, Fact{Type: "protocol_response", Value: map[string]any{"port": "80"}})
	if len(hits) != 0 {
		t.Fatalf("hits = %+v", hits)
	}
	hits = MatchFingerprints(rules, Fact{Type: "protocol_response", Value: map[string]any{
		"protocol": "http", "headers": map[string]any{"server": "nginx/1.24.0"},
	}})
	if len(hits) != 1 || hits[0].Product != "nginx" || hits[0].Version != "1.24.0" || hits[0].Status != "candidate" {
		t.Fatalf("hits = %+v", hits)
	}
}

func TestDNSFingerprintConfirmsProtocolWithoutProduct(t *testing.T) {
	packs, err := Builtin(time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	previous := Fingerprints(packs, PreviousFingerprintVersion)
	if hits := MatchFingerprints(previous, Fact{Type: "protocol_response", Value: map[string]any{"protocol": "dns"}}); len(hits) != 0 {
		t.Fatalf("builtin-1 hits = %+v", hits)
	}
	dnsPack := Fingerprints(packs, DNSFingerprintVersion)
	hits := MatchFingerprints(dnsPack, Fact{Type: "protocol_response", Value: map[string]any{"protocol": "dns", "port": "53"}})
	if len(hits) != 1 || hits[0].ServiceType != "dns" || hits[0].Product != "" || hits[0].Status != "unknown" {
		t.Fatalf("hits = %+v", hits)
	}
	if ftp := MatchFingerprints(dnsPack, Fact{Type: "protocol_response", Value: map[string]any{"protocol": "ftp", "port": "21"}}); len(ftp) != 0 {
		t.Fatalf("builtin-2 ftp hits = %+v", ftp)
	}
	ftpPack := Fingerprints(packs, FTPFingerprintVersion)
	ftp := MatchFingerprints(ftpPack, Fact{Type: "protocol_response", Value: map[string]any{"protocol": "ftp", "reply_code": "220", "port": "21"}})
	if len(ftp) != 1 || ftp[0].ServiceType != "ftp" || ftp[0].Product != "" || ftp[0].Status != "unknown" {
		t.Fatalf("ftp hits = %+v", ftp)
	}
	if smtp := MatchFingerprints(ftpPack, Fact{Type: "protocol_response", Value: map[string]any{"protocol": "smtp", "port": "25"}}); len(smtp) != 0 {
		t.Fatalf("builtin-3 smtp hits = %+v", smtp)
	}
	smtpPack := Fingerprints(packs, SMTPFingerprintVersion)
	smtp := MatchFingerprints(smtpPack, Fact{Type: "protocol_response", Value: map[string]any{"protocol": "smtp", "reply_code": "220", "port": "25"}})
	if len(smtp) != 1 || smtp[0].ServiceType != "smtp" || smtp[0].Product != "" || smtp[0].Status != "unknown" {
		t.Fatalf("smtp hits = %+v", smtp)
	}
	if mysql := MatchFingerprints(smtpPack, Fact{Type: "protocol_response", Value: map[string]any{"protocol": "mysql", "port": "3306"}}); len(mysql) != 0 {
		t.Fatalf("builtin-4 mysql hits = %+v", mysql)
	}
	mysqlPack := Fingerprints(packs, MySQLFingerprintVersion)
	mysql := MatchFingerprints(mysqlPack, Fact{Type: "protocol_response", Value: map[string]any{"protocol": "mysql", "server_version": "5.5.5-10.11.6-MariaDB", "port": "3306"}})
	if len(mysql) != 1 || mysql[0].ServiceType != "mysql" || mysql[0].Product != "" || mysql[0].Status != "unknown" {
		t.Fatalf("mysql hits = %+v", mysql)
	}
	if pg := MatchFingerprints(mysqlPack, Fact{Type: "protocol_response", Value: map[string]any{"protocol": "postgresql", "port": "5432"}}); len(pg) != 0 {
		t.Fatalf("builtin-5 postgresql hits = %+v", pg)
	}
	pgPack := Fingerprints(packs, PostgreSQLFingerprintVersion)
	pg := MatchFingerprints(pgPack, Fact{Type: "protocol_response", Value: map[string]any{"protocol": "postgresql", "message_type": "R", "port": "5432"}})
	if len(pg) != 1 || pg[0].ServiceType != "postgresql" || pg[0].Product != "" || pg[0].Status != "unknown" {
		t.Fatalf("postgresql hits = %+v", pg)
	}
	if redis := MatchFingerprints(pgPack, Fact{Type: "protocol_response", Value: map[string]any{"protocol": "redis", "port": "6379"}}); len(redis) != 0 {
		t.Fatalf("builtin-6 redis hits = %+v", redis)
	}
	redisPack := Fingerprints(packs, RedisFingerprintVersion)
	redis := MatchFingerprints(redisPack, Fact{Type: "protocol_response", Value: map[string]any{"protocol": "redis", "reply": "PONG", "port": "6379"}})
	if len(redis) != 1 || redis[0].ServiceType != "redis" || redis[0].Product != "" || redis[0].Status != "unknown" {
		t.Fatalf("redis hits = %+v", redis)
	}
	if mongo := MatchFingerprints(redisPack, Fact{Type: "protocol_response", Value: map[string]any{"protocol": "mongodb", "port": "27017"}}); len(mongo) != 0 {
		t.Fatalf("builtin-7 mongodb hits = %+v", mongo)
	}
	mongoPack := Fingerprints(packs, MongoDBFingerprintVersion)
	mongo := MatchFingerprints(mongoPack, Fact{Type: "protocol_response", Value: map[string]any{"protocol": "mongodb", "reply": "ok", "port": "27017"}})
	if len(mongo) != 1 || mongo[0].ServiceType != "mongodb" || mongo[0].Product != "" || mongo[0].Status != "unknown" {
		t.Fatalf("mongodb hits = %+v", mongo)
	}
	if tds := MatchFingerprints(mongoPack, Fact{Type: "protocol_response", Value: map[string]any{"protocol": "tds", "port": "1433"}}); len(tds) != 0 {
		t.Fatalf("builtin-8 tds hits = %+v", tds)
	}
	tdsPack := Fingerprints(packs, TDSFingerprintVersion)
	tds := MatchFingerprints(tdsPack, Fact{Type: "protocol_response", Value: map[string]any{"protocol": "tds", "server_version": "15.0.2000.5", "port": "1433"}})
	if len(tds) != 1 || tds[0].ServiceType != "tds" || tds[0].Product != "" || tds[0].Version != "" || tds[0].Status != "unknown" {
		t.Fatalf("tds hits = %+v", tds)
	}
	if tns := MatchFingerprints(tdsPack, Fact{Type: "protocol_response", Value: map[string]any{"protocol": "tns", "port": "1521"}}); len(tns) != 0 {
		t.Fatalf("builtin-9 tns hits = %+v", tns)
	}
	tnsPack := Fingerprints(packs, TNSFingerprintVersion)
	tns := MatchFingerprints(tnsPack, Fact{Type: "protocol_response", Value: map[string]any{"protocol": "tns", "server_version": "19.0.0.0.0", "port": "1521"}})
	if len(tns) != 1 || tns[0].ServiceType != "tns" || tns[0].Product != "" || tns[0].Version != "" || tns[0].Status != "unknown" {
		t.Fatalf("tns hits = %+v", tns)
	}
	if cql := MatchFingerprints(tnsPack, Fact{Type: "protocol_response", Value: map[string]any{"protocol": "cql", "port": "9042"}}); len(cql) != 0 {
		t.Fatalf("builtin-10 cql hits = %+v", cql)
	}
	cqlPack := Fingerprints(packs, CQLFingerprintVersion)
	cql := MatchFingerprints(cqlPack, Fact{Type: "protocol_response", Value: map[string]any{"protocol": "cql", "reply": "READY", "port": "9042"}})
	if len(cql) != 1 || cql[0].ServiceType != "cql" || cql[0].Product != "" || cql[0].Version != "" || cql[0].Status != "unknown" {
		t.Fatalf("cql hits = %+v", cql)
	}
	if bolt := MatchFingerprints(cqlPack, Fact{Type: "protocol_response", Value: map[string]any{"protocol": "bolt", "port": "7687"}}); len(bolt) != 0 {
		t.Fatalf("builtin-11 bolt hits = %+v", bolt)
	}
	boltPack := Fingerprints(packs, BoltFingerprintVersion)
	bolt := MatchFingerprints(boltPack, Fact{Type: "protocol_response", Value: map[string]any{"protocol": "bolt", "protocol_version": "5.4", "port": "7687"}})
	if len(bolt) != 1 || bolt[0].ServiceType != "bolt" || bolt[0].Product != "" || bolt[0].Version != "" || bolt[0].Status != "unknown" {
		t.Fatalf("bolt hits = %+v", bolt)
	}
	if memcached := MatchFingerprints(boltPack, Fact{Type: "protocol_response", Value: map[string]any{"protocol": "memcached", "port": "11211"}}); len(memcached) != 0 {
		t.Fatalf("builtin-12 memcached hits = %+v", memcached)
	}
	memcachedPack := Fingerprints(packs, MemcachedFingerprintVersion)
	memcached := MatchFingerprints(memcachedPack, Fact{Type: "protocol_response", Value: map[string]any{"protocol": "memcached", "server_version": "1.6.22", "port": "11211"}})
	if len(memcached) != 1 || memcached[0].ServiceType != "memcached" || memcached[0].Product != "" || memcached[0].Version != "" || memcached[0].Status != "unknown" {
		t.Fatalf("memcached hits = %+v", memcached)
	}
	if clickhouse := MatchFingerprints(memcachedPack, Fact{Type: "protocol_response", Value: map[string]any{"protocol": "clickhouse", "port": "9000"}}); len(clickhouse) != 0 {
		t.Fatalf("builtin-13 clickhouse hits = %+v", clickhouse)
	}
	current := Fingerprints(packs, FingerprintVersion)
	hits = MatchFingerprints(current, Fact{Type: "protocol_response", Value: map[string]any{"protocol": "dns", "port": "53"}})
	if len(hits) != 1 || hits[0].ServiceType != "dns" || hits[0].Product != "" {
		t.Fatalf("builtin-14 dns hits = %+v", hits)
	}
	clickhouse := MatchFingerprints(current, Fact{Type: "protocol_response", Value: map[string]any{"protocol": "clickhouse", "reply": "HELLO", "port": "9000"}})
	if len(clickhouse) != 1 || clickhouse[0].ServiceType != "clickhouse" || clickhouse[0].Product != "" || clickhouse[0].Version != "" || clickhouse[0].Status != "unknown" {
		t.Fatalf("clickhouse hits = %+v", clickhouse)
	}
	if invented := MatchFingerprints(current, Fact{Type: "protocol_response", Value: map[string]any{"port": "9000", "reply": "HELLO"}}); len(invented) != 0 {
		t.Fatalf("port hits = %+v", invented)
	}
}

func TestPublishedPackRejectsContentChange(t *testing.T) {
	now := time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC)
	packs, err := Builtin(now)
	if err != nil {
		t.Fatal(err)
	}
	changed := packs[0]
	changed.Fingerprints[0].ServiceType = "database"
	digest, err := Digest(changed)
	if err != nil {
		t.Fatal(err)
	}
	changed.ContentDigest = digest
	if err := CheckUpdate(packs[0], changed); !errors.Is(err, ErrPublishedImmutable) {
		t.Fatalf("err = %v", err)
	}
}

func TestConfigRuleDoesNotPassWithoutEvidence(t *testing.T) {
	packs, err := Builtin(time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	rules := Configs(packs, ConfigVersion)
	missing := EvaluateConfigs(rules, nil)
	if missing[0].Status != "insufficient_evidence" || missing[0].Unmatched["required_observation_type"] != "host_inventory" {
		t.Fatalf("missing = %+v", missing[0])
	}
	unsupported := EvaluateConfigs(rules, []Fact{{Type: "host_inventory", Subject: "local:collect_os_info", ResultStatus: "unsupported"}})
	if unsupported[0].Status != "not_applicable" {
		t.Fatalf("unsupported = %+v", unsupported[0])
	}
	present := EvaluateConfigs(rules, []Fact{{Type: "host_inventory", Subject: "local:collect_os_info", ResultStatus: "collected", Value: map[string]any{"name": "Fedora"}}})
	if present[0].Status != "not_vulnerable" || present[0].Matched["pass_field"] != "name" || present[0].Matched["present"] != true {
		t.Fatalf("present = %+v", present[0])
	}
	absent := EvaluateConfigs(rules, []Fact{{Type: "host_inventory", Subject: "local:collect_os_info", ResultStatus: "collected", Value: map[string]any{}}})
	if absent[0].Status != "confirmed" || absent[0].Unmatched["pass_field"] != "name" {
		t.Fatalf("absent = %+v", absent[0])
	}
	envelope := EvaluateConfigs(rules, []Fact{{
		Type: "host_inventory", Subject: "local:collect_os_info", ResultStatus: "observed",
		Value: map[string]any{"collection_status": "collected", "name": "Fedora"},
	}})
	if envelope[0].Status != "not_vulnerable" {
		t.Fatalf("envelope = %+v", envelope[0])
	}
	empty := EvaluateConfigs(rules, []Fact{{
		Type: "host_inventory", Subject: "local:collect_os_info", ResultStatus: "empty",
		Value: map[string]any{"collection_status": "empty"},
	}})
	if empty[0].Status != "insufficient_evidence" || empty[0].Matched["collection_status"] != "empty" {
		t.Fatalf("empty = %+v", empty[0])
	}
}

func TestNegativeConditionSuppressesOnlyThatRule(t *testing.T) {
	base := FingerprintRule{
		ID: StableID("http"), Key: "http", Version: "test", Priority: 10, TargetProtocol: "http", ServiceType: "http",
		Conditions:        []Condition{{Field: "protocol", Op: "equals", Value: "http"}},
		Extractors:        []Extractor{{Target: "product", Source: "headers.server", Method: "server_token"}},
		ConfidenceMatched: "0.8500", ConfidenceEmpty: "0.7000",
		Negative: []Condition{},
	}
	plain := MatchFingerprints([]FingerprintRule{base}, Fact{Type: "protocol_response", Value: map[string]any{"protocol": "http", "headers": map[string]any{"server": "nginx/1.24.0"}}})
	if len(plain) != 1 || plain[0].Status != "candidate" || plain[0].Product != "nginx" {
		t.Fatalf("plain = %+v", plain)
	}
	base.Negative = []Condition{{Field: "headers.server", Op: "contains", Value: "proxy"}}
	kept := MatchFingerprints([]FingerprintRule{base}, Fact{Type: "protocol_response", Value: map[string]any{"protocol": "http", "headers": map[string]any{"server": "nginx/1.24.0"}}})
	if len(kept) != 1 || kept[0].Product != "nginx" || kept[0].Status != "candidate" {
		t.Fatalf("kept = %+v", kept)
	}
	excluded := MatchFingerprints([]FingerprintRule{base}, Fact{Type: "protocol_response", Value: map[string]any{"protocol": "http", "headers": map[string]any{"server": "nginx/1.24.0 proxy"}}})
	if len(excluded) != 1 || excluded[0].Status != "excluded" || excluded[0].Product != "" {
		t.Fatalf("excluded = %+v", excluded)
	}
}

func TestBuiltinFingerprintJSONOmitsEmptyClauses(t *testing.T) {
	packs, err := Builtin(time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	for _, pack := range packs {
		if pack.Type != "fingerprint" {
			continue
		}
		for _, item := range pack.Fingerprints {
			raw, err := json.Marshal(item)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(raw), `"Negative"`) || strings.Contains(string(raw), `"EvidenceTypes"`) || strings.Contains(string(raw), `"template"`) {
				t.Fatalf("%s %s = %s", pack.Version, item.Key, raw)
			}
		}
	}
}
