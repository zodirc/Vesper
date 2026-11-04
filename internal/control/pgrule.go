package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/zodirc/Vesper/internal/id"
	"github.com/zodirc/Vesper/internal/rule"
)

func savePacks(ctx context.Context, tx pgx.Tx, s *Service) error {
	for _, pack := range s.packs {
		var digest string
		err := tx.QueryRow(ctx, `SELECT content_digest FROM rule_pack WHERE pack_type = $1 AND version = $2`, pack.Type, pack.Version).Scan(&digest)
		if err == nil {
			if err := rule.CheckUpdate(rule.Pack{ID: pack.ID, Type: pack.Type, Version: pack.Version, Status: "published", ContentDigest: digest}, pack); err != nil {
				return err
			}
			if err := updatePackStatus(ctx, tx, pack); err != nil {
				return err
			}
			continue
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("load rule pack %s %s: %w", pack.Type, pack.Version, err)
		}
		_, err = tx.Exec(ctx, `
INSERT INTO rule_pack (
    id, pack_type, version, content_digest, schema_version, source, license_metadata, compatibility, status, published_at, created_at
) VALUES ($1::uuid, $2, $3, $4, $5, $6, $7::jsonb, $8::jsonb, $9, $10, $11)`,
			pack.ID.String(), pack.Type, pack.Version, pack.ContentDigest, pack.SchemaVersion, pack.Source, rawOrEmpty(pack.License), rawOrEmpty(pack.Compatibility),
			pack.Status, timeArg(pack.PublishedAt), pack.CreatedAt.UTC())
		if err != nil {
			return fmt.Errorf("save rule pack %s %s: %w", pack.Type, pack.Version, err)
		}
		for _, item := range pack.Fingerprints {
			conditions, err := jsonArg(item.Conditions)
			if err != nil {
				return err
			}
			extractors, err := jsonArg(nonNilExtractors(item.Extractors))
			if err != nil {
				return err
			}
			negative, err := jsonList(item.Negative)
			if err != nil {
				return err
			}
			evidenceTypes, err := jsonList(item.EvidenceTypes)
			if err != nil {
				return err
			}
			_, err = tx.Exec(ctx, `
INSERT INTO fingerprint_rule (
    id, pack_id, rule_key, version, priority, target_protocol, service_type, match_conditions, extractors,
    confidence_matched, confidence_empty, negative_conditions, evidence_types
) VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7, $8::jsonb, $9::jsonb, $10::numeric, $11::numeric, $12::jsonb, $13::jsonb)`,
				item.ID.String(), pack.ID.String(), item.Key, item.Version, item.Priority, item.TargetProtocol, item.ServiceType, conditions, extractors, item.ConfidenceMatched, item.ConfidenceEmpty, negative, evidenceTypes)
			if err != nil {
				return fmt.Errorf("save fingerprint rule %s: %w", item.Key, err)
			}
		}
		for _, item := range pack.Configs {
			applicability, err := jsonList(item.Applicability)
			if err != nil {
				return err
			}
			pass, err := jsonList(item.Pass)
			if err != nil {
				return err
			}
			fail, err := jsonList(item.Fail)
			if err != nil {
				return err
			}
			_, err = tx.Exec(ctx, `
INSERT INTO config_rule (
    id, pack_id, rule_key, version, subject_type, required_observation_type, operation, pass_field, severity,
    title, category, remediation, applicability, pass_conditions, fail_conditions
) VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13::jsonb, $14::jsonb, $15::jsonb)`,
				item.ID.String(), pack.ID.String(), item.Key, item.Version, item.SubjectType, item.RequiredObservationType, item.Operation, item.PassField, item.Severity,
				textOrNil(item.Title), textOrNil(item.Category), textOrNil(item.Remediation), applicability, pass, fail)
			if err != nil {
				return fmt.Errorf("save config rule %s: %w", item.Key, err)
			}
		}
	}
	return saveActiveTemplates(ctx, tx, s)
}

func loadPacks(ctx context.Context, tx pgx.Tx) ([]rule.Pack, error) {
	rows, err := tx.Query(ctx, `
SELECT id::text, pack_type, version, content_digest, schema_version, source, license_metadata, compatibility, status, published_at, created_at
FROM rule_pack ORDER BY pack_type, version`)
	if err != nil {
		return nil, fmt.Errorf("load rule packs: %w", err)
	}
	defer rows.Close()
	var packs []rule.Pack
	index := map[id.ID]int{}
	for rows.Next() {
		var pack rule.Pack
		var idText string
		if err := rows.Scan(&idText, &pack.Type, &pack.Version, &pack.ContentDigest, &pack.SchemaVersion, &pack.Source, &pack.License, &pack.Compatibility, &pack.Status, &pack.PublishedAt, &pack.CreatedAt); err != nil {
			return nil, err
		}
		pack.ID, err = id.Parse(idText)
		if err != nil {
			return nil, err
		}
		index[pack.ID] = len(packs)
		packs = append(packs, pack)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows.Close()
	ruleRows, err := tx.Query(ctx, `
SELECT id::text, pack_id::text, rule_key, version, priority, target_protocol, service_type, match_conditions, extractors,
       confidence_matched::text, confidence_empty::text, negative_conditions, evidence_types
FROM fingerprint_rule`)
	if err != nil {
		return nil, fmt.Errorf("load fingerprint rules: %w", err)
	}
	defer ruleRows.Close()
	for ruleRows.Next() {
		var item rule.FingerprintRule
		var idText, packText string
		var conditions, extractors, negative, evidenceTypes []byte
		if err := ruleRows.Scan(&idText, &packText, &item.Key, &item.Version, &item.Priority, &item.TargetProtocol, &item.ServiceType, &conditions, &extractors, &item.ConfidenceMatched, &item.ConfidenceEmpty, &negative, &evidenceTypes); err != nil {
			return nil, err
		}
		item.ID, err = id.Parse(idText)
		if err != nil {
			return nil, err
		}
		packID, err := id.Parse(packText)
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(conditions, &item.Conditions); err != nil {
			return nil, err
		}
		if len(extractors) > 0 {
			if err := json.Unmarshal(extractors, &item.Extractors); err != nil {
				return nil, err
			}
		}
		if err := decodeJSONList(negative, &item.Negative); err != nil {
			return nil, err
		}
		if err := decodeJSONList(evidenceTypes, &item.EvidenceTypes); err != nil {
			return nil, err
		}
		slot, ok := index[packID]
		if !ok {
			return nil, fmt.Errorf("fingerprint rule %s: pack not found", item.Key)
		}
		packs[slot].Fingerprints = append(packs[slot].Fingerprints, item)
	}
	if err := ruleRows.Err(); err != nil {
		return nil, err
	}
	configRows, err := tx.Query(ctx, `
SELECT id::text, pack_id::text, rule_key, version, subject_type, required_observation_type, operation, pass_field, severity,
       title, category, remediation, applicability, pass_conditions, fail_conditions
FROM config_rule`)
	if err != nil {
		return nil, fmt.Errorf("load config rules: %w", err)
	}
	defer configRows.Close()
	for configRows.Next() {
		var item rule.ConfigRule
		var idText, packText string
		var title, category, remediation *string
		var applicability, pass, fail []byte
		if err := configRows.Scan(&idText, &packText, &item.Key, &item.Version, &item.SubjectType, &item.RequiredObservationType, &item.Operation, &item.PassField, &item.Severity, &title, &category, &remediation, &applicability, &pass, &fail); err != nil {
			return nil, err
		}
		item.Title = textOrEmpty(title)
		item.Category = textOrEmpty(category)
		item.Remediation = textOrEmpty(remediation)
		if err := decodeJSONList(applicability, &item.Applicability); err != nil {
			return nil, fmt.Errorf("decode config applicability %s: %w", item.Key, err)
		}
		if err := decodeJSONList(pass, &item.Pass); err != nil {
			return nil, fmt.Errorf("decode config pass %s: %w", item.Key, err)
		}
		if err := decodeJSONList(fail, &item.Fail); err != nil {
			return nil, fmt.Errorf("decode config fail %s: %w", item.Key, err)
		}
		item.ID, err = id.Parse(idText)
		if err != nil {
			return nil, err
		}
		packID, err := id.Parse(packText)
		if err != nil {
			return nil, err
		}
		slot, ok := index[packID]
		if !ok {
			return nil, fmt.Errorf("config rule %s: pack not found", item.Key)
		}
		packs[slot].Configs = append(packs[slot].Configs, item)
	}
	return packs, configRows.Err()
}

func decodeJSONList(raw []byte, dest any) error {
	text := strings.TrimSpace(string(raw))
	if text == "" || text == "null" || text == "{}" || text == "[]" {
		return nil
	}
	return json.Unmarshal(raw, dest)
}

func nonNilExtractors(items []rule.Extractor) []rule.Extractor {
	if items == nil {
		return []rule.Extractor{}
	}
	return items
}

func textOrNil(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func textOrEmpty(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func rawOrEmpty(raw json.RawMessage) string {
	if len(raw) == 0 {
		return "{}"
	}
	return string(raw)
}

func updatePackStatus(ctx context.Context, tx pgx.Tx, pack rule.Pack) error {
	_, err := tx.Exec(ctx, `
UPDATE rule_pack SET status = $1, published_at = COALESCE(published_at, $2)
WHERE id = $3::uuid AND content_digest = $4`, pack.Status, timeArg(pack.PublishedAt), pack.ID.String(), pack.ContentDigest)
	if err != nil {
		return fmt.Errorf("update rule pack %s: %w", pack.Version, err)
	}
	return nil
}

func saveActiveTemplates(ctx context.Context, tx pgx.Tx, s *Service) error {
	for _, item := range s.active {
		_, err := tx.Exec(ctx, `
INSERT INTO active_template (
    id, pack_id, template_key, template_name, severity, cve_id, request_bound, content_digest, body, enabled
) VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7, $8, $9, $10)
ON CONFLICT (id) DO UPDATE SET enabled = EXCLUDED.enabled`,
			item.ID.String(), item.PackID.String(), item.Key, item.Name, item.Severity, item.CVE, item.RequestBound, item.Digest, string(item.Body), item.Enabled)
		if err != nil {
			return fmt.Errorf("save active template %s: %w", item.Key, err)
		}
	}
	return nil
}
