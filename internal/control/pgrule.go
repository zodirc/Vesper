package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

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
			_, err = tx.Exec(ctx, `
INSERT INTO fingerprint_rule (
    id, pack_id, rule_key, version, priority, target_protocol, service_type, match_conditions, extractors, confidence_matched, confidence_empty
) VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7, $8::jsonb, $9::jsonb, $10::numeric, $11::numeric)`,
				item.ID.String(), pack.ID.String(), item.Key, item.Version, item.Priority, item.TargetProtocol, item.ServiceType, conditions, extractors, item.ConfidenceMatched, item.ConfidenceEmpty)
			if err != nil {
				return fmt.Errorf("save fingerprint rule %s: %w", item.Key, err)
			}
		}
		for _, item := range pack.Configs {
			_, err = tx.Exec(ctx, `
INSERT INTO config_rule (
    id, pack_id, rule_key, version, subject_type, required_observation_type, operation, pass_field, severity
) VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7, $8, $9)`,
				item.ID.String(), pack.ID.String(), item.Key, item.Version, item.SubjectType, item.RequiredObservationType, item.Operation, item.PassField, item.Severity)
			if err != nil {
				return fmt.Errorf("save config rule %s: %w", item.Key, err)
			}
		}
	}
	return nil
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
       confidence_matched::text, confidence_empty::text
FROM fingerprint_rule`)
	if err != nil {
		return nil, fmt.Errorf("load fingerprint rules: %w", err)
	}
	defer ruleRows.Close()
	for ruleRows.Next() {
		var item rule.FingerprintRule
		var idText, packText string
		var conditions, extractors []byte
		if err := ruleRows.Scan(&idText, &packText, &item.Key, &item.Version, &item.Priority, &item.TargetProtocol, &item.ServiceType, &conditions, &extractors, &item.ConfidenceMatched, &item.ConfidenceEmpty); err != nil {
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
SELECT id::text, pack_id::text, rule_key, version, subject_type, required_observation_type, operation, pass_field, severity
FROM config_rule`)
	if err != nil {
		return nil, fmt.Errorf("load config rules: %w", err)
	}
	defer configRows.Close()
	for configRows.Next() {
		var item rule.ConfigRule
		var idText, packText string
		if err := configRows.Scan(&idText, &packText, &item.Key, &item.Version, &item.SubjectType, &item.RequiredObservationType, &item.Operation, &item.PassField, &item.Severity); err != nil {
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
		slot, ok := index[packID]
		if !ok {
			return nil, fmt.Errorf("config rule %s: pack not found", item.Key)
		}
		packs[slot].Configs = append(packs[slot].Configs, item)
	}
	return packs, configRows.Err()
}

func nonNilExtractors(items []rule.Extractor) []rule.Extractor {
	if items == nil {
		return []rule.Extractor{}
	}
	return items
}

func rawOrEmpty(raw json.RawMessage) string {
	if len(raw) == 0 {
		return "{}"
	}
	return string(raw)
}
