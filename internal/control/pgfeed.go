package control

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
)

func saveFeeds(ctx context.Context, tx pgx.Tx, s *Service) error {
	if s.feeds == nil {
		s.feeds = map[string]FeedStatus{}
	}
	keep := make([]string, 0, len(s.feeds))
	for source, item := range s.feeds {
		raw, err := json.Marshal(item)
		if err != nil {
			return fmt.Errorf("save intel feed %s: %w", source, err)
		}
		if _, err := tx.Exec(ctx, `
INSERT INTO intel_feed (source, document)
VALUES ($1, $2::jsonb)
ON CONFLICT (source) DO UPDATE SET document = EXCLUDED.document`, source, string(raw)); err != nil {
			return fmt.Errorf("save intel feed %s: %w", source, err)
		}
		keep = append(keep, source)
	}
	if len(keep) == 0 {
		if _, err := tx.Exec(ctx, `DELETE FROM intel_feed`); err != nil {
			return fmt.Errorf("delete intel feeds: %w", err)
		}
		return nil
	}
	if _, err := tx.Exec(ctx, `DELETE FROM intel_feed WHERE source <> ALL($1::text[])`, "{"+strings.Join(keep, ",")+"}"); err != nil {
		return fmt.Errorf("delete retired intel feeds: %w", err)
	}
	return nil
}

func loadFeeds(ctx context.Context, tx pgx.Tx) (map[string]FeedStatus, error) {
	rows, err := tx.Query(ctx, `SELECT source, document FROM intel_feed`)
	if err != nil {
		return nil, fmt.Errorf("load intel feeds: %w", err)
	}
	defer rows.Close()
	loaded := map[string]FeedStatus{}
	for rows.Next() {
		var source string
		var raw []byte
		if err := rows.Scan(&source, &raw); err != nil {
			return nil, fmt.Errorf("scan intel feed: %w", err)
		}
		var item FeedStatus
		if err := json.Unmarshal(raw, &item); err != nil {
			return nil, fmt.Errorf("decode intel feed %s: %w", source, err)
		}
		if item.Source == "" {
			item.Source = source
		}
		if item.Source != source {
			return nil, fmt.Errorf("load intel feed %s: document source mismatch", source)
		}
		loaded[source] = item
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("load intel feeds: %w", err)
	}
	return loaded, nil
}
