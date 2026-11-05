package control

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/zodirc/Vesper/internal/id"
)

func saveSchedules(ctx context.Context, tx pgx.Tx, s *Service) error {
	if s.schedules == nil {
		s.schedules = map[id.ID]Schedule{}
	}
	keep := make([]string, 0, len(s.schedules))
	for scheduleID, item := range s.schedules {
		raw, err := json.Marshal(item)
		if err != nil {
			return fmt.Errorf("save schedule %s: %w", scheduleID, err)
		}
		if _, err := tx.Exec(ctx, `
INSERT INTO scan_schedule (id, document)
VALUES ($1::uuid, $2::jsonb)
ON CONFLICT (id) DO UPDATE SET document = EXCLUDED.document`, scheduleID.String(), string(raw)); err != nil {
			return fmt.Errorf("save schedule %s: %w", scheduleID, err)
		}
		keep = append(keep, scheduleID.String())
	}
	if len(keep) == 0 {
		if _, err := tx.Exec(ctx, `DELETE FROM scan_schedule`); err != nil {
			return fmt.Errorf("delete schedules: %w", err)
		}
		return nil
	}
	if _, err := tx.Exec(ctx, `DELETE FROM scan_schedule WHERE NOT (id = ANY($1::uuid[]))`, "{"+strings.Join(keep, ",")+"}"); err != nil {
		return fmt.Errorf("delete retired schedules: %w", err)
	}
	return nil
}

func loadSchedules(ctx context.Context, tx pgx.Tx) (map[id.ID]Schedule, error) {
	rows, err := tx.Query(ctx, `SELECT id, document FROM scan_schedule`)
	if err != nil {
		return nil, fmt.Errorf("load schedules: %w", err)
	}
	defer rows.Close()
	loaded := map[id.ID]Schedule{}
	for rows.Next() {
		var key string
		var raw []byte
		if err := rows.Scan(&key, &raw); err != nil {
			return nil, fmt.Errorf("scan schedule: %w", err)
		}
		var item Schedule
		if err := json.Unmarshal(raw, &item); err != nil {
			return nil, fmt.Errorf("decode schedule %s: %w", key, err)
		}
		parsed, err := id.Parse(key)
		if err != nil {
			return nil, fmt.Errorf("decode schedule %s: %w", key, err)
		}
		if item.ID != parsed {
			return nil, fmt.Errorf("load schedule %s: document id mismatch", key)
		}
		loaded[item.ID] = item
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("load schedules: %w", err)
	}
	return loaded, nil
}
