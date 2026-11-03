package control

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

// pgStore 是控制面的 PostgreSQL 连接。任务状态以这里的已提交数据为准。
// pgStore is the PostgreSQL connection for the control plane. Committed rows here are the task-state authority.
type pgStore struct {
	pool *pgxpool.Pool
}

func openStore(ctx context.Context, dsn, migrationFile string) (*pgStore, error) {
	if dsn == "" {
		return nil, fmt.Errorf("open database: DSN is empty")
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	store := &pgStore{pool: pool}
	if err := store.migrate(ctx, migrationFile); err != nil {
		pool.Close()
		return nil, err
	}
	return store, nil
}

func (d *pgStore) migrate(ctx context.Context, path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("read migration path %s: %w", path, err)
	}
	if info.IsDir() {
		entries, err := os.ReadDir(path)
		if err != nil {
			return fmt.Errorf("read migration directory %s: %w", path, err)
		}
		var names []string
		for _, entry := range entries {
			if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".sql") {
				names = append(names, entry.Name())
			}
		}
		sortStrings(names)
		for _, name := range names {
			if err := d.migrateFile(ctx, filepath.Join(path, name)); err != nil {
				return err
			}
		}
		return nil
	}
	return d.migrateFile(ctx, path)
}

func sortStrings(values []string) {
	for i := 1; i < len(values); i++ {
		for j := i; j > 0 && values[j] < values[j-1]; j-- {
			values[j], values[j-1] = values[j-1], values[j]
		}
	}
}

func (d *pgStore) migrateFile(ctx context.Context, path string) error {
	name := filepath.Base(path)
	applied, err := d.migrationApplied(ctx, name)
	if err != nil {
		return err
	}
	if applied {
		return nil
	}
	script, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read migration %s: %w", path, err)
	}
	for _, stmt := range splitSQL(string(script)) {
		if _, err := d.pool.Exec(ctx, stmt); err != nil {
			preview := stmt
			if len(preview) > 80 {
				preview = preview[:80]
			}
			return fmt.Errorf("apply migration %s (%s): %w", name, preview, err)
		}
	}
	if _, err := d.pool.Exec(ctx, `INSERT INTO schema_migration (filename, applied_at) VALUES ($1, now()) ON CONFLICT (filename) DO NOTHING`, name); err != nil {
		return fmt.Errorf("record migration %s: %w", name, err)
	}
	return nil
}

func (d *pgStore) migrationApplied(ctx context.Context, name string) (bool, error) {
	var reg *string
	if err := d.pool.QueryRow(ctx, `SELECT to_regclass('public.schema_migration')::text`).Scan(&reg); err != nil {
		return false, fmt.Errorf("check schema migration table: %w", err)
	}
	if reg == nil || *reg == "" {
		return false, nil
	}
	var applied bool
	if err := d.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM schema_migration WHERE filename = $1)`, name).Scan(&applied); err != nil {
		return false, fmt.Errorf("check migration %s: %w", name, err)
	}
	return applied, nil
}

func splitSQL(script string) []string {
	var out []string
	for _, part := range strings.Split(script, ";") {
		stmt := strings.TrimSpace(part)
		if stmt == "" || onlySQLComments(stmt) {
			continue
		}
		out = append(out, stmt)
	}
	return out
}

func onlySQLComments(stmt string) bool {
	for _, line := range strings.Split(stmt, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" && !strings.HasPrefix(trimmed, "--") {
			return false
		}
	}
	return true
}
