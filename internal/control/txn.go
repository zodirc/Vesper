package control

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
)

func (d *pgStore) transact(ctx context.Context, fn func(pgx.Tx) error) error {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin task transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := fn(tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit task transaction: %w", err)
	}
	return nil
}

// commitState 在一个数据库事务中锁定任务行、装入已提交状态、执行变更并写回。
// commitState locks task rows, loads committed state, applies the change, and writes it back in one database transaction.
//
// 没有数据库时只执行 fn。fn 为空表示把当前内存中的非任务变更与重新装入的任务状态一起提交。
// Without a database it only runs fn. A nil fn commits in-memory non-task changes together with the reloaded task state.
//
// 调用方必须已经持有服务锁。事务失败后会从数据库重新装入，避免内存留下未提交的任务变更。
// The caller must already hold the service lock. After a transaction failure the service reloads from the database so uncommitted task changes do not remain in memory.
func (s *Service) commitState(ctx context.Context, fn func() error) error {
	if s.db == nil {
		if fn == nil {
			return nil
		}
		return fn()
	}
	if ctx == nil {
		ctx = context.Background()
	}
	err := s.db.transact(ctx, func(tx pgx.Tx) error {
		if err := s.db.reloadTaskAuthority(ctx, tx, s); err != nil {
			return err
		}
		if fn != nil {
			if err := fn(); err != nil {
				return err
			}
		}
		return saveAll(ctx, tx, s)
	})
	if err != nil {
		if loadErr := s.db.load(context.Background(), s); loadErr != nil {
			return fmt.Errorf("%w; reload failed: %v", err, loadErr)
		}
		return err
	}
	return nil
}

func (s *Service) flush(ctx context.Context) error {
	return s.commitState(ctx, nil)
}
