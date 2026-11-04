package control

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/zodirc/Vesper/internal/id"
)

// APISession 是一条已签发的管理会话。
// APISession is one issued management session.
//
// Token 是调用方保存的凭据。PrincipalID 是写入审计记录的管理员标识。ExpiresAt 之后会话不再接受。
// Token is the credential held by the caller. PrincipalID is the administrator identifier written into audit records. The session is no longer accepted after ExpiresAt.
type APISession struct {
	Token       id.ID
	PrincipalID id.ID
	ExpiresAt   time.Time
}

// PrincipalID 返回本机管理员标识。配置了数据库时，这个标识在重启后保持不变。
// PrincipalID returns the local administrator identifier. When a database is configured, this identifier stays the same across restarts.
func (s *Service) PrincipalID() id.ID {
	return s.principal
}

// RestoreAPISessions 返回尚未到期的会话，并删除已经到期的会话。没有数据库时返回空列表。
// RestoreAPISessions returns sessions that have not expired and deletes sessions that have. It returns an empty list when no database is configured.
//
// now 用于判断到期。调用方用返回的会话恢复进程内索引。
// now decides expiry. The caller restores its in-process index from the returned sessions.
func (s *Service) RestoreAPISessions(ctx context.Context, now time.Time) ([]APISession, error) {
	if s.db == nil {
		return nil, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return s.db.restoreAPISessions(ctx, now.UTC())
}

// StoreAPISession 把会话写入数据库。没有数据库时不写入，调用方只保留进程内副本。
// StoreAPISession writes a session to the database. When no database is configured, it writes nothing and the caller keeps only the in-process copy.
//
// 写入失败时返回错误，调用方不得把这次令牌交给客户端。
// On a write failure it returns an error, and the caller must not hand that token to the client.
func (s *Service) StoreAPISession(ctx context.Context, item APISession, created time.Time) error {
	if item.Token.IsZero() || item.PrincipalID.IsZero() || !item.ExpiresAt.After(created) {
		return fmt.Errorf("store api session: token, principal, or expiry is invalid")
	}
	if s.db == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return s.db.insertAPISession(ctx, item, created.UTC())
}

// DropAPISession 删除一条会话。没有数据库时不执行删除。
// DropAPISession deletes one session. It does not delete anything when no database is configured.
func (s *Service) DropAPISession(ctx context.Context, token id.ID) error {
	if token.IsZero() || s.db == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	_, err := s.db.pool.Exec(ctx, `DELETE FROM api_session WHERE token = $1::uuid`, token.String())
	if err != nil {
		return fmt.Errorf("delete api session: %w", err)
	}
	return nil
}

func (d *pgStore) ensurePrincipal(ctx context.Context, candidate id.ID) (id.ID, error) {
	existing, found, err := d.readPrincipal(ctx)
	if err != nil {
		return id.ID{}, err
	}
	if found {
		return existing, nil
	}
	_, err = d.pool.Exec(ctx, `INSERT INTO api_principal (id, singleton, created_at) VALUES ($1::uuid, true, now())`, candidate.String())
	if err == nil {
		return candidate, nil
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		existing, found, readErr := d.readPrincipal(ctx)
		if readErr != nil {
			return id.ID{}, readErr
		}
		if found {
			return existing, nil
		}
	}
	return id.ID{}, fmt.Errorf("create api principal: %w", err)
}

func (d *pgStore) readPrincipal(ctx context.Context) (id.ID, bool, error) {
	var text string
	err := d.pool.QueryRow(ctx, `SELECT id::text FROM api_principal`).Scan(&text)
	if errors.Is(err, pgx.ErrNoRows) {
		return id.ID{}, false, nil
	}
	if err != nil {
		return id.ID{}, false, fmt.Errorf("read api principal: %w", err)
	}
	parsed, err := id.Parse(text)
	if err != nil {
		return id.ID{}, false, fmt.Errorf("read api principal: %w", err)
	}
	return parsed, true, nil
}

func (d *pgStore) restoreAPISessions(ctx context.Context, now time.Time) ([]APISession, error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("restore api sessions: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `DELETE FROM api_session WHERE expires_at <= $1`, now); err != nil {
		return nil, fmt.Errorf("delete expired api sessions: %w", err)
	}
	rows, err := tx.Query(ctx, `SELECT token::text, principal_id::text, expires_at FROM api_session ORDER BY created_at`)
	if err != nil {
		return nil, fmt.Errorf("restore api sessions: %w", err)
	}
	defer rows.Close()
	var out []APISession
	for rows.Next() {
		var tokenText, principalText string
		var expires time.Time
		if err := rows.Scan(&tokenText, &principalText, &expires); err != nil {
			return nil, fmt.Errorf("restore api sessions: %w", err)
		}
		token, err := id.Parse(tokenText)
		if err != nil {
			return nil, fmt.Errorf("restore api sessions: %w", err)
		}
		principal, err := id.Parse(principalText)
		if err != nil {
			return nil, fmt.Errorf("restore api sessions: %w", err)
		}
		out = append(out, APISession{Token: token, PrincipalID: principal, ExpiresAt: expires.UTC()})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("restore api sessions: %w", err)
	}
	rows.Close()
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("restore api sessions: %w", err)
	}
	return out, nil
}

func (d *pgStore) insertAPISession(ctx context.Context, item APISession, created time.Time) error {
	_, err := d.pool.Exec(ctx, `
INSERT INTO api_session (token, principal_id, expires_at, created_at)
VALUES ($1::uuid, $2::uuid, $3, $4)`, item.Token.String(), item.PrincipalID.String(), item.ExpiresAt.UTC(), created)
	if err != nil {
		return fmt.Errorf("store api session: %w", err)
	}
	return nil
}
