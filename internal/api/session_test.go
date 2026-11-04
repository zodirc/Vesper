package api

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/zodirc/Vesper/internal/control"
	"github.com/zodirc/Vesper/internal/id"
)

func TestFailedSessionWriteDoesNotIssueToken(t *testing.T) {
	server := &Server{sessions: map[string]session{}}
	err := server.commitSession("token", session{UserID: id.MustNew(), Expires: time.Now().Add(time.Hour)}, func() error {
		return errors.New("database unavailable")
	})
	if err == nil {
		t.Fatal("expected write failure")
	}
	if _, ok := server.sessions["token"]; ok {
		t.Fatal("token was issued after the write failed")
	}
}

func TestExpiredSessionIsRejected(t *testing.T) {
	now := time.Date(2026, 11, 4, 9, 0, 0, 0, time.UTC)
	current := now
	svc, err := control.New(t.TempDir(), func() time.Time { return current })
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{Service: svc, User: "admin", Password: "secret", Now: func() time.Time { return current }}
	handler := server.Handler()
	token := login(t, handler)
	response := call(t, handler, http.MethodGet, "/api/v1/observation-points", token, nil)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", response.Code, response.Body.String())
	}
	current = now.Add(sessionLifetime)
	expired := call(t, handler, http.MethodGet, "/api/v1/observation-points", token, nil)
	if expired.Code != http.StatusUnauthorized {
		t.Fatalf("expired status = %d body = %s", expired.Code, expired.Body.String())
	}
}

func TestSessionSurvivesServiceRestart(t *testing.T) {
	dsn := os.Getenv("VESPER_TEST_DSN")
	if dsn == "" {
		t.Skip("VESPER_TEST_DSN is not set")
	}
	resetAPIDatabase(t, dsn)
	now := time.Date(2026, 11, 4, 9, 30, 0, 0, time.UTC)
	ctx := context.Background()
	migration := filepath.Join("..", "..", "migrations")
	first, err := control.Open(ctx, t.TempDir(), dsn, migration, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{Service: first, User: "admin", Password: "secret", Now: func() time.Time { return now }}
	if err := server.Restore(ctx); err != nil {
		t.Fatal(err)
	}
	token := login(t, server.Handler())
	principal := first.PrincipalID()
	first.Close()

	second, err := control.Open(ctx, t.TempDir(), dsn, migration, func() time.Time { return now.Add(time.Minute) })
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if second.PrincipalID() != principal {
		t.Fatalf("principal = %s, previous = %s", second.PrincipalID(), principal)
	}
	restored := &Server{Service: second, User: "admin", Password: "secret", Now: func() time.Time { return now.Add(time.Minute) }}
	if err := restored.Restore(ctx); err != nil {
		t.Fatal(err)
	}
	response := call(t, restored.Handler(), http.MethodGet, "/api/v1/observation-points", token, nil)
	if response.Code != http.StatusOK {
		t.Fatalf("restored status = %d body = %s", response.Code, response.Body.String())
	}
	later := &Server{Service: second, User: "admin", Password: "secret", Now: func() time.Time { return now.Add(sessionLifetime + time.Minute) }}
	if err := later.Restore(ctx); err != nil {
		t.Fatal(err)
	}
	rejected := call(t, later.Handler(), http.MethodGet, "/api/v1/observation-points", token, nil)
	if rejected.Code != http.StatusUnauthorized {
		t.Fatalf("later status = %d body = %s", rejected.Code, rejected.Body.String())
	}
}

func resetAPIDatabase(t *testing.T, dsn string) {
	t.Helper()
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if _, err := pool.Exec(ctx, `DROP SCHEMA IF EXISTS public CASCADE`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `CREATE SCHEMA public`); err != nil {
		t.Fatal(err)
	}
}
