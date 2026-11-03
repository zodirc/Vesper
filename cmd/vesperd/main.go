// Command vesperd 运行本机控制服务，并在独立循环中执行扫描单元。
// Command vesperd runs the local control service and executes scan units on a separate loop.
package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/zodirc/Vesper/internal/api"
	"github.com/zodirc/Vesper/internal/control"
)

func main() {
	user := os.Getenv("VESPER_ADMIN_USER")
	password := os.Getenv("VESPER_ADMIN_PASSWORD")
	if user == "" || password == "" {
		log.Fatal("VESPER_ADMIN_USER and VESPER_ADMIN_PASSWORD are required")
	}
	listen := getenv("VESPER_LISTEN", "127.0.0.1:8077")
	evidenceRoot := getenv("VESPER_EVIDENCE_DIR", "var/evidence")
	dsn := os.Getenv("VESPER_DATABASE_URL")
	if dsn == "" {
		log.Fatal("VESPER_DATABASE_URL is required")
	}
	service, err := control.Open(context.Background(), evidenceRoot, dsn, getenv("VESPER_MIGRATION", "migrations"), nil)
	if err != nil {
		log.Fatal(err)
	}
	defer service.Close()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-time.After(200 * time.Millisecond):
				if _, err := service.ExecuteAvailable(ctx); err != nil {
					log.Printf("execute scan unit: %v", err)
				}
			}
		}
	}()
	server := &http.Server{
		Addr: listen, Handler: (&api.Server{Service: service, User: user, Password: password}).Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()
	log.Printf("control service listening on %s", listen)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

func getenv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
