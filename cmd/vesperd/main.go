// Command vesperd 运行本机控制服务，并在独立循环中执行扫描单元。
// Command vesperd runs the local control service and executes scan units on a separate loop.
//
// 无参数时直接运行。在 Windows 上由服务控制管理器启动时进入服务控制循环。
// With no arguments it runs directly. On Windows, a process started by the service control manager enters the service control loop.
//
// install、uninstall、start 和 stop 只管理 Windows Service。
// install, uninstall, start, and stop manage the Windows Service only.
package main

import (
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/zodirc/Vesper/internal/activedetect"
	"github.com/zodirc/Vesper/internal/api"
	"github.com/zodirc/Vesper/internal/control"
	"github.com/zodirc/Vesper/internal/winsvc"
)

func main() {
	if os.Getenv("VESPER_ISOLATE_PROVE") == "1" {
		activedetect.ProveNoEgress()
		return
	}
	if len(os.Args) > 2 {
		log.Fatal("usage: vesperd [install|uninstall|start|stop]")
	}
	if len(os.Args) == 2 {
		if !winsvc.KnownCommand(os.Args[1]) {
			log.Fatal("usage: vesperd [install|uninstall|start|stop]")
		}
		result, err := winsvc.Execute(os.Args[1])
		if err != nil {
			log.Fatal(err)
		}
		log.Print(result.Message)
		return
	}
	service, err := winsvc.RunningAsService()
	if err != nil {
		log.Printf("windows service detection: %v", err)
	}
	if service {
		if err := winsvc.Run(serve); err != nil {
			log.Fatal(err)
		}
		return
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := serve(ctx, nil); err != nil && !errors.Is(err, context.Canceled) {
		log.Fatal(err)
	}
}

func serve(ctx context.Context, ready func()) error {
	if ready == nil {
		ready = func() {}
	}
	user := os.Getenv("VESPER_ADMIN_USER")
	password := os.Getenv("VESPER_ADMIN_PASSWORD")
	if user == "" || password == "" {
		return errors.New("VESPER_ADMIN_USER and VESPER_ADMIN_PASSWORD are required")
	}
	listen := getenv("VESPER_LISTEN", "127.0.0.1:8077")
	evidenceRoot := getenv("VESPER_EVIDENCE_DIR", "var/evidence")
	dsn := os.Getenv("VESPER_DATABASE_URL")
	if dsn == "" {
		return errors.New("VESPER_DATABASE_URL is required")
	}
	service, err := control.Open(ctx, evidenceRoot, dsn, getenv("VESPER_MIGRATION", "migrations"), nil)
	if err != nil {
		return err
	}
	defer service.Close()
	go func() {
		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if _, err := service.ExecuteAvailable(ctx); err != nil && ctx.Err() == nil {
					log.Printf("execute scan unit: %v", err)
				}
			}
		}
	}()
	apiServer := &api.Server{Service: service, User: user, Password: password}
	if err := apiServer.Restore(ctx); err != nil {
		return err
	}
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		_ = ln.Close()
		return err
	}
	server := &http.Server{Handler: apiServer.Handler(), ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()
	ready()
	log.Printf("control service listening on %s", listen)
	err = server.Serve(ln)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func getenv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
