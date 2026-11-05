//go:build windows

package winsvc

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	eventRunning = 1
	eventStopped = 2
	eventFailed  = 3
)

// Result 是一次服务管理命令的结果。
// Result is the outcome of one service-management command.
type Result struct {
	// Message 是可以打印的结果，不含口令、连接串或 API 密钥。
	// Message is safe to print. It contains no password, connection string, or API key.
	Message string
}

// Program 在取消时停止控制服务。ready 在监听地址绑定成功后调用一次。
// Program runs the control service until the context is canceled. ready is called once after the listen address is bound.
type Program func(ctx context.Context, ready func()) error

// RunningAsService 报告当前进程是否由服务控制管理器启动。
// RunningAsService reports whether the service control manager started this process.
func RunningAsService() (bool, error) {
	return svc.IsWindowsService()
}

// Execute 执行 install、uninstall、start 或 stop。
// Execute performs install, uninstall, start, or stop.
//
// 命令不读取数据库。install 需要当前进程已经具备管理口令和数据库连接串。
// The command does not read the database. install requires the current process to already have the administrator password and database URL.
func Execute(command string) (Result, error) {
	switch command {
	case "install":
		return installService()
	case "uninstall":
		return uninstallService()
	case "start":
		return startCommand()
	case "stop":
		return stopCommand()
	default:
		return Result{}, fmt.Errorf("%w: %s", ErrFailed, command)
	}
}

// Run 把 program 交给服务控制管理器。停止、关机和预关机取消 program 的上下文。
// Run gives program to the service control manager. Stop, shutdown, and preshutdown cancel its context.
func Run(program Program) error {
	if program == nil {
		return fmt.Errorf("%w: program is missing", ErrFailed)
	}
	return svc.Run(Name, &handler{program: program, secrets: Secrets(os.Getenv)})
}

type handler struct {
	program Program
	secrets []string
}

func (h *handler) Execute(_ []string, requests <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	accepted := svc.AcceptStop | svc.AcceptShutdown | svc.AcceptPreShutdown
	changes <- svc.Status{State: svc.StartPending, CheckPoint: 1, WaitHint: uint32(StartHint / time.Millisecond)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan struct{})
	errCh := make(chan error, 1)
	go func() {
		var once sync.Once
		errCh <- h.program(ctx, func() { once.Do(func() { close(ready) }) })
	}()
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	checkpoint := uint32(1)
	running := false
	for {
		select {
		case <-ready:
			running = true
			changes <- svc.Status{State: svc.Running, Accepts: accepted}
			writeEvent(eventlog.Info, eventRunning, "vesperd is running")
		case <-ticker.C:
			if !running {
				checkpoint++
				changes <- svc.Status{State: svc.StartPending, CheckPoint: checkpoint, WaitHint: uint32(StartHint / time.Millisecond)}
			}
		case err := <-errCh:
			return serviceExit(err, h.secrets)
		case request := <-requests:
			switch request.Cmd {
			case svc.Interrogate:
				changes <- request.CurrentStatus
			case svc.Stop, svc.Shutdown, svc.PreShutdown:
				changes <- svc.Status{State: svc.StopPending, WaitHint: uint32(StopHint / time.Millisecond)}
				writeEvent(eventlog.Info, eventStopped, "vesperd is stopping")
				cancel()
				return serviceExit(<-errCh, h.secrets)
			}
		}
	}
}

func serviceExit(err error, secrets []string) (bool, uint32) {
	if err == nil || errors.Is(err, context.Canceled) {
		return false, 0
	}
	writeEvent(eventlog.Error, eventFailed, "vesperd stopped: "+Redact(err.Error(), secrets))
	return true, 1
}

func writeEvent(kind uint16, id uint32, message string) {
	log, err := eventlog.Open(Name)
	if err != nil {
		return
	}
	defer log.Close()
	switch kind {
	case eventlog.Error:
		_ = log.Error(id, message)
	case eventlog.Warning:
		_ = log.Warning(id, message)
	default:
		_ = log.Info(id, message)
	}
}

func installService() (Result, error) {
	exe, err := executablePath()
	if err != nil {
		return Result{}, err
	}
	cwd, err := os.Getwd()
	if err != nil {
		return Result{}, err
	}
	lines, err := PlanEnvironment(os.Getenv, cwd, exe)
	if err != nil {
		return Result{}, err
	}
	if err := installEventSource(); err != nil {
		return Result{}, err
	}
	manager, err := mgr.Connect()
	if err != nil {
		return Result{}, wrapSCM(err)
	}
	defer manager.Disconnect()
	config := serviceConfig()
	service, created, err := openOrCreate(manager, exe, config)
	if err != nil {
		return Result{}, err
	}
	defer service.Close()
	if !created {
		config.BinaryPathName = syscall.EscapeArg(exe)
		if err := service.UpdateConfig(config); err != nil {
			return Result{}, wrapSCM(err)
		}
	}
	if err := writeEnvironment(lines); err != nil {
		return Result{}, abandonCreate(service, created, err)
	}
	if err := configureRecovery(service); err != nil {
		return Result{}, abandonCreate(service, created, wrapSCM(err))
	}
	status, err := service.Query()
	if err != nil {
		return Result{}, wrapSCM(err)
	}
	if created {
		if err := runStart(service); err != nil {
			return Result{}, fmt.Errorf("vesperd service installed, start failed: %w", err)
		}
		return Result{Message: "vesperd service installed and started"}, nil
	}
	if status.State == svc.Running || status.State == svc.StartPending {
		return Result{Message: "vesperd service updated; restart it to load the current program"}, nil
	}
	return Result{Message: "vesperd service updated"}, nil
}

func abandonCreate(service *mgr.Service, created bool, err error) error {
	if created {
		_ = service.Delete()
	}
	return err
}

func serviceConfig() mgr.Config {
	return mgr.Config{
		ServiceType:      windows.SERVICE_WIN32_OWN_PROCESS,
		StartType:        mgr.StartAutomatic,
		ErrorControl:     mgr.ErrorNormal,
		Dependencies:     []string{Dependency},
		ServiceStartName: Account,
		DisplayName:      DisplayName,
		Description:      Description,
		SidType:          windows.SERVICE_SID_TYPE_UNRESTRICTED,
		DelayedAutoStart: true,
	}
}

func openOrCreate(manager *mgr.Mgr, exe string, config mgr.Config) (*mgr.Service, bool, error) {
	service, err := manager.OpenService(Name)
	if err == nil {
		return service, false, nil
	}
	if !errnoIs(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return nil, false, wrapSCM(err)
	}
	service, err = manager.CreateService(Name, exe, config)
	if err != nil {
		return nil, false, wrapSCM(err)
	}
	return service, true, nil
}

func configureRecovery(service *mgr.Service) error {
	delays := RecoveryDelays()
	actions := make([]mgr.RecoveryAction, len(delays))
	for i, delay := range delays {
		actions[i] = mgr.RecoveryAction{Type: mgr.ServiceRestart, Delay: delay}
	}
	if err := service.SetRecoveryActions(actions, uint32(RecoveryReset/time.Second)); err != nil {
		return err
	}
	if err := service.SetRecoveryActionsOnNonCrashFailures(true); err != nil {
		return err
	}
	info := struct{ Timeout uint32 }{Timeout: uint32(StopHint / time.Millisecond)}
	return windows.ChangeServiceConfig2(service.Handle, windows.SERVICE_CONFIG_PRESHUTDOWN_INFO, (*byte)(unsafe.Pointer(&info)))
}

func writeEnvironment(lines []string) error {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\`+Name, registry.SET_VALUE)
	if err != nil {
		return wrapSCM(err)
	}
	defer key.Close()
	if err := key.SetStringsValue("Environment", lines); err != nil {
		return wrapSCM(err)
	}
	return nil
}

func installEventSource() error {
	err := eventlog.InstallAsEventCreate(Name, eventlog.Error|eventlog.Warning|eventlog.Info)
	if err == nil || strings.Contains(err.Error(), "already exists") {
		return nil
	}
	return wrapSCM(err)
}

func uninstallService() (Result, error) {
	manager, err := mgr.Connect()
	if err != nil {
		return Result{}, wrapSCM(err)
	}
	defer manager.Disconnect()
	service, err := manager.OpenService(Name)
	if errnoIs(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		_ = eventlog.Remove(Name)
		return Result{Message: "vesperd service is not installed"}, nil
	}
	if err != nil {
		return Result{}, wrapSCM(err)
	}
	defer service.Close()
	if err := runStop(service); err != nil {
		return Result{}, err
	}
	if err := service.Delete(); err != nil {
		return Result{}, wrapSCM(err)
	}
	_ = eventlog.Remove(Name)
	return Result{Message: "vesperd service removed"}, nil
}

func startCommand() (Result, error) {
	service, closeService, err := openService()
	if err != nil {
		return Result{}, err
	}
	defer closeService()
	if err := runStart(service); err != nil {
		return Result{}, err
	}
	return Result{Message: "vesperd service started"}, nil
}

func stopCommand() (Result, error) {
	service, closeService, err := openService()
	if err != nil {
		return Result{}, err
	}
	defer closeService()
	if err := runStop(service); err != nil {
		return Result{}, err
	}
	return Result{Message: "vesperd service stopped"}, nil
}

func openService() (*mgr.Service, func(), error) {
	manager, err := mgr.Connect()
	if err != nil {
		return nil, nil, wrapSCM(err)
	}
	service, err := manager.OpenService(Name)
	if err != nil {
		_ = manager.Disconnect()
		if errnoIs(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			return nil, nil, fmt.Errorf("%w: vesperd is not installed", ErrFailed)
		}
		return nil, nil, wrapSCM(err)
	}
	return service, func() {
		_ = service.Close()
		_ = manager.Disconnect()
	}, nil
}

func runStart(service *mgr.Service) error {
	status, err := service.Query()
	if err != nil {
		return wrapSCM(err)
	}
	if status.State == svc.Running {
		return nil
	}
	if status.State == svc.StopPending {
		if _, err := waitState(service, svc.Stopped); err != nil {
			return err
		}
	}
	if err := service.Start(); err != nil && !errnoIs(err, windows.ERROR_SERVICE_ALREADY_RUNNING) {
		return wrapSCM(err)
	}
	status, err = waitState(service, svc.Running)
	if err != nil {
		return err
	}
	if status.State != svc.Running {
		return fmt.Errorf("%w: state %d", ErrFailed, status.State)
	}
	return nil
}

func runStop(service *mgr.Service) error {
	deadline := time.Now().Add(StateWait)
	for {
		status, err := service.Query()
		if err != nil {
			return wrapSCM(err)
		}
		switch status.State {
		case svc.Stopped:
			return nil
		case svc.StopPending:
			_, err = waitState(service, svc.Stopped)
			return err
		case svc.Running, svc.Paused:
			if _, err := service.Control(svc.Stop); err != nil && !errnoIs(err, windows.ERROR_SERVICE_NOT_ACTIVE) {
				return wrapSCM(err)
			}
			_, err = waitState(service, svc.Stopped)
			return err
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%w: state %d", ErrTimeout, status.State)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func waitState(service *mgr.Service, want svc.State) (svc.Status, error) {
	deadline := time.Now().Add(StateWait)
	for {
		status, err := service.Query()
		if err != nil {
			return svc.Status{}, wrapSCM(err)
		}
		if status.State == want {
			return status, nil
		}
		if want == svc.Running && status.State == svc.Stopped {
			return status, fmt.Errorf("%w: service stopped (win32=%d specific=%d)", ErrFailed, status.Win32ExitCode, status.ServiceSpecificExitCode)
		}
		if time.Now().After(deadline) {
			return status, fmt.Errorf("%w: state %d", ErrTimeout, status.State)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func executablePath() (string, error) {
	path, err := os.Executable()
	if err != nil {
		return "", err
	}
	path, err = filepath.Abs(path)
	if err != nil {
		return "", err
	}
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		return resolved, nil
	}
	return path, nil
}

func wrapSCM(err error) error {
	if err == nil {
		return nil
	}
	if errnoIs(err, windows.ERROR_ACCESS_DENIED) {
		return fmt.Errorf("%w: %v", ErrAccess, err)
	}
	return err
}

func errnoIs(err error, target syscall.Errno) bool {
	var errno syscall.Errno
	return errors.As(err, &errno) && errno == target
}
