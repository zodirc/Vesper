//go:build !windows

package winsvc

import "context"

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

// RunningAsService 在非 Windows 上始终为 false。
// RunningAsService is always false outside Windows.
func RunningAsService() (bool, error) {
	return false, nil
}

// Execute 在非 Windows 上不注册服务。
// Execute does not register a service outside Windows.
func Execute(command string) (Result, error) {
	return Result{}, ErrUnsupported
}

// Run 在非 Windows 上不进入服务控制循环。
// Run does not enter the service control loop outside Windows.
func Run(program Program) error {
	return ErrUnsupported
}
