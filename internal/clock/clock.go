// Package clock 提供可替换的 UTC 时间源，供超时、有效期和租约测试使用。
// Package clock provides a replaceable UTC time source for timeouts, validity windows, and lease tests.
package clock

import "time"

// Clock 返回当前时间。实现必须使用带时区的时间，调用方统一转换为 UTC。
// Clock returns the current time. Implementations must return zoned timestamps; callers convert to UTC.
type Clock interface {
	Now() time.Time
}

// System 使用操作系统时钟。
// System uses the operating system clock.
type System struct{}

// Now 返回当前 UTC 时间。
// Now returns the current UTC time.
func (System) Now() time.Time {
	return time.Now().UTC()
}

// Fixed 返回预设时间，测试用它推进租约和授权有效期。
// Fixed returns a preset time. Tests use it to advance leases and grant validity.
type Fixed struct {
	Current time.Time
}

// Now 返回预设 UTC 时间。
// Now returns the preset UTC time.
func (c Fixed) Now() time.Time {
	return c.Current.UTC()
}
