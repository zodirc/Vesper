//go:build !linux

package activedetect

import "os/exec"

func isolateProcess(cmd *exec.Cmd) {}
