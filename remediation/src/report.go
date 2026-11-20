//go:build windows

package remediation

import "fmt"

type Report struct{ Failed int }

func (r *Report) Info(format string, args ...any) { fmt.Printf(format+"\n", args...) }

func (r *Report) Fail(format string, args ...any) {
	r.Failed++
	fmt.Printf("FAILED: "+format+"\n", args...)
}
