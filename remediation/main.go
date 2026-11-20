//go:build windows

// maltrack-remediate finds and removes the mal-track / maltrack RAT and
// reverts the changes documented in the analysis (see revert_windows.go).
// Run it as the affected user, elevated.
package main

import (
	remediation "maltrack-remediate/src"
	"os"
)

func main() {
	r := &remediation.Report{}

	r.Info("== Running processes ==")
	remediation.KillRunning(r)

	r.Info("== Files on fixed drives ==")
	remediation.DeleteCopies(r)

	r.Info("== Reverting documented changes ==")
	remediation.RevertChanges(r)

	if r.Failed > 0 {
		r.Info("\n%d step(s) failed", r.Failed)
		os.Exit(1)
	}
	r.Info("\nDone")
}
