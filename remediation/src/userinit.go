//go:build windows

package remediation

import "strings"

const (
	// userinitOriginal is the Winlogon\Userinit value the Procmon capture read
	// before mal-track.exe tried to overwrite it.
	userinitOriginal = `C:\Windows\system32\userinit.exe,`

	// droppedExeSuffix is the tail of the path mal-track.exe appended to Userinit.
	droppedExeSuffix = `\documents\maltrack\maltrack.exe`
)

// restoredUserinit returns the value Userinit must be set back to, and true,
// if cur contains the dropped executable; otherwise it returns false and the
// value is left alone.
func restoredUserinit(cur string) (string, bool) {
	if strings.Contains(strings.ToLower(cur), droppedExeSuffix) {
		return userinitOriginal, true
	}
	return "", false
}
