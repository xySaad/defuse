//go:build windows

package remediation

import (
	"errors"
	"io/fs"
	"os"

	"golang.org/x/sys/windows"
)

// fixedDriveRoots returns the root of every local fixed drive, e.g. `C:\`.
func fixedDriveRoots() []string {
	mask, err := windows.GetLogicalDrives()
	if err != nil {
		return nil
	}
	var roots []string
	for i := 0; i < 26; i++ {
		if mask&(1<<uint(i)) == 0 {
			continue
		}
		root := string(rune('A'+i)) + `:\`
		p, err := windows.UTF16PtrFromString(root)
		if err != nil {
			continue
		}
		if windows.GetDriveType(p) == windows.DRIVE_FIXED {
			roots = append(roots, root)
		}
	}
	return roots
}

// DeleteCopies deletes every file on the fixed drives that matches the signature.
func DeleteCopies(r *Report) {
	for _, path := range findCopies(fixedDriveRoots(), malTrack) {
		removeFile(r, path)
	}
}

func removeFile(r *Report, path string) {
	switch err := os.Remove(path); {
	case err == nil:
		r.Info("deleted  %s", path)
	case errors.Is(err, fs.ErrNotExist):
		r.Info("absent   %s", path)
	default:
		r.Fail("delete %s: %v", path, err)
	}
}

// removeEmptyDir removes dir only if it is empty.
func removeEmptyDir(r *Report, dir string) {
	switch err := os.Remove(dir); {
	case err == nil:
		r.Info("removed  %s", dir)
	case errors.Is(err, fs.ErrNotExist):
		r.Info("absent   %s", dir)
	default:
		r.Fail("remove directory %s: %v", dir, err)
	}
}

// removeTree removes dir and everything in it.
func removeTree(r *Report, dir string) {
	if _, err := os.Stat(dir); errors.Is(err, fs.ErrNotExist) {
		r.Info("absent   %s", dir)
		return
	}
	if err := os.RemoveAll(dir); err != nil {
		r.Fail("remove %s: %v", dir, err)
		return
	}
	r.Info("removed  %s", dir)
}
