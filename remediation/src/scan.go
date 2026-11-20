//go:build windows

package remediation

import (
	"io/fs"
	"path/filepath"
)

// findCopies walks each root and returns every regular file matching sig.
// Entries that cannot be read are skipped.
func findCopies(roots []string, sig signature) []string {
	var found []string
	for _, root := range roots {
		filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if !d.Type().IsRegular() {
				return nil
			}
			info, err := d.Info()
			if err != nil || info.Size() != sig.size {
				return nil
			}
			if ok, _ := sig.hashMatches(path); ok {
				found = append(found, path)
			}
			return nil
		})
	}
	return found
}
