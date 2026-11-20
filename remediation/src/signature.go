//go:build windows

package remediation

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"strings"
)

// signature identifies a file by size and SHA-256. The size is checked first
// so that only same-sized files are ever hashed.
type signature struct {
	size   int64
	sha256 string // lowercase hex
}

// malTrack is the sample from the README's "Sample Info" table (mal-track.exe).
var malTrack = signature{
	size:   674304,
	sha256: "a164abbb6778e1378af208b4a3d4833c2b226c68452d2151fb14e2e01a578fdd",
}

// matches reports whether the file at path has this signature.
func (s signature) matches(path string) (bool, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return false, err
	}
	if !fi.Mode().IsRegular() || fi.Size() != s.size {
		return false, nil
	}
	return s.hashMatches(path)
}

// hashMatches reports whether the SHA-256 of the file at path equals the
// signature's. The caller has already checked the size.
func (s signature) hashMatches(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return false, err
	}
	return strings.EqualFold(hex.EncodeToString(h.Sum(nil)), s.sha256), nil
}
