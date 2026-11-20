//go:build windows

package remediation

import (
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows/registry"
)

const (
	runKey      = `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
	winlogonKey = `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`
	zoneMapKey  = `SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap`
	dc3Key      = `SOFTWARE\DC3_FEXEC`
)

// zoneMapValues are the values mal-track.exe set under HKCU\...\ZoneMap, with
// the data it wrote. Their original data was not recorded, so they are
// reported but not reverted.
var zoneMapValues = []struct {
	name    string
	written uint64
}{
	{"ProxyBypass", 1},
	{"IntranetName", 1},
	{"UNCAsIntranet", 1},
	{"AutoDetect", 0},
}

// RevertChanges undoes every change documented in the README and confirmed in
// the Procmon captures.
func RevertChanges(r *Report) {
	home, err := os.UserHomeDir()
	if err != nil {
		r.Fail("locate user profile: %v", err)
	} else {
		dir := filepath.Join(home, "Documents", "maltrack")
		removeFile(r, filepath.Join(dir, "maltrack.exe"))
		removeEmptyDir(r, dir)
	}

	if appData, err := os.UserConfigDir(); err != nil { // %AppData%
		r.Fail("locate AppData: %v", err)
	} else {
		removeTree(r, filepath.Join(appData, "dclogs"))
	}

	deleteHKCUKey(r, dc3Key)
	deleteRunValue(r)
	restoreUserinit(r)
	reportZoneMap(r)
}

func deleteHKCUKey(r *Report, path string) {
	switch err := registry.DeleteKey(registry.CURRENT_USER, path); {
	case err == nil:
		r.Info("removed  HKCU\\%s", path)
	case errors.Is(err, registry.ErrNotExist):
		r.Info("absent   HKCU\\%s", path)
	default:
		r.Fail("delete HKCU\\%s: %v", path, err)
	}
}

func deleteRunValue(r *Report) {
	const name = "Mal-Track"
	full := `HKCU\` + runKey + `\` + name
	k, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.SET_VALUE)
	if errors.Is(err, registry.ErrNotExist) {
		r.Info("absent   %s", full)
		return
	}
	if err != nil {
		r.Fail("open HKCU\\%s: %v", runKey, err)
		return
	}
	defer k.Close()
	switch err := k.DeleteValue(name); {
	case err == nil:
		r.Info("removed  %s", full)
	case errors.Is(err, registry.ErrNotExist):
		r.Info("absent   %s", full)
	default:
		r.Fail("delete %s: %v", full, err)
	}
}

// restoreUserinit sets Winlogon\Userinit back to its original value if it
// contains the dropped executable. Needs administrator rights to write.
func restoreUserinit(r *Report) {
	full := `HKLM\` + winlogonKey + `\Userinit`
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, winlogonKey, registry.QUERY_VALUE)
	if err != nil {
		r.Fail("open HKLM\\%s: %v", winlogonKey, err)
		return
	}
	cur, _, err := k.GetStringValue("Userinit")
	k.Close()
	if errors.Is(err, registry.ErrNotExist) {
		r.Info("absent   %s", full)
		return
	}
	if err != nil {
		r.Fail("read %s: %v", full, err)
		return
	}
	want, tampered := restoredUserinit(cur)
	if !tampered {
		r.Info("not modified  %s", full)
		return
	}
	w, err := registry.OpenKey(registry.LOCAL_MACHINE, winlogonKey, registry.SET_VALUE)
	if err != nil {
		r.Fail("open HKLM\\%s for writing (run elevated): %v", winlogonKey, err)
		return
	}
	defer w.Close()
	if err := w.SetStringValue("Userinit", want); err != nil {
		r.Fail("restore %s: %v", full, err)
		return
	}
	r.Info("restored %s = %s", full, want)
}

// reportZoneMap prints the current data of the four ZoneMap values the malware
// set. Their original data is not documented, so they are left unchanged.
func reportZoneMap(r *Report) {
	k, err := registry.OpenKey(registry.CURRENT_USER, zoneMapKey, registry.QUERY_VALUE)
	if err != nil {
		r.Info("ZoneMap  cannot read HKCU\\%s: %v (nothing changed)", zoneMapKey, err)
		return
	}
	defer k.Close()
	for _, v := range zoneMapValues {
		cur, _, err := k.GetIntegerValue(v.name)
		if err != nil {
			r.Info("left     ZoneMap\\%s  not set (malware sets %d; original undocumented)", v.name, v.written)
			continue
		}
		r.Info("left     ZoneMap\\%s = %d (malware sets %d; original undocumented)", v.name, cur, v.written)
	}
}
