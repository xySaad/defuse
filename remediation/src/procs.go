//go:build windows

package remediation

import (
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

const maxPath = 32768

// KillRunning terminates every running process whose image file matches the
// signature and waits for each to exit.
func KillRunning(r *Report) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		r.Fail("list processes: %v", err)
		return
	}
	defer windows.CloseHandle(snap)

	var e windows.ProcessEntry32
	e.Size = uint32(unsafe.Sizeof(e))
	self := uint32(os.Getpid())
	for err = windows.Process32First(snap, &e); err == nil; err = windows.Process32Next(snap, &e) {
		if e.ProcessID != 0 && e.ProcessID != self {
			killIfMatch(r, e.ProcessID)
		}
	}
}

func killIfMatch(r *Report, pid uint32) {
	path, ok := imagePath(pid)
	if !ok {
		return
	}
	if match, _ := malTrack.matches(path); !match {
		return
	}

	h, err := windows.OpenProcess(windows.PROCESS_TERMINATE|windows.SYNCHRONIZE, false, pid)
	if err != nil {
		r.Fail("pid %d %s: open for termination: %v", pid, path, err)
		return
	}
	defer windows.CloseHandle(h)
	if err := windows.TerminateProcess(h, 1); err != nil {
		r.Fail("pid %d %s: terminate: %v", pid, path, err)
		return
	}
	if ev, err := windows.WaitForSingleObject(h, 5000); err != nil || ev != windows.WAIT_OBJECT_0 {
		r.Fail("pid %d %s: did not exit after termination", pid, path)
		return
	}
	r.Info("killed pid %d  %s", pid, path)
}

// imagePath returns the executable path of a process, if it can be queried.
func imagePath(pid uint32) (string, bool) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "", false
	}
	defer windows.CloseHandle(h)
	buf := make([]uint16, maxPath)
	n := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &n); err != nil {
		return "", false
	}
	return windows.UTF16ToString(buf[:n]), true
}
