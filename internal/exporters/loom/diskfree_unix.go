//go:build linux || darwin || freebsd

package loom

import "syscall"

// diskFree reports the bytes an unprivileged writer may still use on the
// filesystem holding dir. It leaves out the root-reserved blocks on purpose:
// the agent runs as root, and those blocks are what keeps the rest of the
// host working when the spool is the thing filling the disk.
func diskFree(dir string) (uint64, bool) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return 0, false
	}
	return uint64(st.Bavail) * uint64(st.Bsize), true
}
