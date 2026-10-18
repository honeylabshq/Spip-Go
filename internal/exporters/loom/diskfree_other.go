//go:build !(linux || darwin || freebsd)

package loom

// diskFree is unknown here, so only the size and age caps bound the spool.
func diskFree(string) (uint64, bool) { return 0, false }
