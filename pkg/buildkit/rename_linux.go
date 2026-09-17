package buildkit

import "golang.org/x/sys/unix"

// renameDirectoryNoReplace publishes a directory only if the destination is
// still absent. Do not fall back to a replacing rename on unsupported filesystems.
func renameDirectoryNoReplace(source, destination string) error {
	return unix.Renameat2(unix.AT_FDCWD, source, unix.AT_FDCWD, destination, unix.RENAME_NOREPLACE)
}
