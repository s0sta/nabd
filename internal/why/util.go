package why

import (
	"io/fs"
	"os"
	"syscall"
)

var skipDir = fs.SkipDir

func devOf(fi os.FileInfo) uint64 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return uint64(st.Dev)
	}
	return 0
}

func allocated(fi os.FileInfo) uint64 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && st.Blocks > 0 {
		return uint64(st.Blocks) * 512
	}
	if fi.Size() > 0 {
		return uint64(fi.Size())
	}
	return 0
}
