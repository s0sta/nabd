package core

import "os"

func pageSize() int { return os.Getpagesize() }
