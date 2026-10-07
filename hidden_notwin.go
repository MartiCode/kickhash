//go:build !windows

package main

import "path/filepath"

func IsHiddenFile(filename string) (bool, error) {
	name := filepath.Base(path)
	return len(name) > 1 && name[0] == '.', nil
}
