//go:build !windows

package main

func IsHiddenFile(filename string) (bool, error) {
    return filename[0] == '.', nil
}