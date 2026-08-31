//go:build !linux && !darwin && !netbsd

/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

func countOpenFDs() (int, string) {
	return -1, "unavailable"
}
