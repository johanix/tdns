/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
//go:build !linux && !darwin && !netbsd

package tdns

func countOpenFDs() (int, string) {
	return -1, "unavailable"
}
