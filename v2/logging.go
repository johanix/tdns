/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */

package tdns

import (
	"log"

	"gopkg.in/natefinch/lumberjack.v2"
)

func SetupLogging(logfile string) error {

	log.SetFlags(log.Lshortfile | log.Ltime)

	if logfile != "" {
		log.SetOutput(&lumberjack.Logger{
			Filename:   logfile,
			MaxSize:    20,
			MaxBackups: 3,
			MaxAge:     14,
		})
	} else {
		log.Fatalf("Error: standard log (key log.file) not specified")
	}

	return nil
}

// SetupCliLogging sets up logging for CLI commands with file/line info when verbose or debug mode is enabled.
// This is called for CLI commands that may not have a log file configured.
// Default CLI logging has no timestamps; verbose/debug mode adds file/line info.
func SetupCliLogging() {
	if Globals.Verbose || Globals.Debug {
		log.SetFlags(log.Lshortfile | log.Ltime)
	} else {
		// Remove timestamps from default CLI output
		log.SetFlags(0)
	}
}
