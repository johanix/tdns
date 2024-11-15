/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package music

import (
	"log"
	"strconv"
	"strings"
	"time"
)

func ParseDesecDuration(str string) time.Duration {
	var clockZero, _ = time.Parse("15:04:05", "00:00:00")
	var daydur time.Duration

	if strings.Contains(str, " ") {
		stuff := strings.Split(str, " ")
		days, _ := strconv.Atoi(stuff[0])
		daydur = time.Duration(days) * time.Hour * 24
		str = stuff[1]
	}

	c, err := time.Parse("15:04:05", str)
	if err != nil {
		log.Fatalf("Error from time.ParseDuration(%s): %v", str, err)
	}
	return c.Add(daydur).Sub(clockZero)
}
