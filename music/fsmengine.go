/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package music

import (
	"log"
	"strings"
	"time"

	"github.com/spf13/viper"
)

func NewInterval(current, target, mininterval, maxinterval, count int) int {
	if count == 0 {
		if current < maxinterval {
			current = current * 2
		}
		if current > maxinterval {
			current = maxinterval
		}
		return current
	}
	current = target
	if current < mininterval {
		current = mininterval
	}
	return current
}

func FSMEngine(conf *Config, stopch chan struct{}) {
	mdb := conf.Internal.MusicDB
	var err error
	var count int
	var zones []Zone
	var zonename string
	var checkitem EngineCheck
	var emptymap = map[string]bool{}
	checkch := conf.Internal.EngineCheck

	if !viper.GetBool("fsmengine.active") {
		log.Printf("FSM Engine is NOT active. All state transitions must be managed manually.")
		for {
			select {
			case <-checkch: // ensure that we keep reading to keep the
				continue // channel open (otherwise other parts of MUSIC
			} // may block)
		}
	}

	mininterval := viper.GetInt("fsmengine.intervals.minimum")
	if mininterval < 15 {
		mininterval = 15
		viper.Set("fsmengine.mininterval", 15)
	}
	maxinterval := viper.GetInt("fsmengine.intervals.maximum")
	if maxinterval > 3600 {
		maxinterval = 3600
		viper.Set("fsmengine.maxinterval", 3600)
	}

	target := viper.GetInt("fsmengine.intervals.target")
	if target < mininterval || target > maxinterval {
		target = mininterval
	}
	current := target

	completeinterval := viper.GetInt("fsmengine.intervals.complete")

	if completeinterval < 3600 || completeinterval > 24*3600 {
		completeinterval = 7200
		if viper.GetBool("common.debug") {
			completeinterval = 30
			log.Printf("Debug mode on, complete check of all zones every %d seconds", completeinterval)
		}
	}

	log.Printf("Starting FSM Engine (will run once every %d seconds)", current)

	ticker := time.NewTicker(time.Duration(current) * time.Second)
	completeticker := time.NewTicker(time.Duration(completeinterval) * time.Second)

	_, err = mdb.PushZones(nil, emptymap, true) // check ALL zones
	if err != nil {
		log.Printf("FSMEngine: Error from PushZones: %v", err)
	}

	UpdateTicker := func() {
		ni := NewInterval(current, target, mininterval, maxinterval, count)
		if ni != current {
			ticker.Stop()
			log.Printf("FSM Engine: changing run interval from %d to %d seconds", current, ni)
			current = ni
			ticker = time.NewTicker(time.Duration(current) * time.Second)
		}
	}

	ReportProgress := func() {
		count = len(zones)
		if count > 0 {
			zonelist := []string{}
			for _, z := range zones {
				zonelist = append(zonelist, z.Name)
			}
			log.Printf("FSM Engine: tried to move these zones forward: %s (will run every %d seconds)",
				strings.Join(zonelist, " "), current)
		} else {
			log.Printf("FSM Engine: There are currently no unblocked zones (this check will run every %d seconds)",
				current)
		}
	}

	for {
		select {
		case checkitem = <-checkch:
			zonename = checkitem.ZoneName
			if zonename != "" {
				log.Printf("FSM Engine: Someone wants me to check the zone '%s', so I'll do that.",
					zonename)
				zones, err = mdb.PushZones(nil, map[string]bool{zonename: true}, false)
			} else {
				log.Print("FSM Engine: Someone wants me to do a run now, so I'll do that.")
				zones, err = mdb.PushZones(nil, emptymap, false)
			}
			if err != nil {
				log.Printf("FSMEngine: Error from PushZones: %v", err)
			}
			ReportProgress()
			UpdateTicker()

		case <-ticker.C:
			zones, err = mdb.PushZones(nil, emptymap, false) // check non-blocked zones only
			if err != nil {
				log.Printf("FSMEngine: Error from PushZones: %v", err)
			}
			ReportProgress()
			UpdateTicker()

		case <-completeticker.C:
			zones, err = mdb.PushZones(nil, emptymap, true) // check ALL zones
			if err != nil {
				log.Printf("FSMEngine: Error from PushZones: %v", err)
			}
			ReportProgress()
			UpdateTicker()

		case <-stopch:
			ticker.Stop()
			log.Println("FSM Engine: stop signal received.")
			return
		}
	}
}
