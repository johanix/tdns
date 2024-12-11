/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package music

const (
	SignerJoinGroupProcess  = "add-signer"
	SignerLeaveGroupProcess = "remove-signer"
	VerifyZoneInSyncProcess = "verify-zone-sync"

	SignerGroupMinimumSigners = 1
)

const (
	DefaultCfgFile            = "/etc/music/musicd.yaml"        // used for monolithic musicd
	DefaultSidecarCfgFile     = "/etc/music/music-sidecar.yaml" // used for everything MUSIC related in music-sidecar (together with next file)
	DefaultSidecarTdnsCfgFile = "/etc/music/tdns-sidecar.yaml"  // used for everything TDNS related in music-sidecar
	DefaultZonesCfgFile       = "/etc/music/music-zones.yaml"   // Zones that MUSIC sidecar should serve; may be empty
)
