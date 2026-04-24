package tdns

import "time"

// ClampedDuration returns min(configured, R+margin) per automated KSK rollover spec §5.2.
// If configured or margin is zero, configured is returned unchanged (caller disables clamp or omits policy).
func ClampedDuration(configured, R, margin time.Duration) time.Duration {
	if configured <= 0 || margin <= 0 {
		return configured
	}
	capD := R + margin
	if configured < capD {
		return configured
	}
	return capD
}
