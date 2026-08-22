package license

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// DefaultHardwareGrace is how long a hardware-mismatch grace period lasts:
// long enough for a human support round-trip (customer reports the new
// fingerprint, vendor re-issues) without demanding same-minute action, short
// enough that it isn't a de-facto permanent bypass of node-locking.
const DefaultHardwareGrace = 72 * time.Hour

// graceState is persisted next to the license file (path + graceSuffix) so the
// grace period survives a restart — without persistence, every restart would
// look like "the first mismatch" and grace would never actually expire.
type graceState struct {
	// MismatchedFingerprint is the CurrentFingerprint seen when this grace
	// period was granted. If a later boot sees a DIFFERENT mismatched
	// fingerprint (e.g. hardware changed again, or a stale grace file was
	// copied to a new machine), that is treated as a fresh mismatch, not a
	// continuation — it gets its own new grace window, not the old deadline.
	MismatchedFingerprint string    `json:"mismatched_fingerprint"`
	FirstSeen             time.Time `json:"first_seen"`
	Until                 time.Time `json:"until"`
}

const graceSuffix = ".hwgrace"

// LoadWithGrace behaves like Load, except a hardware-lock mismatch is not an
// immediate hard failure: the first time a given mismatch is seen, it grants
// a grace window (persisted in a small state file next to the license, so it
// survives restarts) during which the gateway boots normally — Valid=true,
// Grace=true — instead of refusing to start. Once the window elapses, the
// same mismatch hard-fails exactly like Load would. A grace period is
// per-mismatch: a different fingerprint (hardware changed again) starts a
// fresh window rather than inheriting whatever was left of an old one.
//
// This exists because a same-minute production outage over a routine host
// migration is a worse outcome than a bounded window of running on
// technically-mismatched hardware — the deterrent value of node-locking is in
// the eventual hard stop and the loud, unmissable warning in the meantime, not
// in a zero-tolerance first instant.
//
// Known limitation (documented, not silently accepted — audit finding,
// 2026-08-23): the grace state file has no integrity protection tying it to
// the license bytes, so anyone with filesystem WRITE access to the license's
// directory specifically (a materially narrower bar than "compromised the
// host," but broader than "root only" on e.g. a shared volume) could delete
// it before the window elapses to make the next boot look like a first-ever
// mismatch and get a fresh window, indefinitely. This is consistent with the
// package's stated "deterrent, not DRM" threat model (that level of access
// already permits patching the binary or replacing publicKeyB64), but IS a
// materially different bar than "patch a Go binary" — mitigated in practice
// by cmd/gateway/main.go's licenseRecheckLoop, which re-logs a loud grace
// warning on every re-check (default every 15 min) for as long as the
// mismatch persists, rather than only once at boot — a repeatedly-reset
// grace period is now a repeatedly-loud one, not a silent one.
func LoadWithGrace(path string, graceWindow time.Duration) Status {
	st := Load(path)

	gracePath := path + graceSuffix
	if !st.HardwareMismatch {
		// Not a hardware-mismatch case at all (valid, expired, tampered,
		// missing...) — grace is only ever about hardware, so nothing to do
		// beyond tidying up a stale grace file left over from a since-fixed
		// mismatch (e.g. a correct new license has since been installed).
		if st.Valid {
			_ = os.Remove(gracePath) // best-effort; a leftover file here is harmless
		}
		return st
	}

	now := time.Now()
	existing, err := readGraceState(gracePath)
	if err == nil && existing.MismatchedFingerprint == st.CurrentFingerprint {
		// Same ongoing mismatch as a previous boot.
		if now.Before(existing.Until) {
			st.Valid = true
			st.Grace = true
			st.GraceUntil = existing.Until
			return st
		}
		// Grace window for this mismatch has elapsed — hard-fail, same as
		// Load would without grace at all. st.Reason (from Load) already
		// explains the mismatch; add when the grace ran out for clarity.
		st.Reason += fmt.Sprintf(" (a %s grace period was granted at %s and expired at %s)",
			graceWindow, existing.FirstSeen.Format(time.RFC3339), existing.Until.Format(time.RFC3339))
		return st
	}

	// First time we've seen this specific mismatch (or the grace file is
	// missing/unreadable/for a different fingerprint) — grant a fresh window.
	// A zero/negative graceWindow means no real grace (e.g. an operator who
	// disabled grace outright): record it so a later boot doesn't re-grant,
	// but don't let THIS boot through either.
	until := now.Add(graceWindow)
	_ = writeGraceState(gracePath, graceState{ // best-effort: a write failure just means no persistence across restarts, not a security hole
		MismatchedFingerprint: st.CurrentFingerprint,
		FirstSeen:             now,
		Until:                 until,
	})
	if !now.Before(until) {
		st.Reason += fmt.Sprintf(" (grace window is %s — non-positive, so no grace applies)", graceWindow)
		return st
	}
	st.Valid = true
	st.Grace = true
	st.GraceUntil = until
	return st
}

func readGraceState(path string) (graceState, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- derived from operator-supplied license_path, not user input
	if err != nil {
		return graceState{}, err
	}
	var gs graceState
	if err := json.Unmarshal(data, &gs); err != nil {
		return graceState{}, fmt.Errorf("grace state file is present but corrupt: %w", err)
	}
	return gs, nil
}

func writeGraceState(path string, gs graceState) error {
	data, err := json.Marshal(gs)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}
