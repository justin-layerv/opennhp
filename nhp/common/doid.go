package common

import (
	"errors"
	"regexp"
)

// DoIDPattern bounds the DoId character set used when building
// ztdo filesystem paths. DoIds arrive on the wire (DRGMsg.DoId,
// DARMsg.DoId, DAVMsg.DoId, DWRMsg.DoId) and get concatenated
// into filenames, so the validator must reject every directory
// separator shape an attacker could use to escape the config
// directory.
//
// Stricter than utils.IsValidPathComponent on purpose — blocks
// backslash, null byte, unicode separators, shell metachars.
// Production DoIds are UUIDs (hex + dash only, 36 chars), a
// strict subset of the allowed set. Deliberately wider than
// UUID-only to tolerate future id formats without becoming
// permissive: do not widen to include `.` / `/` / `:` without
// redoing the threat model in #1161.
var DoIDPattern = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)

// ErrInvalidDoID is the fixed sentinel returned to callers. It
// is deliberately generic — the rejected DoId value goes to the
// operator log with %q (escapes control bytes); the error
// shipped back on the wire carries no attacker-controlled bytes.
var ErrInvalidDoID = errors.New("invalid DoId")

// ValidateDoID enforces DoIDPattern. Call at every boundary
// where a wire-supplied DoId is about to be concatenated into a
// filesystem path — see endpoints/server/msghandler.go
// (SaveZdtoConfig, ReadZdtoConfig) and endpoints/db/utils.go
// (NewDataPrivateKeyStoreWith, DataPrivateKeyStore.Save/Delete).
// The two packages share this helper so a new sink can't land
// without opting in.
func ValidateDoID(doId string) error {
	if !DoIDPattern.MatchString(doId) {
		return ErrInvalidDoID
	}
	return nil
}
