package server

import (
	"fmt"
	"strings"
)

// parsePermitStrictEnv decodes a permit/strict boolean env var
// (false → permit, true → strict). Shared by every fail-closed
// gate on the server — NHP_INTERNAL_AUTH_REQUIRE (#1122 HMAC),
// NHP_KNOCK_HEADERTYPE_VERIFY (#1154 type-flip), and any future
// gate with the same rollout pattern.
//
// Accepted tokens are deliberately narrow: an unrecognized value
// (operator typo in Terraform — "enable", "2", "yep", etc.) must
// NOT silently leave the gate in permit mode. That's how an
// operator thinks they've flipped strict but the runtime keeps the
// bypass live. Every gate uses the same token list so a Terraform
// template operator doesn't have to learn a different grammar per
// gate.
//
// Whitespace is trimmed. Case is ignored. Empty → false (permit).
func parsePermitStrictEnv(raw string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "false", "0", "no", "off":
		return false, nil
	case "true", "1", "yes", "on":
		return true, nil
	default:
		return false, fmt.Errorf("unrecognized value %q; expected true/false/1/0/yes/no/on/off", raw)
	}
}
