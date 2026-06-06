//go:build ignore

package fixture

// Fixture for scripts/check-lockdown-body-drift.sh (GO_RESOLVER_FILE). Only the
// SSM parameter name string is load-bearing; this is never compiled.
func resolve() string { return "/" + "sandbox" + "/nhp/qurl/internal-lockdown-body" }
