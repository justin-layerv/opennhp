//go:build ignore

package fixture

// Fixture for scripts/check-lockdown-body-drift.sh (GO_FENCE_FILE). The
// runtime-resolved body declaration carries no map-literal assignment (check
// 4a), and publicALBLockdownExpectedCT matches the rule's content_type (check
// 6); the fence-literal-reintroduced and ct-drift fixtures flip those.
const publicALBLockdownExpectedCT = "application/json"

var publicALBLockdownExpectedBody = map[string]string{"error": "not found"}
