package server

import (
	"testing"

	"github.com/OpenNHP/opennhp/endpoints/internal/acktoken"
)

// TestACKTokenOperationTimeout_InSync guards the deliberately-duplicated
// DynamoDB read timeout. acktoken.OperationTimeout mirrors
// server.DynamoDBOperationTimeout because the AC's read-only reader must not
// import package server (the whole point of the acktoken extraction). The two
// are kept equal by comment today; this test fails loudly if a future tuner
// changes one without the other. The test can import both even though the
// acktoken package cannot import server.
func TestACKTokenOperationTimeout_InSync(t *testing.T) {
	if acktoken.OperationTimeout != DynamoDBOperationTimeout {
		t.Fatalf("acktoken.OperationTimeout (%v) != server.DynamoDBOperationTimeout (%v) — the duplicated DynamoDB read timeout drifted; update both",
			acktoken.OperationTimeout, DynamoDBOperationTimeout)
	}
}
