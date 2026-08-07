//go:build smoke

package smoke

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/smithy-go"
)

type iamPolicyDocument struct {
	Statements []iamPolicyStatement `json:"Statement"`
}

type iamPolicyStatement struct {
	Sid       string                                `json:"Sid"`
	Effect    string                                `json:"Effect"`
	Action    json.RawMessage                       `json:"Action"`
	Resource  json.RawMessage                       `json:"Resource"`
	Condition map[string]map[string]json.RawMessage `json:"Condition"`
}

// iamStrings decodes an IAM policy field that IAM may serialize as either a
// single JSON string or an array of strings, failing the test on malformed input.
func iamStrings(t *testing.T, raw json.RawMessage, field string) []string {
	t.Helper()

	var values []string
	if err := json.Unmarshal(raw, &values); err == nil {
		return values
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatalf("%s: decode IAM string or string array: %v", field, err)
	}
	return []string{value}
}

// requireIAMStrings asserts the decoded field equals want as an unordered set.
func requireIAMStrings(t *testing.T, raw json.RawMessage, field string, want []string) {
	t.Helper()

	if got := iamStrings(t, raw, field); !sameStringSet(got, want) {
		t.Fatalf("%s = %v, want exactly %v", field, got, want)
	}
}

func requireIAMCondition(t *testing.T, statement iamPolicyStatement, operator, key string, want []string) {
	t.Helper()

	keys, ok := statement.Condition[operator]
	if !ok {
		t.Fatalf("statement %s missing Condition[%q]", statement.Sid, operator)
	}
	value, ok := keys[key]
	if !ok {
		t.Fatalf("statement %s missing Condition[%q][%q]", statement.Sid, operator, key)
	}
	requireIAMStrings(t, value, fmt.Sprintf("statement %s Condition[%q][%q]", statement.Sid, operator, key), want)
}

func statementsWithSid(document iamPolicyDocument, sid string) []iamPolicyStatement {
	var matches []iamPolicyStatement
	for _, statement := range document.Statements {
		if statement.Sid == sid {
			matches = append(matches, statement)
		}
	}
	return matches
}

func requireSingleIAMStatement(t *testing.T, document iamPolicyDocument, sid string) iamPolicyStatement {
	t.Helper()

	matches := statementsWithSid(document, sid)
	if len(matches) != 1 {
		t.Fatalf("inline policy has %d statements with Sid %s, want exactly 1", len(matches), sid)
	}
	return matches[0]
}

// Regression fence for PR #3740 (device credential revoke returned 500
// revoke_failed when the qurl-api task role lacked the authority-table grant).
// This mirrors the Terraform contract by validating the two named grants; a
// whole-policy least-privilege audit is a separate security invariant from the
// missing-grant availability regression fenced here.
func TestQurlDeviceCredentialAuthorityIAM_HeadReadAndRevokeAreFenced(t *testing.T) {
	requireRemote(t)

	namePrefix := fmt.Sprintf("layerv-nhp-%s", testConfig.Environment)
	roleName := fmt.Sprintf("%s-%s-qurl-api-task", namePrefix, testConfig.CellID)
	expectedAuthorityTable := namePrefix + "-control-connector-authority"

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	policy, err := testConfig.IAMClient.GetRolePolicy(ctx, &iam.GetRolePolicyInput{
		RoleName:   aws.String(roleName),
		PolicyName: aws.String("dynamodb-access"),
	})
	if err != nil {
		failureClass := "IAM API failure before the device-head grants could be evaluated"
		var apiErr smithy.APIError
		if errors.As(err, &apiErr) {
			switch apiErr.ErrorCode() {
			case "NoSuchEntity":
				failureClass = "role or inline policy is absent"
			case "AccessDenied", "AccessDeniedException":
				failureClass = "smoke caller lacks iam:GetRolePolicy (harness permission failure; device-head grants were not evaluated)"
			case "Throttling", "ThrottlingException", "RequestLimitExceeded":
				failureClass = "IAM throttled the read (transient harness failure; device-head grants were not evaluated)"
			}
		}
		t.Fatalf("%s: get IAM inline policy dynamodb-access for role %s: %v", failureClass, roleName, err)
	}

	decoded, err := url.QueryUnescape(aws.ToString(policy.PolicyDocument))
	if err != nil {
		t.Fatalf("URL-decode IAM inline policy dynamodb-access for role %s: %v", roleName, err)
	}
	var document iamPolicyDocument
	if err := json.Unmarshal([]byte(decoded), &document); err != nil {
		t.Fatalf("parse IAM inline policy dynamodb-access for role %s: %v", roleName, err)
	}

	// ControlIdentityAccess marks control identity mode. The grants use a
	// separate condition, but the qurl-service Terraform precondition requires
	// the authority-table ARN whenever control identity is enabled, so its
	// absence means cell identity mode where these grants are intentionally absent.
	if len(statementsWithSid(document, "ControlIdentityAccess")) == 0 {
		t.Skipf("role %s has no ControlIdentityAccess statement; environment uses cell identity mode, where device credential authority grants are intentionally absent", roleName)
	}

	tests := []struct {
		sid                  string
		action               string
		requireTransactionOp bool
	}{
		{sid: "ControlDeviceCredentialHeadRead", action: "dynamodb:GetItem"},
		{sid: "ControlDeviceCredentialHeadRevoke", action: "dynamodb:PutItem", requireTransactionOp: true},
	}
	for _, tc := range tests {
		t.Run(tc.sid, func(t *testing.T) {
			statement := requireSingleIAMStatement(t, document, tc.sid)
			if statement.Effect != "Allow" {
				t.Fatalf("statement %s Effect = %q, want Allow", tc.sid, statement.Effect)
			}
			requireIAMStrings(t, statement.Action, "statement "+tc.sid+" Action", []string{tc.action})
			resources := iamStrings(t, statement.Resource, "statement "+tc.sid+" Resource")
			if len(resources) != 1 {
				t.Fatalf("statement %s Resource = %v, want exactly one ARN", tc.sid, resources)
			}
			resourceARN, err := arn.Parse(resources[0])
			if err != nil {
				t.Fatalf("statement %s Resource %q is not an ARN: %v", tc.sid, resources[0], err)
			}
			if resourceARN.Service != "dynamodb" || resourceARN.Resource != "table/"+expectedAuthorityTable {
				t.Fatalf("statement %s Resource = %q, want a DynamoDB ARN ending in table/%s", tc.sid, resources[0], expectedAuthorityTable)
			}

			requireIAMCondition(t, statement, "ForAllValues:StringLike", "dynamodb:LeadingKeys", []string{"OWNER#*"})
			requireIAMCondition(t, statement, "Null", "dynamodb:LeadingKeys", []string{"false"})
			if tc.requireTransactionOp {
				requireIAMCondition(t, statement, "ForAnyValue:StringEquals", "dynamodb:EnclosingOperation", []string{"TransactWriteItems"})
			}
		})
	}

	t.Logf("role %s inline policy dynamodb-access has fenced device credential head read/revoke grants on %s", roleName, expectedAuthorityTable)
}
