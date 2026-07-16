package common

import "testing"

func TestAgentAssignmentErrorCodes(t *testing.T) {
	tests := []struct {
		name string
		err  *Error
		code string
		msg  string
	}{
		{"assignment ticket invalid", ErrAssignmentTicketInvalid, "52110", "assignment ticket invalid"},
		{"assignment ticket expired", ErrAssignmentTicketExpired, "52111", "assignment ticket expired"},
		{"agent registration quota exceeded", ErrAgentRegistrationQuotaExceeded, "52112", "agent registration quota exceeded"},
		{"assignment unavailable", ErrAssignmentUnavailable, "52200", "assignment unavailable"},
		{"assignment identity rejected", ErrAssignmentIdentityRejected, "52201", "identity rejected"},
		{"reassignment in progress", ErrReassignmentInProgress, "52202", "reassignment in progress"},
		{"assignment quota exceeded", ErrAssignmentQuotaExceeded, "52203", "assignment quota exceeded"},
		{"assignment rate limited", ErrAssignmentRateLimited, "52204", "assignment rate limited"},
		{"invalid assignment request", ErrInvalidAssignmentRequest, "52205", "invalid assignment request"},
		{"completion unavailable", ErrCompletionUnavailable, "52300", "completion unavailable"},
		{"completion identity rejected", ErrCompletionIdentityRejected, "52301", "completion identity rejected"},
		{"device credential quota exceeded", ErrDeviceCredentialQuotaExceeded, "52302", "device credential quota exceeded"},
		{"device credential conflict", ErrDeviceCredentialConflict, "52303", "device credential conflict"},
		{"invalid completion request", ErrInvalidCompletionRequest, "52304", "invalid completion request"},
	}

	seen := make(map[string]string, len(tests))
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if previous, exists := seen[tc.code]; exists {
				t.Fatalf("error code %s is duplicated by %q and %q", tc.code, previous, tc.name)
			}
			seen[tc.code] = tc.name

			if got := tc.err.ErrorCode(); got != tc.code {
				t.Errorf("ErrorCode() = %q, want %q", got, tc.code)
			}
			if got := tc.err.Error(); got != tc.msg {
				t.Errorf("Error() = %q, want %q", got, tc.msg)
			}
			if got := ErrorCodeToError(tc.code); got != tc.err {
				t.Errorf("ErrorCodeToError(%q) = %p, want %p", tc.code, got, tc.err)
			}
		})
	}
	if len(seen) != 14 {
		t.Fatalf("tested %d unique assignment codes, want 14", len(seen))
	}
}
