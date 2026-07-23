package connectorcell

import (
	"strings"
	"testing"
)

func TestRouteCompletionIntentStructuralBoundary(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name string
		body string
		want bool
	}{
		{
			name: "escaped keys and values",
			body: `{"asp\u0049d":"ag\u0065nt","usrData":{"qu\u0065ry":"agent_credential_recov\u0065ry"}}`,
			want: true,
		},
		{
			name: "query before asp",
			body: `{"usrData":{"query":"agent_credential_recovery"},"aspId":"agent"}`,
			want: true,
		},
		{
			name: "markers in unrelated object",
			body: `{"other":{"aspId":"agent","usrData":{"query":"agent_credential_recovery"}}}`,
		},
		{
			name: "markers in unrelated array",
			body: `{"other":[{"aspId":"agent","usrData":{"query":"agent_credential_recovery"}}]}`,
		},
		{
			name: "markers in string",
			body: `{"other":"aspId agent usrData query agent_credential_recovery"}`,
		},
		{
			name: "query below immediate data object",
			body: `{"aspId":"agent","usrData":{"nested":{"query":"agent_credential_recovery"}}}`,
		},
		{
			name: "malformed after pair",
			body: `{"aspId":"agent","usrData":{"query":"agent_credential_recovery"`,
			want: true,
		},
		{
			name: "invalid trailing byte after pair",
			body: `{"aspId":"agent","usrData":{"query":"agent_credential_recovery"}}` + string([]byte{0xff}),
			want: true,
		},
		{
			name: "mismatched composite before pair is conservative",
			body: `{"other":[},"aspId":"agent","usrData":{"query":"agent_credential_recovery"}}`,
			want: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := routeCompletionIntent([]byte(test.body)); got != test.want {
				t.Fatalf("routeCompletionIntent = %v, want %v", got, test.want)
			}
		})
	}
}

func TestRouteCompletionIntentDeepCompositeIsIterative(t *testing.T) {
	t.Parallel()
	const depth = 100_000
	body := `{"other":` + strings.Repeat("[", depth) + `0` + strings.Repeat("]", depth) + `}`
	if routeCompletionIntent([]byte(body)) {
		t.Fatal("deep unrelated composite routed as recovery")
	}
}

func TestRegistrationIntentRoutingOwnsExactAgentWithoutLossyDecode(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name       string
		body       string
		wantOTPREG bool
		wantLST    bool
	}{
		{name: "agent registration", body: `{"aspId":"agent","usrData":{"assignment_ticket":"t"}}`, wantOTPREG: true},
		{name: "escaped agent", body: `{"asp\u0049d":"ag\u0065nt"`, wantOTPREG: true},
		{name: "agent completion", body: `{"usrData":{"query":"agent_registration_completion"},"aspId":"agent"}`, wantOTPREG: true, wantLST: true},
		{name: "malformed exact completion", body: `{"aspId":"agent","usrData":{"query":"agent_registration_completion"`, wantOTPREG: true, wantLST: true},
		{name: "other asp", body: `{"aspId":"passcode","usrData":{"query":"agent_registration_completion"}}`},
		{name: "nested agent", body: `{"other":{"aspId":"agent"}}`},
		{name: "other agent query", body: `{"aspId":"agent","usrData":{"query":"cell_assignment"}}`, wantOTPREG: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := IsRegistrationOTPIntent([]byte(test.body)); got != test.wantOTPREG {
				t.Errorf("IsRegistrationOTPIntent = %v, want %v", got, test.wantOTPREG)
			}
			if got := IsRegistrationIntent([]byte(test.body)); got != test.wantOTPREG {
				t.Errorf("IsRegistrationIntent = %v, want %v", got, test.wantOTPREG)
			}
			if got := IsRegistrationCompletionIntent([]byte(test.body)); got != test.wantLST {
				t.Errorf("IsRegistrationCompletionIntent = %v, want %v", got, test.wantLST)
			}
		})
	}
}
