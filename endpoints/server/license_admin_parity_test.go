package server

import (
	"reflect"
	"strings"
	"testing"

	"github.com/OpenNHP/opennhp/endpoints/licenseadmin"
)

// TestLicenseAdminSchemaParity guards against the duplicated License struct in
// package licenseadmin drifting from server.License on any shared DynamoDB
// attribute.
//
// The nhp-license-admin CLI is deliberately decoupled from package server (so
// the operator binary doesn't inherit the kbs/confidential-containers init
// side-effects), and therefore carries its own minimal License mirror. If a
// dynamodbav tag were renamed on one side but not the other, the tool would
// silently read/write the wrong attribute and corrupt — or quietly miss — the
// security-critical bound_pubkeys allowlist the gate enforces. This test fails
// loudly if that ever happens.
//
// The comparison is keyed on the wire attribute name (the part of the
// dynamodbav tag before any options like ",omitempty"), NOT the Go field name —
// the attribute name is what DynamoDB actually reads/writes, so a server-side Go
// field rename that keeps the same tag is correctly a non-event here. For each
// shared attribute it asserts both the full tag AND the Go type match: a type
// change (e.g. updated_at int64 → string) with an unchanged tag would otherwise
// pass parity yet silently mis-marshal the security-relevant row. It is
// intentionally one-directional (admin ⊆ server): an attribute server carries
// but the admin mirror does not is out of scope, since the tool never touches
// it.
func TestLicenseAdminSchemaParity(t *testing.T) {
	serverByAttr := dynamodbavByAttr(reflect.TypeOf(License{}))
	adminByAttr := dynamodbavByAttr(reflect.TypeOf(licenseadmin.License{}))

	if len(adminByAttr) == 0 {
		t.Fatal("no dynamodbav tags found on licenseadmin.License")
	}
	// Assert the security-critical attribute directly, so accidentally dropping
	// it from the mirror trips this test rather than only failing transitively
	// at an unrelated call site.
	if _, ok := adminByAttr["bound_pubkeys"]; !ok {
		t.Fatal("licenseadmin.License must carry the bound_pubkeys attribute")
	}

	for attr, admin := range adminByAttr {
		server, ok := serverByAttr[attr]
		if !ok {
			t.Errorf("licenseadmin.License uses dynamodbav attribute %q with no counterpart in server.License (attribute renamed on the server side? update the mirror to match)", attr)
			continue
		}
		if server.tag != admin.tag {
			t.Errorf("dynamodbav tag mismatch for attribute %q: server=%q licenseadmin=%q", attr, server.tag, admin.tag)
		}
		if server.goType != admin.goType {
			t.Errorf("Go type mismatch for attribute %q: server=%s licenseadmin=%s (mis-marshal risk)", attr, server.goType, admin.goType)
		}
	}
}

// TestLicenseAdminACAssignmentSchemaParity provides the same drift fence for
// the F5 operator CLI's ACAssignment mirror. The CLI only needs ac_id, version,
// and revoked_pubkeys, but those three tags/types are load-bearing: a mismatch
// would make the CLI mutate a row shape the server-side F5 gate does not read.
func TestLicenseAdminACAssignmentSchemaParity(t *testing.T) {
	serverByAttr := dynamodbavByAttr(reflect.TypeOf(ACAssignment{}))
	adminByAttr := dynamodbavByAttr(reflect.TypeOf(licenseadmin.ACAssignment{}))

	for _, attr := range []string{"ac_id", "version", "revoked_pubkeys"} {
		if _, ok := adminByAttr[attr]; !ok {
			t.Fatalf("licenseadmin.ACAssignment must carry %s", attr)
		}
	}
	for attr, admin := range adminByAttr {
		server, ok := serverByAttr[attr]
		if !ok {
			t.Errorf("licenseadmin.ACAssignment uses dynamodbav attribute %q with no counterpart in server.ACAssignment", attr)
			continue
		}
		if server.tag != admin.tag {
			t.Errorf("dynamodbav tag mismatch for attribute %q: server=%q licenseadmin=%q", attr, server.tag, admin.tag)
		}
		if server.goType != admin.goType {
			t.Errorf("Go type mismatch for attribute %q: server=%s licenseadmin=%s", attr, server.goType, admin.goType)
		}
	}
}

type attrSchema struct {
	tag    string
	goType string
}

// dynamodbavByAttr maps the wire attribute name (the dynamodbav tag up to the
// first comma) to its full tag and Go type, for every tagged field of t.
func dynamodbavByAttr(t reflect.Type) map[string]attrSchema {
	out := make(map[string]attrSchema)
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		tag, ok := f.Tag.Lookup("dynamodbav")
		if !ok {
			continue
		}
		attr := tag
		if comma := strings.IndexByte(tag, ','); comma >= 0 {
			attr = tag[:comma]
		}
		out[attr] = attrSchema{tag: tag, goType: f.Type.String()}
	}
	return out
}
