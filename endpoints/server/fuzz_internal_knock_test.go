package server

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/OpenNHP/opennhp/nhp/common"
)

// FuzzHttpKnockForwardRequest exercises the JSON unmarshal of the
// /nhp/internal/knock endpoint body. The endpoint is VPC-internal today,
// but if the isPrivateIP gate is ever weakened, any panic in this parser
// becomes an unauthenticated DoS — fence the parser independently.
//
// Seeds use the actual struct tags (camelCase: usrId/devId/aspId/srcIp/
// opnTime/resInfo/addr/ip), not snake_case. encoding/json's case-insensitive
// match does not bridge underscore differences, so wrong-shape seeds
// unmarshal into empty structs and the fuzzer has to rediscover the real
// keys via mutation — a much weaker base.
func FuzzHttpKnockForwardRequest(f *testing.F) {
	f.Add([]byte(`{"request":{"usrId":"u","devId":"d","aspId":"asp"},"resource":{"opnTime":300}}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`null`))
	f.Add([]byte(`{"request":null,"resource":null}`))
	f.Add([]byte(`{"source":"api","request":{},"resource":{}}`))
	f.Add([]byte(`{"source":"unexpected","request":{},"resource":{}}`))
	deep := []byte(`{"request":` + strings.Repeat(`{"dstUrl":`, 200) + `"x"` + strings.Repeat(`}`, 200) + `}`)
	f.Add(deep)
	// Mutation-pool fodder, not a faithful parse: ResourceData embeds
	// ResourceGroup with a mapstructure:",squash" tag, but encoding/json
	// doesn't honor squash, so resInfo doesn't populate the inner map
	// the way the literal suggests. The fuzzer treats it as bytes anyway.
	f.Add([]byte(`{"request":{"usrId":"u"},"resource":{"resInfo":{"a":{"acId":"x","addr":{"ip":"1.1.1.1","port":443}}}}}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		// 128KB cap mirrors NLB-fronted request size limits and keeps the
		// fuzzer focused on parser logic instead of multi-MB payloads.
		if len(data) > 128*1024 {
			return
		}
		var req HttpKnockForwardRequest
		_ = json.Unmarshal(data, &req)
		// Round-trip catches encoder panics. The wrapper's Source +
		// Request + Resource and the inner UserId / DstUrl / ResourceInfo
		// fields all round-trip; only Url, UserAgent, and Ctx on
		// common.HttpKnockRequest are json:"-" and skip the encoder.
		// Also future-proofs against new fuzzable fields.
		_, _ = json.Marshal(&req)
	})
}

// FuzzHttpKnockRequest exercises the nested HttpKnockRequest wire type in
// isolation. The internal HTTP pre-handler parses this shape before reaching
// the retired, fail-closed direct-admission terminal.
//
// Intentionally distinct from FuzzHttpKnockForwardRequest above: that
// fuzzer mutates the inner type only as a sub-tree of the wrapper, so
// the mutator's edits are constrained by the wrapper's JSON shape. This
// fuzzer mutates HttpKnockRequest bytes directly, exercising parser
// paths the wrapper-shape fuzzer can't reach.
func FuzzHttpKnockRequest(f *testing.F) {
	f.Add([]byte(`{"usrId":"u","devId":"d","srcIp":"1.2.3.4"}`))
	f.Add([]byte(`{"dstUrl":"https://example.com/x?a=b"}`))
	f.Add([]byte(`{"forwarded":true}`))
	f.Add([]byte(`{}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		// 64KB cap — the inner request type is smaller than the wrapper;
		// half the wrapper cap leaves headroom for fuzzer overhead.
		if len(data) > 64*1024 {
			return
		}
		var req common.HttpKnockRequest
		_ = json.Unmarshal(data, &req)
		// Round-trip symmetric with FuzzHttpKnockForwardRequest above —
		// catches encoder panics on UsrId / DevId / DstUrl / SrcIp /
		// other inner fields that the wrapper fuzzer only exercises as
		// a sub-tree (constrained by the wrapper's JSON shape).
		_, _ = json.Marshal(&req)
	})
}
