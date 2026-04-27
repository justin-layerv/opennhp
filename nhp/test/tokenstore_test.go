package test

import (
	"encoding/base64"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/OpenNHP/opennhp/nhp/common"
)

// testEntry is a simple implementation of common.TokenEntry for testing.
type testEntry struct {
	value      string
	expireTime time.Time
}

func (e *testEntry) GetExpireTime() time.Time {
	return e.expireTime
}

func TestTokenStore_StoreAndLoad(t *testing.T) {
	ts := common.NewTokenStore[*testEntry]()

	entry := &testEntry{value: "test-value", expireTime: time.Now().Add(1 * time.Hour)}
	token := "abcd1234token"

	ts.Store(token, entry)

	loaded, found := ts.Load(token)
	if !found {
		t.Fatal("expected to find stored token")
	}
	if loaded.value != "test-value" {
		t.Errorf("expected value 'test-value', got '%s'", loaded.value)
	}
}

func TestTokenStore_LoadNotFound(t *testing.T) {
	ts := common.NewTokenStore[*testEntry]()

	_, found := ts.Load("nonexistent")
	if found {
		t.Error("expected not to find nonexistent token")
	}
}

func TestTokenStore_Delete(t *testing.T) {
	ts := common.NewTokenStore[*testEntry]()

	entry := &testEntry{value: "test", expireTime: time.Now().Add(1 * time.Hour)}
	token := "token-to-delete"

	ts.Store(token, entry)
	ts.Delete(token)

	_, found := ts.Load(token)
	if found {
		t.Error("expected token to be deleted")
	}
}

func TestTokenStore_CleanExpired(t *testing.T) {
	ts := common.NewTokenStore[*testEntry]()

	// Add an expired entry
	expiredEntry := &testEntry{value: "expired", expireTime: time.Now().Add(-1 * time.Hour)}
	ts.Store("expired-token", expiredEntry)

	// Add a valid entry
	validEntry := &testEntry{value: "valid", expireTime: time.Now().Add(1 * time.Hour)}
	ts.Store("valid-token", validEntry)

	if ts.Size() != 2 {
		t.Errorf("expected size 2, got %d", ts.Size())
	}

	removed := ts.CleanExpired()
	if removed != 1 {
		t.Errorf("expected 1 removed, got %d", removed)
	}

	if ts.Size() != 1 {
		t.Errorf("expected size 1 after cleanup, got %d", ts.Size())
	}

	// Verify expired token is gone
	_, found := ts.Load("expired-token")
	if found {
		t.Error("expected expired token to be removed")
	}

	// Verify valid token still exists
	_, found = ts.Load("valid-token")
	if !found {
		t.Error("expected valid token to still exist")
	}
}

func TestTokenStore_Size(t *testing.T) {
	ts := common.NewTokenStore[*testEntry]()

	if ts.Size() != 0 {
		t.Errorf("expected empty store to have size 0, got %d", ts.Size())
	}

	for i := 0; i < 100; i++ {
		token := string(rune('A'+i%26)) + "token" + string(rune('0'+i%10))
		entry := &testEntry{value: token, expireTime: time.Now().Add(1 * time.Hour)}
		ts.Store(token, entry)
	}

	if ts.Size() != 100 {
		t.Errorf("expected size 100, got %d", ts.Size())
	}
}

func TestTokenStore_ConcurrentAccess(t *testing.T) {
	ts := common.NewTokenStore[*testEntry]()
	var wg sync.WaitGroup

	// Concurrent writes
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			token := string(rune('A'+n%26)) + "concurrent" + string(rune('0'+n%10))
			entry := &testEntry{value: token, expireTime: time.Now().Add(1 * time.Hour)}
			ts.Store(token, entry)
		}(i)
	}
	wg.Wait()

	// Concurrent reads
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			token := string(rune('A'+n%26)) + "concurrent" + string(rune('0'+n%10))
			ts.Load(token)
		}(i)
	}
	wg.Wait()

	// Concurrent deletes
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			token := string(rune('A'+n%26)) + "concurrent" + string(rune('0'+n%10))
			ts.Delete(token)
		}(i)
	}
	wg.Wait()
}

func TestTokenStore_EmptyToken(t *testing.T) {
	ts := common.NewTokenStore[*testEntry]()

	// Store with empty token should be silently ignored
	entry := &testEntry{value: "test", expireTime: time.Now().Add(1 * time.Hour)}
	ts.Store("", entry)

	if ts.Size() != 0 {
		t.Errorf("expected size 0 after storing empty token, got %d", ts.Size())
	}

	// Load with empty token should return not found
	_, found := ts.Load("")
	if found {
		t.Error("expected empty token load to return not found")
	}

	// Delete with empty token should not panic
	ts.Delete("") // Should not panic
}

func TestTokenStore_TwoLevelIndexing(t *testing.T) {
	ts := common.NewTokenStore[*testEntry]()

	// Store tokens with different first characters
	tokens := []string{"Atoken1", "Btoken2", "Atoken3", "Ctoken4", "Atoken5"}
	for _, token := range tokens {
		entry := &testEntry{value: token, expireTime: time.Now().Add(1 * time.Hour)}
		ts.Store(token, entry)
	}

	// All should be loadable
	for _, token := range tokens {
		loaded, found := ts.Load(token)
		if !found {
			t.Errorf("expected to find token '%s'", token)
		}
		if loaded.value != token {
			t.Errorf("expected value '%s', got '%s'", token, loaded.value)
		}
	}

	// Delete one and verify others still exist
	ts.Delete("Atoken3")
	_, found := ts.Load("Atoken3")
	if found {
		t.Error("expected Atoken3 to be deleted")
	}

	// Other 'A' tokens should still exist
	_, found = ts.Load("Atoken1")
	if !found {
		t.Error("expected Atoken1 to still exist")
	}
	_, found = ts.Load("Atoken5")
	if !found {
		t.Error("expected Atoken5 to still exist")
	}
}

// TestGenerateOpaqueToken_Shape pins the wire-compatible shape consumers
// depend on: 44 ASCII chars, base64-StdEncoding charset with trailing '='.
// Regression fence for nhp#1124 (replace SHA-256-over-public-inputs with
// crypto/rand) — if shape ever changes, downstream regex/fixed-length
// validators (qurl-service, traefik-plugins, agent SDKs) will silently
// reject tokens.
func TestGenerateOpaqueToken_Shape(t *testing.T) {
	const expectedLen = 44 // 32 bytes base64-StdEncoding-encoded
	for i := 0; i < 1000; i++ {
		token := common.GenerateOpaqueToken()
		if len(token) != expectedLen {
			t.Fatalf("token %d: len=%d, want %d (token=%q)", i, len(token), expectedLen, token)
		}
		if token[expectedLen-1] != '=' {
			t.Fatalf("token %d: missing base64 padding (token=%q)", i, token)
		}
		for _, c := range token[:expectedLen-1] {
			ok := (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
				(c >= '0' && c <= '9') || c == '+' || c == '/'
			if !ok {
				t.Fatalf("token %d: invalid base64 char %q (token=%q)", i, c, token)
			}
		}
	}
}

// TestGenerateOpaqueToken_NeverEmpty pins the panic-vs-empty contract:
// GenerateOpaqueToken's response to crypto/rand failure is to panic, not
// to return empty. A regression that swapped the panic for `return ""`
// would silently hand out the empty token; TokenStore.Store ignores
// empty tokens (so no entry is recorded), but a downstream consumer
// that compared against the issued empty value would gain valid access
// to nothing — confusing, and ripe for follow-on bugs. Pin the
// non-empty postcondition explicitly.
func TestGenerateOpaqueToken_NeverEmpty(t *testing.T) {
	for i := 0; i < 1000; i++ {
		if got := common.GenerateOpaqueToken(); got == "" {
			t.Fatalf("token %d was empty", i)
		}
	}
}

// TestGenerateOpaqueToken_NoCollisions asserts uniqueness across a large
// batch — birthday probability for 32-byte values is ~10⁻⁶⁰, so any
// collision indicates a regression to a low-entropy construction.
func TestGenerateOpaqueToken_NoCollisions(t *testing.T) {
	const n = 10_000
	seen := make(map[string]struct{}, n)
	for i := 0; i < n; i++ {
		token := common.GenerateOpaqueToken()
		if _, dup := seen[token]; dup {
			t.Fatalf("collision after %d tokens: %q", i, token)
		}
		seen[token] = struct{}{}
	}
}

// TestGenerateOpaqueToken_ByteEntropy decodes a large batch and asserts every
// byte value 0x00–0xFF appears at least once. A regression to a hashed-
// metadata construction with low timestamp variance would skew the
// distribution; this is a coarse but cheap canary that catches the obvious
// failure modes without pulling in a NIST-style suite. 10_000 tokens × 32
// bytes = 320KB, so each of 256 byte values is expected ~1250 times by
// chance — missing any value is a strong signal of non-randomness.
func TestGenerateOpaqueToken_ByteEntropy(t *testing.T) {
	const n = 10_000
	var seen [256]bool
	for i := 0; i < n; i++ {
		// EncodeToString output always round-trips through DecodeString
		// without error; the err check is defense-in-depth against a
		// future refactor that switches the encoding.
		raw, err := base64.StdEncoding.DecodeString(common.GenerateOpaqueToken())
		if err != nil {
			t.Fatalf("decode failed: %v", err)
		}
		for _, b := range raw {
			seen[b] = true
		}
	}
	for v, ok := range seen {
		if !ok {
			t.Fatalf("byte value 0x%02x never appeared in %d tokens — entropy regressed", v, n)
		}
	}
}

// TestGenerateOpaqueToken_ConcurrentNoCollisions fences a future change
// that accidentally introduces shared state in the generation path (a
// per-process counter, a token-formatter pool). Today the primitive is
// stateless, so this is belt-and-suspenders.
//
// Concurrency pattern: each goroutine writes to its own pre-sized slot
// in `results`, never appending to a shared slice. A future change that
// switches to `append` on a shared `[]string` would be a data race; if
// you refactor this test, preserve the fixed-slot write pattern.
func TestGenerateOpaqueToken_ConcurrentNoCollisions(t *testing.T) {
	const goroutines = 16
	const tokensPerGoroutine = 1000

	results := make([][]string, goroutines)
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			batch := make([]string, tokensPerGoroutine)
			for i := 0; i < tokensPerGoroutine; i++ {
				batch[i] = common.GenerateOpaqueToken()
			}
			results[idx] = batch
		}(g)
	}
	wg.Wait()

	seen := make(map[string]int, goroutines*tokensPerGoroutine)
	for g, batch := range results {
		for i, token := range batch {
			if prev, dup := seen[token]; dup {
				t.Fatalf("collision: goroutine=%d index=%d token=%q (also seen at flat index %d)",
					g, i, token, prev)
			}
			seen[token] = g*tokensPerGoroutine + i
		}
	}
}

// TestRedactToken pins the log-redaction contract: a real 44-char access
// token must keep its leading 8 chars and lose the rest, and pathologically
// short inputs must not be re-formatted (they will fail the wire-shape
// check downstream regardless). This is what stops a future caller from
// re-introducing full-token logging via copy-paste from a pre-1124 code
// path that treated the token as derivable-from-public-inputs.
//
// SECURITY: the "abcdefgh..." cases below also fence the value of
// common.tokenLogPrefixLen — bumping it (e.g. to 16) would silently
// reveal more token entropy in logs and require a new threat-model
// review. The doc comment on tokenLogPrefixLen quantifies the bits
// revealed at 8 chars; if you change either, change both.
func TestRedactToken(t *testing.T) {
	cases := []struct {
		name  string
		token string
		want  string
	}{
		{"empty", "", ""},
		{"short_kept_verbatim", "abc", "abc"},
		{"exactly_prefix_len_kept_verbatim", "abcdefgh", "abcdefgh"},
		{"truncated", "abcdefghij", "abcdefgh..."},
		{"full_44char_token", "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH", "abcdefgh..."},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := common.RedactToken(tc.token); got != tc.want {
				t.Fatalf("RedactToken(%q) = %q, want %q", tc.token, got, tc.want)
			}
		})
	}
}

// --- Benchmarks for performance profiling and regression detection ---

const benchKeySpace = 1000

func BenchmarkTokenStore_Store(b *testing.B) {
	ts := common.NewTokenStore[*testEntry]()
	entry := &testEntry{value: "test", expireTime: time.Now().Add(time.Hour)}
	tokens := make([]string, benchKeySpace)
	for i := range tokens {
		tokens[i] = fmt.Sprintf("token-%d", i)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ts.Store(tokens[i%benchKeySpace], entry)
	}
}

func BenchmarkTokenStore_Load(b *testing.B) {
	ts := common.NewTokenStore[*testEntry]()
	tokens := make([]string, benchKeySpace)
	for i := range tokens {
		tokens[i] = fmt.Sprintf("token-%d", i)
		ts.Store(tokens[i], &testEntry{value: "test", expireTime: time.Now().Add(time.Hour)})
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ts.Load(tokens[i%benchKeySpace])
	}
}

func BenchmarkTokenStore_Size(b *testing.B) {
	ts := common.NewTokenStore[*testEntry]()
	for i := 0; i < benchKeySpace; i++ {
		ts.Store(fmt.Sprintf("token-%d", i), &testEntry{value: "test", expireTime: time.Now().Add(time.Hour)})
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ts.Size()
	}
}

// BenchmarkTokenStore_ConcurrentAccess measures throughput under concurrent Store/Load/Delete.
// Goroutines intentionally share the same key space to stress-test lock contention.
func BenchmarkTokenStore_ConcurrentAccess(b *testing.B) {
	ts := common.NewTokenStore[*testEntry]()
	entry := &testEntry{value: "test", expireTime: time.Now().Add(time.Hour)}
	tokens := make([]string, benchKeySpace)
	for i := range tokens {
		tokens[i] = fmt.Sprintf("token-%d", i)
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			token := tokens[i%benchKeySpace]
			switch i % 3 {
			case 0:
				ts.Store(token, entry)
			case 1:
				ts.Load(token)
			case 2:
				ts.Delete(token)
			}
			i++
		}
	})
}
