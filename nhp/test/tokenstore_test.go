package test

import (
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
