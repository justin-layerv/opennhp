package hub

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func validPublicConfigJSON(t *testing.T, config Config) string {
	t.Helper()
	data, err := json.Marshal(publicConfig{
		Environment:                     config.Environment,
		UDPListenAddr:                   config.UDPListenAddr,
		HealthListenAddr:                config.HealthListenAddr,
		AWSRegion:                       config.AWSRegion,
		AWSAccountID:                    config.AWSAccountID,
		IssueAssignmentAliasARN:         config.IssueAssignmentAliasARN,
		RefreshAssignmentAliasARN:       config.RefreshAssignmentAliasARN,
		IssueCredentialRecoveryAliasARN: config.IssueCredentialRecoveryAliasARN,
		AuthorityLambdaTimeout:          config.AuthorityLambdaTimeout,
		HandlerBudget:                   config.HandlerBudget,
		PacketBudget:                    config.PacketBudget,
		ResponseReserve:                 config.ResponseReserve,
		WriteBudget:                     config.WriteBudget,
		MaxConcurrentPackets:            config.MaxConcurrentPackets,
		PacketsPerSecond:                config.PacketsPerSecond,
		PacketBurst:                     config.PacketBurst,
		MaxConcurrentPerPeer:            config.MaxConcurrentPerPeer,
		ResponseQueueCapacity:           config.ResponseQueueCapacity,
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func validMaterializeInput(t *testing.T, config Config) MaterializeInput {
	t.Helper()
	return MaterializeInput{
		PublicConfigJSON:        validPublicConfigJSON(t, config),
		PrivateKeyBase64:        config.PrivateKeyBase64,
		ActiveCookieKeyBase64:   config.ActiveCookieKeyBase64,
		PreviousCookieKeyBase64: config.PreviousCookieKeyBase64,
	}
}

func TestMaterializeConfigWritesOnePrivateAtomicRoundTrip(t *testing.T) {
	config := validConfig()
	directory := t.TempDir()
	path := filepath.Join(directory, "hub.toml")

	digest, err := materializeConfig(
		path,
		validMaterializeInput(t, config),
		os.Geteuid(),
		os.Getegid(),
	)
	if err != nil {
		t.Fatalf("materializeConfig: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	wantDigest := sha256.Sum256(data)
	if want := "sha256:" + hex.EncodeToString(wantDigest[:]); digest != want {
		t.Fatalf("digest = %q, want %q", digest, want)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != privateConfigFileMode {
		t.Fatalf("config mode = %04o, want %04o", got, privateConfigFileMode)
	}
	assertTestFileOwner(t, info, os.Geteuid(), os.Getegid())

	got, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig(materialized): %v", err)
	}
	if got != config {
		t.Fatal("materialized configuration did not round-trip exactly")
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "hub.toml" {
		t.Fatalf("materialization left unexpected files: %v", entries)
	}
}

func TestMaterializeConfigIsDeterministic(t *testing.T) {
	input := validMaterializeInput(t, validConfig())
	var first []byte
	var firstDigest string
	for iteration := 0; iteration < 2; iteration++ {
		path := filepath.Join(t.TempDir(), "hub.toml")
		digest, err := materializeConfig(path, input, os.Geteuid(), os.Getegid())
		if err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if iteration == 0 {
			first = data
			firstDigest = digest
			continue
		}
		if string(data) != string(first) || digest != firstDigest {
			t.Fatal("identical init inputs produced different config bytes or digest")
		}
	}
}

func TestMaterializeConfigAcceptsNoPreviousCookieKey(t *testing.T) {
	config := validConfig()
	config.PreviousCookieKeyBase64 = ""
	path := filepath.Join(t.TempDir(), "hub.toml")
	if _, err := materializeConfig(
		path,
		validMaterializeInput(t, config),
		os.Geteuid(),
		os.Getegid(),
	); err != nil {
		t.Fatalf("materializeConfig without previous key: %v", err)
	}
	got, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.PreviousCookieKeyBase64 != "" {
		t.Fatal("materialized config invented a previous cookie key")
	}
}

func TestDecodePublicConfigRequiresExactObject(t *testing.T) {
	valid := validPublicConfigJSON(t, validConfig())
	var object map[string]any
	if err := json.Unmarshal([]byte(valid), &object); err != nil {
		t.Fatal(err)
	}

	withoutEnvironment := cloneJSONMap(object)
	delete(withoutEnvironment, "environment")
	withUnknown := cloneJSONMap(object)
	withUnknown["private_key"] = "must-not-enter-public-config"
	wrongType := cloneJSONMap(object)
	wrongType["packet_burst"] = "4"

	tests := map[string]string{
		"missing":    marshalJSON(t, withoutEnvironment),
		"unknown":    marshalJSON(t, withUnknown),
		"wrong type": marshalJSON(t, wrongType),
		"duplicate":  strings.Replace(valid, `"environment":"sandbox"`, `"environment":"sandbox","environment":"prod"`, 1),
		"trailing":   valid + `{}`,
		"array":      `[]`,
		"empty":      ``,
		"oversized":  strings.Repeat("x", maxPublicConfigBytes+1),
		"malformed":  `{"environment":`,
		"non-object": `"sandbox"`,
	}
	for name, document := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := decodePublicConfig(document); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("decodePublicConfig error = %v, want ErrInvalidConfig", err)
			}
		})
	}
}

func TestMaterializeConfigNeverReplacesExistingTarget(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "hub.toml")
	original := []byte("existing-config")
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := materializeConfig(
		path,
		validMaterializeInput(t, validConfig()),
		os.Geteuid(),
		os.Getegid(),
	); !errors.Is(err, ErrConfigMaterialization) {
		t.Fatalf("materializeConfig existing target error = %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(original) {
		t.Fatal("materialization replaced an existing target")
	}
}

func TestMaterializeConfigRejectsSymlinkTarget(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target")
	path := filepath.Join(directory, "hub.toml")
	if err := os.WriteFile(target, []byte("do-not-replace"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}

	if _, err := materializeConfig(
		path,
		validMaterializeInput(t, validConfig()),
		os.Geteuid(),
		os.Getegid(),
	); !errors.Is(err, ErrConfigMaterialization) {
		t.Fatalf("materializeConfig symlink error = %v", err)
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "do-not-replace" {
		t.Fatal("materialization followed or replaced a symlink")
	}
}

func TestInstallPrivateConfigPreservesTargetThatWinsPublishRace(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "hub.toml")
	winner := []byte("concurrent-winner")

	err := installPrivateConfigWithLink(
		path,
		[]byte("candidate"),
		os.Geteuid(),
		os.Getegid(),
		func(_, target string) error {
			if err := os.WriteFile(target, winner, 0o600); err != nil {
				t.Fatal(err)
			}
			return os.ErrExist
		},
	)
	if !errors.Is(err, ErrConfigMaterialization) {
		t.Fatalf("installPrivateConfigWithLink error = %v, want ErrConfigMaterialization", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(winner) {
		t.Fatal("failed publish removed or replaced the concurrent winner")
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "hub.toml" {
		t.Fatalf("failed publish left unexpected files: %v", entries)
	}
}

func TestMaterializeConfigFailureLeavesNoFileOrSecretInError(t *testing.T) {
	secret := "do-not-echo-this-key"
	input := validMaterializeInput(t, validConfig())
	input.PrivateKeyBase64 = secret
	directory := t.TempDir()
	path := filepath.Join(directory, "hub.toml")

	_, err := materializeConfig(path, input, os.Geteuid(), os.Getegid())
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("materializeConfig error = %v, want ErrInvalidConfig", err)
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatal("materializeConfig error exposed key material")
	}
	if _, statErr := os.Lstat(path); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("failed materialization left target: %v", statErr)
	}
	entries, readErr := os.ReadDir(directory)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if len(entries) != 0 {
		t.Fatalf("failed materialization left temporary files: %v", entries)
	}
}

func cloneJSONMap(input map[string]any) map[string]any {
	result := make(map[string]any, len(input))
	for key, value := range input {
		result[key] = value
	}
	return result
}

func marshalJSON(t *testing.T, value any) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
