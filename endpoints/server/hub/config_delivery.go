package hub

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/pelletier/go-toml/v2"
)

const (
	// ContainerConfigPath is the sole config path used by the Hub container's
	// init, worker, and healthcheck commands. Runtime infrastructure overlays
	// /nhp-hub/etc with one task-scoped volume; the long-lived worker mounts it
	// read-only.
	ContainerConfigPath = "/nhp-hub/etc/hub.toml"

	PublicConfigEnv       = "NHP_HUB_PUBLIC_CONFIG_JSON"
	PrivateKeyEnv         = "NHP_HUB_PRIVATE_KEY_B64"
	ActiveCookieKeyEnv    = "NHP_HUB_ACTIVE_COOKIE_KEY_B64"
	PreviousCookieKeyEnv  = "NHP_HUB_PREVIOUS_COOKIE_KEY_B64"
	containerUID          = 65532
	containerGID          = 65532
	maxPublicConfigBytes  = 16 << 10
	privateConfigFileMode = 0o400
)

var ErrConfigMaterialization = errors.New("connector hub: config materialization failed")

// MaterializeInput is the complete one-shot init input. PublicConfigJSON is
// safe for an ordinary ECS environment entry. The three key fields must be
// supplied only to the short-lived init container through ECS secret
// references; the long-lived Hub container receives none of these values.
type MaterializeInput struct {
	PublicConfigJSON        string
	PrivateKeyBase64        string
	ActiveCookieKeyBase64   string
	PreviousCookieKeyBase64 string
}

// publicConfig is an exact required-field schema, not a bag of deployment
// defaults. Adding a future optional field requires an explicit compatibility
// decision in decodePublicConfig rather than silently accepting its zero value.
type publicConfig struct {
	Environment string `json:"environment"`

	UDPListenAddr    string `json:"udp_listen_addr"`
	HealthListenAddr string `json:"health_listen_addr"`

	AWSRegion                       string `json:"aws_region"`
	AWSAccountID                    string `json:"aws_account_id"`
	IssueAssignmentAliasARN         string `json:"issue_assignment_alias_arn"`
	RefreshAssignmentAliasARN       string `json:"refresh_assignment_alias_arn"`
	IssueCredentialRecoveryAliasARN string `json:"issue_credential_recovery_alias_arn"`

	AuthorityLambdaTimeout string `json:"authority_lambda_timeout"`
	HandlerBudget          string `json:"handler_budget"`
	PacketBudget           string `json:"packet_budget"`
	ResponseReserve        string `json:"response_reserve"`
	WriteBudget            string `json:"write_budget"`

	MaxConcurrentPackets  int `json:"max_concurrent_packets"`
	PacketsPerSecond      int `json:"packets_per_second"`
	PacketBurst           int `json:"packet_burst"`
	MaxConcurrentPerPeer  int `json:"max_concurrent_per_peer"`
	ResponseQueueCapacity int `json:"response_queue_capacity"`
}

var publicConfigKeys = map[string]struct{}{
	"environment":                         {},
	"udp_listen_addr":                     {},
	"health_listen_addr":                  {},
	"aws_region":                          {},
	"aws_account_id":                      {},
	"issue_assignment_alias_arn":          {},
	"refresh_assignment_alias_arn":        {},
	"issue_credential_recovery_alias_arn": {},
	"authority_lambda_timeout":            {},
	"handler_budget":                      {},
	"packet_budget":                       {},
	"response_reserve":                    {},
	"write_budget":                        {},
	"max_concurrent_packets":              {},
	"packets_per_second":                  {},
	"packet_burst":                        {},
	"max_concurrent_per_peer":             {},
	"response_queue_capacity":             {},
}

// MaterializeConfig validates and atomically installs a complete secret-bearing
// Hub TOML document. It never replaces an existing target, so config rotation
// requires a fresh task volume and cannot hot-rewrite a running Hub.
func MaterializeConfig(path string, input MaterializeInput) (string, error) {
	return materializeConfig(path, input, containerUID, containerGID)
}

func materializeConfig(path string, input MaterializeInput, ownerUID, ownerGID int) (string, error) {
	public, err := decodePublicConfig(input.PublicConfigJSON)
	if err != nil {
		return "", ErrInvalidConfig
	}
	config := Config{
		Environment:                     public.Environment,
		UDPListenAddr:                   public.UDPListenAddr,
		HealthListenAddr:                public.HealthListenAddr,
		PrivateKeyBase64:                input.PrivateKeyBase64,
		ActiveCookieKeyBase64:           input.ActiveCookieKeyBase64,
		PreviousCookieKeyBase64:         input.PreviousCookieKeyBase64,
		AWSRegion:                       public.AWSRegion,
		AWSAccountID:                    public.AWSAccountID,
		IssueAssignmentAliasARN:         public.IssueAssignmentAliasARN,
		RefreshAssignmentAliasARN:       public.RefreshAssignmentAliasARN,
		IssueCredentialRecoveryAliasARN: public.IssueCredentialRecoveryAliasARN,
		AuthorityLambdaTimeout:          public.AuthorityLambdaTimeout,
		HandlerBudget:                   public.HandlerBudget,
		PacketBudget:                    public.PacketBudget,
		ResponseReserve:                 public.ResponseReserve,
		WriteBudget:                     public.WriteBudget,
		MaxConcurrentPackets:            public.MaxConcurrentPackets,
		PacketsPerSecond:                public.PacketsPerSecond,
		PacketBurst:                     public.PacketBurst,
		MaxConcurrentPerPeer:            public.MaxConcurrentPerPeer,
		ResponseQueueCapacity:           public.ResponseQueueCapacity,
	}
	if _, _, _, err := config.validate(); err != nil {
		return "", ErrInvalidConfig
	}

	// The init process intentionally serializes validated secret-bearing config
	// into the private task-volume file; bytes and errors are never logged.
	data, err := toml.Marshal(config) //nolint:gosec // G117: private one-shot TOML materialization
	if err != nil || len(data) == 0 || len(data) > maxConfigBytes {
		clear(data)
		return "", ErrInvalidConfig
	}
	defer clear(data)

	digest := sha256.Sum256(data)
	if err := installPrivateConfig(path, data, ownerUID, ownerGID); err != nil {
		return "", ErrConfigMaterialization
	}
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func decodePublicConfig(raw string) (publicConfig, error) {
	if len(raw) == 0 || len(raw) > maxPublicConfigBytes {
		return publicConfig{}, ErrInvalidConfig
	}

	// Pre-scan the top-level object so duplicate keys cannot silently use
	// encoding/json's last-value-wins behavior.
	scanner := json.NewDecoder(bytes.NewBufferString(raw))
	token, err := scanner.Token()
	if err != nil || token != json.Delim('{') {
		return publicConfig{}, ErrInvalidConfig
	}
	seen := make(map[string]struct{}, len(publicConfigKeys))
	for scanner.More() {
		token, err := scanner.Token()
		key, ok := token.(string)
		if err != nil || !ok {
			return publicConfig{}, ErrInvalidConfig
		}
		if _, duplicate := seen[key]; duplicate {
			return publicConfig{}, ErrInvalidConfig
		}
		seen[key] = struct{}{}
		var value json.RawMessage
		if err := scanner.Decode(&value); err != nil {
			return publicConfig{}, ErrInvalidConfig
		}
	}
	if token, err = scanner.Token(); err != nil || token != json.Delim('}') {
		return publicConfig{}, ErrInvalidConfig
	}
	if token, err = scanner.Token(); !errors.Is(err, io.EOF) || token != nil {
		return publicConfig{}, ErrInvalidConfig
	}
	if len(seen) != len(publicConfigKeys) {
		return publicConfig{}, ErrInvalidConfig
	}
	for key := range seen {
		if _, ok := publicConfigKeys[key]; !ok {
			return publicConfig{}, ErrInvalidConfig
		}
	}

	decoder := json.NewDecoder(bytes.NewBufferString(raw))
	decoder.DisallowUnknownFields()
	var config publicConfig
	if err := decoder.Decode(&config); err != nil {
		return publicConfig{}, ErrInvalidConfig
	}
	return config, nil
}

func installPrivateConfig(path string, data []byte, ownerUID, ownerGID int) error {
	return installPrivateConfigWithLink(path, data, ownerUID, ownerGID, os.Link)
}

func installPrivateConfigWithLink(
	path string,
	data []byte,
	ownerUID, ownerGID int,
	link func(string, string) error,
) error {
	if link == nil {
		return ErrConfigMaterialization
	}
	parent := filepath.Dir(path)
	parentInfo, err := os.Lstat(parent)
	if err != nil || !parentInfo.IsDir() {
		return ErrConfigMaterialization
	}
	if _, err := os.Lstat(path); err == nil || !errors.Is(err, os.ErrNotExist) {
		return ErrConfigMaterialization
	}

	file, err := os.CreateTemp(parent, ".hub.toml.tmp-")
	if err != nil {
		return ErrConfigMaterialization
	}
	tempPath := file.Name()
	removePublishedTarget := false
	defer func() {
		_ = file.Close()
		_ = os.Remove(tempPath)
		if removePublishedTarget {
			_ = os.Remove(path)
		}
	}()

	written, err := file.Write(data)
	if err != nil || written != len(data) {
		return ErrConfigMaterialization
	}
	if err := file.Sync(); err != nil {
		return ErrConfigMaterialization
	}
	if err := file.Chmod(privateConfigFileMode); err != nil {
		return ErrConfigMaterialization
	}
	if err := file.Chown(ownerUID, ownerGID); err != nil {
		return ErrConfigMaterialization
	}
	if err := file.Close(); err != nil {
		return ErrConfigMaterialization
	}

	// A hard link publishes the already-complete inode atomically and fails if
	// any file or symlink has appeared at the target. Unlike Rename, it never
	// replaces a live config.
	if err := link(tempPath, path); err != nil {
		return ErrConfigMaterialization
	}
	removePublishedTarget = true
	if err := os.Remove(tempPath); err != nil {
		return ErrConfigMaterialization
	}
	removePublishedTarget = false
	return nil
}
