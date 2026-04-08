// Package integration provides tests for validating the NHP plugin system.
// These tests verify plugin deployment, S3 access, and configuration rendering.
//
// Run with: go test -v ./tests/integration/... -tags=integration
//
// Required environment variables:
// - PLUGIN_BUCKET: S3 bucket name for plugins (e.g., "layerv-nhp-sandbox-plugins")
// - AWS_REGION: AWS region
//
//go:build integration
// +build integration

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// Plugin manifest structure (matches Terraform output)
type PluginManifest struct {
	GeneratedAt    string                   `json:"generated_at"`
	Environment    string                   `json:"environment"`
	ServerPlugins  map[string]ServerPlugin  `json:"server_plugins"`
	TraefikPlugins map[string]TraefikPlugin `json:"traefik_plugins"`
}

type ServerPlugin struct {
	Version   string `json:"version"`
	BinaryKey string `json:"binary_key"`
	ConfigKey string `json:"config_key"`
}

type TraefikPlugin struct {
	Version   string  `json:"version"`
	PluginKey string  `json:"plugin_key"`
	ConfigKey *string `json:"config_key"`
}

type pluginTestConfig struct {
	bucketName string
	awsRegion  string
	s3Client   *s3.Client
}

func loadPluginTestConfig(t *testing.T) *pluginTestConfig {
	t.Helper()

	bucketName := getEnvOrSkip(t, "PLUGIN_BUCKET")
	region := getEnvOrDefault("AWS_REGION", "us-east-2")

	cfg, err := config.LoadDefaultConfig(context.Background(),
		config.WithRegion(region),
	)
	if err != nil {
		t.Fatalf("Failed to load AWS config: %v", err)
	}

	return &pluginTestConfig{
		bucketName: bucketName,
		awsRegion:  region,
		s3Client:   s3.NewFromConfig(cfg),
	}
}

func TestPlugins_BucketExists(t *testing.T) {
	cfg := loadPluginTestConfig(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := cfg.s3Client.HeadBucket(ctx, &s3.HeadBucketInput{
		Bucket: aws.String(cfg.bucketName),
	})
	if err != nil {
		t.Fatalf("Plugin bucket %s does not exist or is not accessible: %v", cfg.bucketName, err)
	}

	t.Logf("Plugin bucket %s exists and is accessible", cfg.bucketName)
}

func TestPlugins_ManifestExists(t *testing.T) {
	cfg := loadPluginTestConfig(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := cfg.s3Client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(cfg.bucketName),
		Key:    aws.String("manifest.json"),
	})
	if err != nil {
		t.Fatalf("Failed to get manifest.json: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read manifest.json: %v", err)
	}

	var manifest PluginManifest
	if err := json.Unmarshal(body, &manifest); err != nil {
		t.Fatalf("Failed to parse manifest.json: %v", err)
	}

	t.Logf("Manifest found: environment=%s, generated_at=%s", manifest.Environment, manifest.GeneratedAt)
	t.Logf("Server plugins: %d, Traefik plugins: %d", len(manifest.ServerPlugins), len(manifest.TraefikPlugins))

	// Store manifest for other tests
	t.Setenv("_MANIFEST", string(body))
}

func TestPlugins_ServerPluginBinariesExist(t *testing.T) {
	cfg := loadPluginTestConfig(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Get manifest
	manifest := getManifest(t, cfg)

	for name, plugin := range manifest.ServerPlugins {
		t.Run(name, func(t *testing.T) {
			// Check binary exists
			_, err := cfg.s3Client.HeadObject(ctx, &s3.HeadObjectInput{
				Bucket: aws.String(cfg.bucketName),
				Key:    aws.String(plugin.BinaryKey),
			})
			if err != nil {
				t.Errorf("Plugin binary not found: s3://%s/%s: %v", cfg.bucketName, plugin.BinaryKey, err)
				return
			}

			t.Logf("Plugin %s binary exists: %s (version: %s)", name, plugin.BinaryKey, plugin.Version)
		})
	}
}

func TestPlugins_ServerPluginConfigsExist(t *testing.T) {
	cfg := loadPluginTestConfig(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	manifest := getManifest(t, cfg)

	for name, plugin := range manifest.ServerPlugins {
		t.Run(name, func(t *testing.T) {
			// Check config exists
			resp, err := cfg.s3Client.GetObject(ctx, &s3.GetObjectInput{
				Bucket: aws.String(cfg.bucketName),
				Key:    aws.String(plugin.ConfigKey),
			})
			if err != nil {
				t.Errorf("Plugin config not found: s3://%s/%s: %v", cfg.bucketName, plugin.ConfigKey, err)
				return
			}
			defer resp.Body.Close()

			body, _ := io.ReadAll(resp.Body)
			lines := strings.Split(string(body), "\n")

			t.Logf("Plugin %s config exists: %s (%d lines)", name, plugin.ConfigKey, len(lines))

			// Validate it looks like TOML
			if len(lines) < 3 {
				t.Errorf("Config file seems too short (%d lines)", len(lines))
			}
			if !strings.HasPrefix(lines[0], "#") {
				t.Error("Config file should start with a comment")
			}
		})
	}
}

func TestPlugins_TraefikPluginsExist(t *testing.T) {
	cfg := loadPluginTestConfig(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	manifest := getManifest(t, cfg)

	for name, plugin := range manifest.TraefikPlugins {
		t.Run(name, func(t *testing.T) {
			// List objects in plugin directory
			prefix := plugin.PluginKey
			resp, err := cfg.s3Client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
				Bucket: aws.String(cfg.bucketName),
				Prefix: aws.String(prefix),
			})
			if err != nil {
				t.Errorf("Failed to list plugin files: %v", err)
				return
			}

			if len(resp.Contents) == 0 {
				t.Errorf("No files found in plugin directory: s3://%s/%s", cfg.bucketName, prefix)
				return
			}

			// Check for required Traefik plugin files
			var hasTraefikYml, hasGoMod bool
			for _, obj := range resp.Contents {
				key := *obj.Key
				if strings.HasSuffix(key, ".traefik.yml") {
					hasTraefikYml = true
				}
				if strings.HasSuffix(key, "go.mod") {
					hasGoMod = true
				}
			}

			if !hasTraefikYml {
				t.Error("Missing .traefik.yml manifest file")
			}
			if !hasGoMod {
				t.Error("Missing go.mod file")
			}

			t.Logf("Plugin %s has %d files (version: %s)", name, len(resp.Contents), plugin.Version)
		})
	}
}

func TestPlugins_BucketStructure(t *testing.T) {
	cfg := loadPluginTestConfig(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Expected top-level prefixes
	expectedPrefixes := []string{"nhp-server/", "traefik/", "configs/"}

	for _, prefix := range expectedPrefixes {
		t.Run(prefix, func(t *testing.T) {
			resp, err := cfg.s3Client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
				Bucket:  aws.String(cfg.bucketName),
				Prefix:  aws.String(prefix),
				MaxKeys: aws.Int32(1),
			})
			if err != nil {
				t.Errorf("Failed to list %s: %v", prefix, err)
				return
			}

			if len(resp.Contents) == 0 && (resp.CommonPrefixes == nil || len(resp.CommonPrefixes) == 0) {
				t.Logf("Warning: No objects found under %s (may be expected if no plugins configured)", prefix)
			} else {
				t.Logf("Prefix %s exists", prefix)
			}
		})
	}
}

// Helper functions

func getManifest(t *testing.T, cfg *pluginTestConfig) PluginManifest {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := cfg.s3Client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(cfg.bucketName),
		Key:    aws.String("manifest.json"),
	})
	if err != nil {
		t.Fatalf("Failed to get manifest.json: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read manifest.json: %v", err)
	}

	var manifest PluginManifest
	if err := json.Unmarshal(body, &manifest); err != nil {
		t.Fatalf("Failed to parse manifest.json: %v", err)
	}

	return manifest
}

func getEnvOrSkip(t *testing.T, key string) string {
	t.Helper()
	value := getEnvOrDefault(key, "")
	if value == "" {
		t.Skipf("%s not set, skipping plugin tests", key)
	}
	return value
}

func getEnvOrDefault(key, defaultValue string) string {
	if value := lookupEnv(key); value != "" {
		return value
	}
	return defaultValue
}

func lookupEnv(key string) string {
	return os.Getenv(key)
}

// TestPlugins_Summary prints a summary of the plugin configuration
func TestPlugins_Summary(t *testing.T) {
	cfg := loadPluginTestConfig(t)
	manifest := getManifest(t, cfg)

	fmt.Println("\n=== Plugin System Validation Summary ===")
	fmt.Printf("Bucket:      %s\n", cfg.bucketName)
	fmt.Printf("Region:      %s\n", cfg.awsRegion)
	fmt.Printf("Environment: %s\n", manifest.Environment)
	fmt.Println("\nServer Plugins:")
	for name, plugin := range manifest.ServerPlugins {
		fmt.Printf("  - %s (version: %s)\n", name, plugin.Version)
	}
	fmt.Println("\nTraefik Plugins:")
	for name, plugin := range manifest.TraefikPlugins {
		fmt.Printf("  - %s (version: %s)\n", name, plugin.Version)
	}
	fmt.Println("==========================================")
}
