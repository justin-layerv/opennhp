//go:build local

package local

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

var (
	etcdContainer testcontainers.Container
	etcdEndpoint  string
)

// TestMain manages the etcd container lifecycle for all tests
func TestMain(m *testing.M) {
	// Configure Docker host for macOS if not already set
	if os.Getenv("DOCKER_HOST") == "" && runtime.GOOS == "darwin" {
		// Docker Desktop on macOS uses a socket in ~/.docker/run/
		homeDir, err := os.UserHomeDir()
		if err == nil {
			macOSSocket := filepath.Join(homeDir, ".docker", "run", "docker.sock")
			if _, err := os.Stat(macOSSocket); err == nil {
				os.Setenv("DOCKER_HOST", "unix://"+macOSSocket)
			}
		}
	}

	ctx := context.Background()

	// Start etcd container
	var err error
	etcdContainer, etcdEndpoint, err = startEtcdContainer(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to start etcd container: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "etcd started at %s\n", etcdEndpoint)

	// Run tests
	code := m.Run()

	// Cleanup
	if etcdContainer != nil {
		if err := etcdContainer.Terminate(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to terminate etcd container: %v\n", err)
		}
	}

	os.Exit(code)
}

func startEtcdContainer(ctx context.Context) (testcontainers.Container, string, error) {
	req := testcontainers.ContainerRequest{
		Image:        "quay.io/coreos/etcd:v3.5.11",
		ExposedPorts: []string{"2379/tcp"},
		Cmd: []string{
			"etcd",
			"--name=etcd0",
			"--advertise-client-urls=http://0.0.0.0:2379",
			"--listen-client-urls=http://0.0.0.0:2379",
			"--initial-advertise-peer-urls=http://0.0.0.0:2380",
			"--listen-peer-urls=http://0.0.0.0:2380",
			"--initial-cluster=etcd0=http://0.0.0.0:2380",
			"--log-level=warn",
		},
		// Use HTTP health check - more reliable than log parsing
		WaitingFor: wait.ForHTTP("/health").
			WithPort("2379/tcp").
			WithStartupTimeout(30 * time.Second),
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		return nil, "", fmt.Errorf("failed to start etcd container: %w", err)
	}

	// Get the mapped port
	host, err := container.Host(ctx)
	if err != nil {
		container.Terminate(ctx)
		return nil, "", fmt.Errorf("failed to get container host: %w", err)
	}

	mappedPort, err := container.MappedPort(ctx, "2379")
	if err != nil {
		container.Terminate(ctx)
		return nil, "", fmt.Errorf("failed to get mapped port: %w", err)
	}

	endpoint := fmt.Sprintf("http://%s:%s", host, mappedPort.Port())
	return container, endpoint, nil
}
