# Local E2E Tests

This directory contains end-to-end tests that run locally with automatic Docker container management.

## Purpose

These tests validate critical NHP behaviors without requiring AWS infrastructure:

- **AC Registry Preservation**: Verifies that dynamically registered ACs are not wiped when `/nhp/config` is updated
- **etcd Watch Mechanism**: Confirms the AC registry watch notifications work correctly
- **Config Parsing**: Validates TOML config parsing matches expected behavior
- **Lease Expiration**: Tests TTL-based AC deregistration

## Prerequisites

- Docker (Docker Desktop on macOS/Windows, or Docker Engine on Linux)
- Go 1.22+

## Quick Start

```bash
# From project root
make test-local

# Or directly from this directory
cd tests/local
go test -v -tags=local ./...
```

That's it! The tests use [testcontainers-go](https://golang.testcontainers.org/) to automatically:
1. Start an etcd container before tests run
2. Wait for etcd to be healthy
3. Run all tests against the container
4. Clean up the container when tests complete

## Test Descriptions

### TestACRegistry_PeerPreservation
The main test for the AC peer preservation fix. Simulates:
1. AC registers in `/nhp/ac-registry/`
2. Lambda updates `/nhp/config` (without `[[ACs]]` section)
3. Verifies AC registration is NOT wiped

### TestACRegistry_MultipleACs
Tests that multiple AC registrations survive repeated config updates.

### TestACRegistry_WatchNotification
Validates the etcd watch mechanism receives AC registration events.

### TestACRegistry_Deregistration
Tests AC removal from the registry works correctly.

### TestACRegistry_ConcurrentRegistrations
Tests multiple ACs registering simultaneously.

### TestACRegistry_InvalidEntries
Validates handling of malformed registry entries.

### TestACRegistry_ConfigUpdateDuringRegistration
Tests race conditions between config updates and AC registration.

### TestACRegistry_LeaseExpiration
Tests TTL-based automatic AC deregistration (takes ~6 seconds).

### TestConfigUpdate_ParsesCorrectly
Table-driven tests for config parsing edge cases.

## How It Works

The tests use `TestMain` in `testmain_test.go` to manage the etcd container lifecycle:

```go
func TestMain(m *testing.M) {
    // Start etcd container (testcontainers-go)
    etcdContainer, etcdEndpoint = startEtcdContainer(ctx)

    // Run all tests
    code := m.Run()

    // Cleanup
    etcdContainer.Terminate(ctx)
    os.Exit(code)
}
```

## Troubleshooting

### Docker socket not found

On macOS with Docker Desktop, the test automatically detects the Docker socket at `~/.docker/run/docker.sock`. If you have Docker configured differently, set:

```bash
export DOCKER_HOST="unix:///path/to/docker.sock"
```

### Container startup timeout

If tests fail with "context deadline exceeded", ensure Docker is running and has network access to pull the etcd image:

```bash
docker pull quay.io/coreos/etcd:v3.5.11
```

### Test timeout

The lease expiration test takes ~6 seconds. Use a longer timeout if running all tests:

```bash
go test -v -tags=local -timeout 60s ./...
```

## CI Integration

These tests run automatically in GitHub Actions. No manual docker-compose setup is required - testcontainers handles everything.

See `.github/workflows/ubuntu-build.yml` for the CI configuration.
