# NHP Testing Guide

This document describes the test structure, how to run tests, and how to add new tests to the NHP codebase.

## Test Categories

NHP has three levels of testing:

| Level | Location | Build Tag | Dependencies | CI |
|-------|----------|-----------|--------------|-----|
| **Unit Tests** | `endpoints/server/*_test.go` | none | none | Yes |
| **#2214 fence** | `*/tokenstore_debug_test.go` | `nhp_debug` | none | Yes — see build-and-push.yml; `make test-debug` is the local reproducer |
| **Local E2E** | `tests/local/*_test.go` | `local` | Docker (etcd) | Yes |
| **Integration** | `tests/integration/*_test.go` | `integration` | AWS infra | Manual |
| **E2E** | `tests/e2e/*_test.go` | `e2e` | Live deployment | Manual |

> The `nhp_debug` build tag activates `common.TokenStore.Store`'s
> pointer-uniqueness assertion (#2214). Production builds use the
> no-op variant (`nhp/common/tokenstore_debug_off.go`) and pay zero
> cost. The CI fence runs on every PR via the "Debug-tag
> pointer-uniqueness assertion" step in
> `.github/workflows/build-and-push.yml`; locally, `make test-debug`
> reproduces it. See `nhp/common/tokenstore_debug_on.go` for the
> rationale and `endpoints/ac/tokenstore.go`'s `AccessEntry` godoc
> for the pointer-identity invariant the fence protects.
>
> Note: `make test-debug` exercises `endpoints/ac/...` alongside the
> common-package tests. Some AC tests independently require iptables /
> ipset (CI runs inside a privileged Docker container where these are
> pre-installed); a host without them may see unrelated AC test
> failures. The fence-specific tests themselves
> (`*_debug_test.go`) have no such dependency.

## Running Tests

### Unit Tests

Unit tests run without external dependencies:

```bash
# Run all unit tests
make test

# Run specific test
cd endpoints && KBS_SKIP_INIT=1 go test -v ./server/... -run TestACRegistry
```

### Local E2E Tests

Local E2E tests use testcontainers-go to automatically manage Docker containers:

```bash
# Run tests (etcd container is automatically started/stopped)
make test-local

# Or directly:
cd tests/local && go test -v -tags=local ./...
```

The tests automatically:
1. Start an etcd container before tests run
2. Wait for etcd to be healthy
3. Run all tests against the container
4. Clean up the container when tests complete

Prerequisites: Docker must be running.

### Integration Tests

Integration tests run against deployed AWS infrastructure:

```bash
# Set required environment variables
export ETCD_ENDPOINTS="https://etcd.example.com:2379"
export ETCD_CA_CERT=/path/to/ca.crt
export ETCD_CLIENT_CERT=/path/to/client.crt
export ETCD_CLIENT_KEY=/path/to/client.key
export NHP_SERVER_ENDPOINT="nlb.example.com:62206"
export AWS_REGION=us-east-2

# Run tests
cd tests/integration && go test -v -tags=integration ./...
```

### Full E2E Tests

E2E tests run against live deployments (qurl.link, etc.):

```bash
# Optional: configure custom endpoints
export CONSOLE_API_URL="https://home.secure.layerv.xyz"
export LOGIN_PORTAL_DOMAIN="qurl.link"
export APPS_DOMAIN="qurl.site"

# Run tests
cd tests/e2e && go test -v -tags=e2e ./...
```

## Test Structure

```
nhp/
├── endpoints/
│   └── server/
│       ├── config_test.go         # AC registry parsing tests
│       ├── etcd_config_test.go    # etcd config & AC peer preservation tests
│       └── plugin_loading_test.go # Plugin loading tests
├── nhp/
│   ├── core/
│   │   └── *_test.go              # Core crypto/device tests
│   ├── etcd/
│   │   └── etcd_test.go           # etcd client tests
│   └── test/
│       └── *_test.go              # Packet/connection tests
└── tests/
    ├── local/                     # Docker-based local e2e
    │   ├── docker-compose.test.yaml
    │   ├── ac_registry_test.go
    │   └── README.md
    ├── integration/               # AWS infrastructure tests
    │   ├── deployment_test.go
    │   └── plugins_test.go
    └── e2e/                       # Live deployment tests
        └── demo_flow_test.go
```

## Adding New Tests

### Adding Unit Tests

1. Create or edit `*_test.go` in the appropriate package
2. Use standard Go testing patterns
3. Use `KBS_SKIP_INIT=1` env var to skip KBS initialization in tests

```go
func TestMyFeature(t *testing.T) {
    // Arrange
    server := &UdpServer{...}

    // Act
    result := server.MyMethod()

    // Assert
    if result != expected {
        t.Errorf("got %v, want %v", result, expected)
    }
}
```

### Adding Local E2E Tests

1. Add tests to `tests/local/ac_registry_test.go` or create new file
2. Use the `//go:build local` build tag
3. Use `createTestEtcdClient(t)` helper for etcd access

```go
//go:build local

func TestMyE2EScenario(t *testing.T) {
    client := createTestEtcdClient(t)
    defer client.Close()

    ctx := context.Background()

    // Test your scenario...
}
```

### Adding Integration Tests

1. Add tests to `tests/integration/`
2. Use the `//go:build integration` build tag
3. Use `loadTestConfig(t)` to get environment configuration

### Test Naming Conventions

- Use descriptive names: `TestACRegistry_PeerPreservation`
- Use subtests for table-driven tests: `t.Run("scenario", func(t *testing.T) {...})`
- Prefix with component: `TestEtcd_`, `TestACRegistry_`, `TestConfig_`

## CI/CD Integration

Tests are automatically run in GitHub Actions:

1. **Unit Tests**: Run on every push/PR to `main`
2. **Local E2E Tests**: Run after build succeeds (uses Docker etcd)
3. **Integration/E2E Tests**: Manual trigger (require credentials)

See `.github/workflows/ubuntu-build.yml` for the CI configuration.

## Debugging Failed Tests

### View test output

```bash
go test -v ./... 2>&1 | tee test.log
```

### Run single test with verbose logging

```bash
go test -v -run TestACRegistry_PeerPreservation ./...
```

### Check etcd state during local tests

```bash
# While etcd is running
docker exec nhp-test-etcd etcdctl get --prefix /nhp/
```

## Common Issues

### KBS_SKIP_INIT panic

If you see `panic: fail to create private key directory`:
```bash
KBS_SKIP_INIT=1 go test ./...
```

### etcd connection refused (local e2e tests)

Ensure Docker is running. The tests use testcontainers-go to automatically start etcd:
```bash
# Check Docker is running
docker info

# Pre-pull the etcd image if needed
docker pull quay.io/coreos/etcd:v3.5.11
```

### Test timeout

The lease expiration test takes ~6 seconds. Increase timeout if needed:
```bash
go test -v -timeout 60s -tags=local ./...
```
