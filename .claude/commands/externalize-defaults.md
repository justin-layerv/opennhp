---
name: externalize-defaults
description: Refactor code to externalize hardcoded defaults for explicit configuration
---

Refactor the code to externalize hardcoded defaults: $ARGUMENTS

## Philosophy

We prefer **explicit configuration** over defaults, so operators make conscious decisions about values. This approach:

- Prevents bugs from forgotten Terraform plumbing
- Avoids invasive changes later to expose hidden defaults
- Enables fail-fast behavior where misconfigurations are caught at deploy time, not runtime

## When NOT to Use

Keep values as constants (don't externalize) when they are:

- **Protocol-defined**: HTTP status codes, cryptographic parameters, wire format constants
- **Algorithm internals**: Hash seed values, buffer sizes tuned for performance, retry backoff multipliers
- **Compile-time invariants**: Version strings, build tags, feature flags that never change per-deployment
- **Safety limits**: Maximum recursion depth, panic thresholds that protect against bugs (not config)

If unsure, ask: "Would an operator ever need to change this value between deployments?" If no, keep it as a constant.

## Instructions

1. **Analyze the target code** (file path or PR URL provided in arguments)
   - If a **file path**: Analyze that specific file
   - If a **PR URL**: Fetch the PR, analyze all changed files for hardcoded defaults
   - Identify all hardcoded default values
   - Note which values are configuration-driven vs truly constant

2. **For each default found, determine:**
   - **Externalize**: Values that operators should consciously set (timeouts, URLs, sizes, thresholds)
   - **Keep as constant**: Values that are implementation details (magic numbers for algorithms, protocol constants)

3. **Show me your analysis:**
   - List of defaults to externalize with their current values
   - List of constants to keep (with reasoning)
   - Proposed configuration field names

4. **Wait for my approval** before making changes

5. **After approval, implement:**
   - Remove default values from code
   - Add required configuration fields with validation
   - Update config validation to fail fast on missing/invalid values
   - Document recommended values in comments (but don't apply them as defaults)
   - Update tests to explicitly set all required config
   - Update any Terraform/deployment documentation if present

## Example Transformation

**Before:**
```go
func NewClient() *Client {
    return &Client{
        Timeout:     30 * time.Second,  // hardcoded default
        MaxRetries:  3,                  // hardcoded default
        BaseURL:     "https://api.example.com",
    }
}
```

**After:**
```go
// Config holds client configuration.
// All fields are required - no defaults are applied.
type Config struct {
    // Timeout is the request timeout. Recommended: 30s
    Timeout time.Duration
    // MaxRetries is the retry count. Recommended: 3
    MaxRetries int
    // BaseURL is the API endpoint.
    BaseURL string
}

func NewClient(config *Config) (*Client, error) {
    if err := validateConfig(config); err != nil {
        return nil, fmt.Errorf("invalid config: %w", err)
    }
    return &Client{
        Timeout:    config.Timeout,
        MaxRetries: config.MaxRetries,
        BaseURL:    config.BaseURL,
    }, nil
}

func validateConfig(c *Config) error {
    if c.Timeout <= 0 {
        return fmt.Errorf("timeout is required and must be positive")
    }
    if c.MaxRetries < 0 {
        return fmt.Errorf("maxRetries must be non-negative")
    }
    if c.BaseURL == "" {
        return fmt.Errorf("baseURL is required")
    }
    return nil
}
```

## Commit Format

Use conventional commit format:
```
refactor(scope): externalize hardcoded defaults for explicit config

- Remove default values, require explicit configuration
- Add validation for all required fields (fail-fast)
- Document recommended values in comments
```
