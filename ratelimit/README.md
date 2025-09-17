# Rate Limit Library

The Rate Limit library provides a unified interface for rate limiting operations across multiple providers including Redis and in-memory storage. It offers comprehensive rate limiting capabilities with support for various algorithms (token bucket, sliding window, fixed window, leaky bucket), batch operations, and advanced features like pattern matching, persistence, and clustering.

## Features

- **Multi-Provider Support**: Redis, in-memory, and custom providers
- **Multiple Algorithms**: Token bucket, sliding window, fixed window, leaky bucket
- **Batch Operations**: Efficient batch rate limit checks
- **Pattern Matching**: Key pattern matching for bulk operations
- **Persistence**: Persistent rate limit storage
- **Clustering**: Distributed rate limiting support
- **Statistics**: Comprehensive rate limit statistics
- **Retry Logic**: Automatic retry for failed operations
- **Connection Management**: Provider connection management
- **Monitoring**: Real-time monitoring and health checks

## Supported Providers

- **Redis**: Distributed rate limiting with persistence
- **In-Memory**: Fast in-memory rate limiting
- **Custom**: Custom rate limiting providers

## Installation

```bash
go get github.com/anasamu/go-micro-libs/ratelimit
```

## Quick Start

```go
package main

import (
    "context"
    "fmt"
    "log"
    "time"

    "github.com/anasamu/go-micro-libs/ratelimit"
    "github.com/anasamu/go-micro-libs/ratelimit/types"
    "github.com/sirupsen/logrus"
)

func main() {
    // Create logger
    logger := logrus.New()

    // Create rate limit manager
    config := &ratelimit.ManagerConfig{
        DefaultProvider: "redis",
        RetryAttempts:   3,
        RetryDelay:      1 * time.Second,
        Timeout:         30 * time.Second,
        FallbackEnabled: true,
    }
    manager := ratelimit.NewRateLimitManager(config, logger)

    // Register Redis provider (example)
    // redisProvider := redis.NewRedisProvider("localhost:6379")
    // manager.RegisterProvider(redisProvider)

    // Create rate limit
    limit := &types.RateLimit{
        Limit:     100,                    // 100 requests
        Window:    1 * time.Minute,        // per minute
        Algorithm: types.AlgorithmTokenBucket,
    }

    // Check rate limit
    ctx := context.Background()
    result, err := manager.Allow(ctx, "user:123", limit)
    if err != nil {
        log.Fatal(err)
    }

    if result.Allowed {
        fmt.Printf("Request allowed. Remaining: %d\n", result.Remaining)
    } else {
        fmt.Printf("Request blocked. Retry after: %v\n", result.RetryAfter)
    }
}
```

## API Reference

### RateLimitManager

The main manager for handling rate limiting operations across multiple providers.

#### Methods

##### `NewRateLimitManager(config *ManagerConfig, logger *logrus.Logger) *RateLimitManager`
Creates a new rate limit manager with the given configuration and logger.

##### `RegisterProvider(provider RateLimitProvider) error`
Registers a new rate limit provider.

**Parameters:**
- `provider`: The rate limit provider to register

**Returns:**
- `error`: Any error that occurred during registration

##### `GetProvider(name string) (RateLimitProvider, error)`
Retrieves a specific provider by name.

##### `GetDefaultProvider() (RateLimitProvider, error)`
Returns the default rate limit provider.

##### `Allow(ctx context.Context, key string, limit *types.RateLimit) (*types.RateLimitResult, error)`
Checks if a request is allowed using the default provider.

**Parameters:**
- `ctx`: Context for cancellation and timeouts
- `key`: Unique identifier for the rate limit
- `limit`: Rate limit configuration

**Returns:**
- `*types.RateLimitResult`: Rate limit result with allowed status and remaining requests
- `error`: Any error that occurred

##### `AllowWithProvider(ctx context.Context, providerName string, key string, limit *types.RateLimit) (*types.RateLimitResult, error)`
Checks if a request is allowed using a specific provider.

##### `Reset(ctx context.Context, key string) error`
Resets the rate limit for a key using the default provider.

##### `ResetWithProvider(ctx context.Context, providerName string, key string) error`
Resets the rate limit for a key using a specific provider.

##### `GetRemaining(ctx context.Context, key string, limit *types.RateLimit) (int64, error)`
Returns the remaining requests for a key using the default provider.

##### `GetRemainingWithProvider(ctx context.Context, providerName string, key string, limit *types.RateLimit) (int64, error)`
Returns the remaining requests for a key using a specific provider.

##### `GetResetTime(ctx context.Context, key string, limit *types.RateLimit) (time.Time, error)`
Returns the reset time for a key using the default provider.

##### `GetResetTimeWithProvider(ctx context.Context, providerName string, key string, limit *types.RateLimit) (time.Time, error)`
Returns the reset time for a key using a specific provider.

##### `AllowMultiple(ctx context.Context, requests []*types.RateLimitRequest) ([]*types.RateLimitResult, error)`
Checks multiple rate limit requests using the default provider.

##### `AllowMultipleWithProvider(ctx context.Context, providerName string, requests []*types.RateLimitRequest) ([]*types.RateLimitResult, error)`
Checks multiple rate limit requests using a specific provider.

##### `ResetMultiple(ctx context.Context, keys []string) error`
Resets multiple rate limits using the default provider.

##### `ResetMultipleWithProvider(ctx context.Context, providerName string, keys []string) error`
Resets multiple rate limits using a specific provider.

##### `GetStats(ctx context.Context) (map[string]*types.RateLimitStats, error)`
Returns rate limit statistics from all providers.

##### `GetKeys(ctx context.Context, pattern string) ([]string, error)`
Returns keys matching a pattern using the default provider.

##### `GetKeysWithProvider(ctx context.Context, providerName string, pattern string) ([]string, error)`
Returns keys matching a pattern using a specific provider.

##### `Close() error`
Closes all rate limit providers.

##### `ListProviders() []string`
Returns a list of registered provider names.

##### `GetProviderInfo() map[string]*types.ProviderInfo`
Returns information about all registered providers.

### Types

#### ManagerConfig
Configuration for the rate limit manager.

```go
type ManagerConfig struct {
    DefaultProvider string            `json:"default_provider"`
    RetryAttempts   int               `json:"retry_attempts"`
    RetryDelay      time.Duration     `json:"retry_delay"`
    Timeout         time.Duration     `json:"timeout"`
    FallbackEnabled bool              `json:"fallback_enabled"`
    Metadata        map[string]string `json:"metadata"`
}
```

#### RateLimit
Represents a rate limit configuration.

```go
type RateLimit struct {
    Limit     int64                  `json:"limit"`     // Maximum number of requests
    Window    time.Duration          `json:"window"`    // Time window for the limit
    Algorithm Algorithm              `json:"algorithm"` // Rate limiting algorithm
    Metadata  map[string]interface{} `json:"metadata,omitempty"`
}
```

#### Algorithm
Represents the rate limiting algorithm.

```go
const (
    AlgorithmTokenBucket   Algorithm = "token_bucket"
    AlgorithmSlidingWindow Algorithm = "sliding_window"
    AlgorithmFixedWindow   Algorithm = "fixed_window"
    AlgorithmLeakyBucket   Algorithm = "leaky_bucket"
)
```

#### RateLimitResult
Represents the result of a rate limit check.

```go
type RateLimitResult struct {
    Allowed    bool                   `json:"allowed"`               // Whether the request is allowed
    Limit      int64                  `json:"limit"`                 // Total limit
    Remaining  int64                  `json:"remaining"`             // Remaining requests
    ResetTime  time.Time              `json:"reset_time"`            // When the limit resets
    RetryAfter time.Duration          `json:"retry_after,omitempty"` // How long to wait before retry
    Key        string                 `json:"key"`                   // The rate limit key
    Metadata   map[string]interface{} `json:"metadata,omitempty"`
}
```

#### RateLimitRequest
Represents a rate limit request.

```go
type RateLimitRequest struct {
    Key   string     `json:"key"`
    Limit *RateLimit `json:"limit"`
}
```

#### RateLimitStats
Represents rate limit statistics.

```go
type RateLimitStats struct {
    TotalRequests   int64         `json:"total_requests"`
    AllowedRequests int64         `json:"allowed_requests"`
    BlockedRequests int64         `json:"blocked_requests"`
    ActiveKeys      int64         `json:"active_keys"`
    Memory          int64         `json:"memory"`
    Uptime          time.Duration `json:"uptime"`
    LastUpdate      time.Time     `json:"last_update"`
    Provider        string        `json:"provider"`
}
```

#### ConnectionInfo
Holds connection information for a rate limit provider.

```go
type ConnectionInfo struct {
    Host     string            `json:"host"`
    Port     int               `json:"port"`
    Database string            `json:"database"`
    Username string            `json:"username"`
    Status   ConnectionStatus  `json:"status"`
    Metadata map[string]string `json:"metadata"`
}
```

#### ProviderInfo
Holds information about a rate limit provider.

```go
type ProviderInfo struct {
    Name              string             `json:"name"`
    SupportedFeatures []RateLimitFeature `json:"supported_features"`
    ConnectionInfo    *ConnectionInfo    `json:"connection_info"`
    IsConnected       bool               `json:"is_connected"`
}
```

## Advanced Usage

### Different Rate Limiting Algorithms

```go
// Token bucket algorithm
tokenBucketLimit := &types.RateLimit{
    Limit:     100,
    Window:    1 * time.Minute,
    Algorithm: types.AlgorithmTokenBucket,
    Metadata: map[string]interface{}{
        "capacity":     100,
        "refill_rate":  10, // 10 tokens per second
        "refill_period": 1 * time.Second,
    },
}

result, err := manager.Allow(ctx, "user:123", tokenBucketLimit)

// Sliding window algorithm
slidingWindowLimit := &types.RateLimit{
    Limit:     50,
    Window:    1 * time.Minute,
    Algorithm: types.AlgorithmSlidingWindow,
    Metadata: map[string]interface{}{
        "window_size":  1 * time.Minute,
        "granularity":  1 * time.Second,
    },
}

result, err = manager.Allow(ctx, "api:endpoint", slidingWindowLimit)

// Fixed window algorithm
fixedWindowLimit := &types.RateLimit{
    Limit:     1000,
    Window:    1 * time.Hour,
    Algorithm: types.AlgorithmFixedWindow,
    Metadata: map[string]interface{}{
        "window_size": 1 * time.Hour,
    },
}

result, err = manager.Allow(ctx, "service:global", fixedWindowLimit)

// Leaky bucket algorithm
leakyBucketLimit := &types.RateLimit{
    Limit:     200,
    Window:    1 * time.Minute,
    Algorithm: types.AlgorithmLeakyBucket,
    Metadata: map[string]interface{}{
        "capacity": 200,
        "leak_rate": 5, // 5 requests per second
    },
}

result, err = manager.Allow(ctx, "queue:processing", leakyBucketLimit)
```

### Batch Operations

```go
// Check multiple rate limits at once
requests := []*types.RateLimitRequest{
    {
        Key: "user:123",
        Limit: &types.RateLimit{
            Limit:     100,
            Window:    1 * time.Minute,
            Algorithm: types.AlgorithmTokenBucket,
        },
    },
    {
        Key: "user:456",
        Limit: &types.RateLimit{
            Limit:     50,
            Window:    1 * time.Minute,
            Algorithm: types.AlgorithmSlidingWindow,
        },
    },
    {
        Key: "api:global",
        Limit: &types.RateLimit{
            Limit:     1000,
            Window:    1 * time.Hour,
            Algorithm: types.AlgorithmFixedWindow,
        },
    },
}

results, err := manager.AllowMultiple(ctx, requests)
if err != nil {
    log.Printf("Batch rate limit check failed: %v", err)
    return
}

for i, result := range results {
    if result.Allowed {
        fmt.Printf("Request %d allowed. Remaining: %d\n", i, result.Remaining)
    } else {
        fmt.Printf("Request %d blocked. Retry after: %v\n", i, result.RetryAfter)
    }
}

// Reset multiple rate limits
keys := []string{"user:123", "user:456", "api:global"}
err = manager.ResetMultiple(ctx, keys)
```

### Pattern Matching

```go
// Get all keys matching a pattern
pattern := "user:*"
keys, err := manager.GetKeys(ctx, pattern)
if err != nil {
    log.Printf("Failed to get keys: %v", err)
    return
}

fmt.Printf("Found %d keys matching pattern '%s'\n", len(keys), pattern)

// Get keys for specific patterns
patterns := []string{
    "user:*",
    "api:*",
    "service:*",
}

for _, pattern := range patterns {
    keys, err := manager.GetKeys(ctx, pattern)
    if err != nil {
        log.Printf("Failed to get keys for pattern %s: %v", pattern, err)
        continue
    }
    fmt.Printf("Pattern '%s': %d keys\n", pattern, len(keys))
}
```

### HTTP Middleware for Rate Limiting

```go
func rateLimitMiddleware(manager *ratelimit.RateLimitManager) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            // Extract user identifier (could be IP, user ID, etc.)
            userID := getUserID(r)
            key := fmt.Sprintf("api:%s:%s", r.URL.Path, userID)
            
            // Define rate limit
            limit := &types.RateLimit{
                Limit:     100,
                Window:    1 * time.Minute,
                Algorithm: types.AlgorithmTokenBucket,
            }
            
            // Check rate limit
            result, err := manager.Allow(r.Context(), key, limit)
            if err != nil {
                log.Printf("Rate limit check failed: %v", err)
                http.Error(w, "Rate limit check failed", http.StatusInternalServerError)
                return
            }
            
            // Add rate limit headers
            w.Header().Set("X-RateLimit-Limit", fmt.Sprintf("%d", result.Limit))
            w.Header().Set("X-RateLimit-Remaining", fmt.Sprintf("%d", result.Remaining))
            w.Header().Set("X-RateLimit-Reset", fmt.Sprintf("%d", result.ResetTime.Unix()))
            
            if !result.Allowed {
                w.Header().Set("Retry-After", fmt.Sprintf("%.0f", result.RetryAfter.Seconds()))
                http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
                return
            }
            
            // Process request
            next.ServeHTTP(w, r)
        })
    }
}

func getUserID(r *http.Request) string {
    // Extract user ID from various sources
    if userID := r.Header.Get("X-User-ID"); userID != "" {
        return userID
    }
    if userID := r.URL.Query().Get("user_id"); userID != "" {
        return userID
    }
    // Fallback to IP address
    return r.RemoteAddr
}
```

### Advanced Rate Limiting Strategies

```go
// Tiered rate limiting
func tieredRateLimit(manager *ratelimit.RateLimitManager, userID string, userTier string) (*types.RateLimitResult, error) {
    var limit *types.RateLimit
    
    switch userTier {
    case "premium":
        limit = &types.RateLimit{
            Limit:     1000,
            Window:    1 * time.Minute,
            Algorithm: types.AlgorithmTokenBucket,
        }
    case "standard":
        limit = &types.RateLimit{
            Limit:     100,
            Window:    1 * time.Minute,
            Algorithm: types.AlgorithmTokenBucket,
        }
    case "basic":
        limit = &types.RateLimit{
            Limit:     10,
            Window:    1 * time.Minute,
            Algorithm: types.AlgorithmTokenBucket,
        }
    default:
        limit = &types.RateLimit{
            Limit:     5,
            Window:    1 * time.Minute,
            Algorithm: types.AlgorithmTokenBucket,
        }
    }
    
    key := fmt.Sprintf("tier:%s:%s", userTier, userID)
    return manager.Allow(context.Background(), key, limit)
}

// Burst rate limiting
func burstRateLimit(manager *ratelimit.RateLimitManager, key string) (*types.RateLimitResult, error) {
    // Allow burst of 10 requests, then 1 request per second
    limit := &types.RateLimit{
        Limit:     10,
        Window:    1 * time.Second,
        Algorithm: types.AlgorithmTokenBucket,
        Metadata: map[string]interface{}{
            "capacity":     10,
            "refill_rate":  1,
            "refill_period": 1 * time.Second,
        },
    }
    
    return manager.Allow(context.Background(), key, limit)
}

// Adaptive rate limiting
func adaptiveRateLimit(manager *ratelimit.RateLimitManager, key string, currentLoad float64) (*types.RateLimitResult, error) {
    var limit int64
    
    // Adjust limit based on current system load
    if currentLoad > 0.8 {
        limit = 10 // High load, reduce limit
    } else if currentLoad > 0.5 {
        limit = 50 // Medium load, moderate limit
    } else {
        limit = 100 // Low load, normal limit
    }
    
    rateLimit := &types.RateLimit{
        Limit:     limit,
        Window:    1 * time.Minute,
        Algorithm: types.AlgorithmSlidingWindow,
        Metadata: map[string]interface{}{
            "load_factor": currentLoad,
        },
    }
    
    return manager.Allow(context.Background(), key, rateLimit)
}
```

### Statistics and Monitoring

```go
// Get statistics from all providers
stats, err := manager.GetStats(ctx)
if err != nil {
    log.Printf("Failed to get statistics: %v", err)
    return
}

for providerName, stat := range stats {
    fmt.Printf("Provider: %s\n", providerName)
    fmt.Printf("  Total Requests: %d\n", stat.TotalRequests)
    fmt.Printf("  Allowed Requests: %d\n", stat.AllowedRequests)
    fmt.Printf("  Blocked Requests: %d\n", stat.BlockedRequests)
    fmt.Printf("  Active Keys: %d\n", stat.ActiveKeys)
    fmt.Printf("  Memory Usage: %d bytes\n", stat.Memory)
    fmt.Printf("  Uptime: %v\n", stat.Uptime)
    fmt.Printf("  Last Update: %v\n", stat.LastUpdate)
    fmt.Println()
}

// Get provider information
providerInfo := manager.GetProviderInfo()
for name, info := range providerInfo {
    fmt.Printf("Provider: %s\n", name)
    fmt.Printf("  Connected: %t\n", info.IsConnected)
    fmt.Printf("  Features: %v\n", info.SupportedFeatures)
    if info.ConnectionInfo != nil {
        fmt.Printf("  Host: %s:%d\n", info.ConnectionInfo.Host, info.ConnectionInfo.Port)
        fmt.Printf("  Status: %s\n", info.ConnectionInfo.Status)
    }
    fmt.Println()
}
```

### Error Handling

```go
result, err := manager.Allow(ctx, "user:123", limit)
if err != nil {
    // Handle different types of errors
    switch {
    case strings.Contains(err.Error(), "connection"):
        log.Printf("Rate limit provider connection error: %v", err)
        // Fallback to local rate limiting or allow request
    case strings.Contains(err.Error(), "timeout"):
        log.Printf("Rate limit operation timeout: %v", err)
        // Allow request or return error
    case strings.Contains(err.Error(), "quota"):
        log.Printf("Rate limit quota exceeded: %v", err)
        // Block request
    default:
        log.Printf("Rate limit operation failed: %v", err)
        // Handle unknown error
    }
    return
}

// Handle rate limit result
if !result.Allowed {
    log.Printf("Rate limit exceeded for key %s. Retry after %v", result.Key, result.RetryAfter)
    // Return rate limit exceeded response
    return
}

log.Printf("Request allowed. Remaining: %d, Reset time: %v", result.Remaining, result.ResetTime)
```

### Configuration Management

```go
// Custom configuration
config := &ratelimit.ManagerConfig{
    DefaultProvider: "redis",
    RetryAttempts:   5,
    RetryDelay:      2 * time.Second,
    Timeout:         60 * time.Second,
    FallbackEnabled: true,
    Metadata: map[string]string{
        "environment": "production",
        "version":     "1.0.0",
    },
}

manager := ratelimit.NewRateLimitManager(config, logger)
```

## Best Practices

1. **Key Design**: Use meaningful, hierarchical keys for rate limits
2. **Algorithm Selection**: Choose appropriate algorithms for different use cases
3. **Batch Operations**: Use batch operations for better performance
4. **Error Handling**: Implement comprehensive error handling
5. **Monitoring**: Monitor rate limit statistics and performance
6. **Fallback Strategy**: Implement fallback strategies for provider failures
7. **Testing**: Test rate limiting in different scenarios
8. **Documentation**: Document rate limit policies and configurations
9. **Security**: Secure rate limit keys and prevent manipulation
10. **Performance**: Optimize rate limit operations for high throughput

## Contributing

Contributions are welcome! Please read the contributing guidelines and submit pull requests for any improvements.

## License

This library is licensed under the MIT License. See the LICENSE file for details.
