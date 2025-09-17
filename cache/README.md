# Cache Library

The Cache library provides a unified interface for caching operations across multiple providers including Redis, Memcached, and in-memory caching. It offers comprehensive caching features with TTL support, tagging, batch operations, and advanced cache management capabilities.

## Features

- **Multi-Provider Support**: Redis, Memcached, and in-memory caching
- **TTL Support**: Time-to-live configuration for cache entries
- **Tagging System**: Cache invalidation by tags for efficient cache management
- **Batch Operations**: Set, get, and delete multiple keys efficiently
- **Pattern Matching**: Find keys using pattern matching
- **Statistics**: Comprehensive cache statistics and monitoring
- **Fallback Support**: Automatic fallback between providers
- **Connection Management**: Robust connection handling with retry logic
- **Health Monitoring**: Provider health checks and status monitoring

## Supported Providers

- **Redis**: Redis cache with advanced features
- **Memcached**: Memcached distributed caching
- **Memory**: In-memory caching for high-performance scenarios

## Installation

```bash
go get github.com/anasamu/go-micro-libs/cache
```

## Quick Start

```go
package main

import (
    "context"
    "fmt"
    "log"
    "time"

    "github.com/anasamu/go-micro-libs/cache"
    "github.com/anasamu/go-micro-libs/cache/types"
    "github.com/sirupsen/logrus"
)

func main() {
    // Create logger
    logger := logrus.New()

    // Create cache manager with default config
    config := &cache.ManagerConfig{
        DefaultProvider: "redis",
        RetryAttempts:   3,
        RetryDelay:      time.Second,
        Timeout:         30 * time.Second,
        FallbackEnabled: true,
    }
    
    manager := cache.NewCacheManager(config, logger)

    // Register Redis provider (example)
    // redisProvider := redis.NewRedisProvider("localhost:6379")
    // manager.RegisterProvider(redisProvider)

    // Set a value in cache
    ctx := context.Background()
    err := manager.Set(ctx, "user:123", map[string]interface{}{
        "name":  "John Doe",
        "email": "john@example.com",
    }, 1*time.Hour)
    
    if err != nil {
        log.Fatal(err)
    }

    // Get value from cache
    var user map[string]interface{}
    err = manager.Get(ctx, "user:123", &user)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("User: %+v\n", user)
}
```

## API Reference

### CacheManager

The main manager for handling cache operations across multiple providers.

#### Methods

##### `NewCacheManager(config *ManagerConfig, logger *logrus.Logger) *CacheManager`
Creates a new cache manager with the given configuration and logger.

##### `RegisterProvider(provider CacheProvider) error`
Registers a new cache provider.

**Parameters:**
- `provider`: The cache provider to register

**Returns:**
- `error`: Any error that occurred during registration

##### `GetProvider(name string) (CacheProvider, error)`
Retrieves a specific provider by name.

##### `GetDefaultProvider() (CacheProvider, error)`
Returns the default cache provider.

##### `Set(ctx context.Context, key string, value interface{}, ttl time.Duration) error`
Stores a value in the cache using the default provider.

**Parameters:**
- `ctx`: Context for cancellation and timeouts
- `key`: Cache key
- `value`: Value to store
- `ttl`: Time-to-live duration

**Returns:**
- `error`: Any error that occurred

##### `SetWithProvider(ctx context.Context, providerName string, key string, value interface{}, ttl time.Duration) error`
Stores a value using a specific provider.

##### `Get(ctx context.Context, key string, dest interface{}) error`
Retrieves a value from the cache using the default provider.

##### `GetWithProvider(ctx context.Context, providerName string, key string, dest interface{}) error`
Retrieves a value using a specific provider.

##### `Delete(ctx context.Context, key string) error`
Removes a value from the cache using the default provider.

##### `DeleteWithProvider(ctx context.Context, providerName string, key string) error`
Removes a value using a specific provider.

##### `Exists(ctx context.Context, key string) (bool, error)`
Checks if a key exists in the cache using the default provider.

##### `ExistsWithProvider(ctx context.Context, providerName string, key string) (bool, error)`
Checks if a key exists using a specific provider.

##### `SetWithTags(ctx context.Context, key string, value interface{}, ttl time.Duration, tags []string) error`
Stores a value with tags for easier invalidation.

##### `SetWithTagsAndProvider(ctx context.Context, providerName string, key string, value interface{}, ttl time.Duration, tags []string) error`
Stores a value with tags using a specific provider.

##### `InvalidateByTag(ctx context.Context, tag string) error`
Invalidates all keys with a specific tag.

##### `InvalidateByTagWithProvider(ctx context.Context, providerName string, tag string) error`
Invalidates all keys with a specific tag using a specific provider.

##### `SetMultiple(ctx context.Context, items map[string]interface{}, ttl time.Duration) error`
Stores multiple values in the cache.

##### `GetMultiple(ctx context.Context, keys []string) (map[string]interface{}, error)`
Retrieves multiple values from the cache.

##### `DeleteMultiple(ctx context.Context, keys []string) error`
Removes multiple values from the cache.

##### `GetKeys(ctx context.Context, pattern string) ([]string, error)`
Returns keys matching a pattern.

##### `GetTTL(ctx context.Context, key string) (time.Duration, error)`
Returns the TTL of a key.

##### `SetTTL(ctx context.Context, key string, ttl time.Duration) error`
Sets the TTL of a key.

##### `GetStats(ctx context.Context) (map[string]*types.CacheStats, error)`
Returns cache statistics from all providers.

##### `Flush(ctx context.Context) error`
Clears all cache data from all providers.

##### `Close() error`
Closes all providers and cleans up resources.

### Types

#### ManagerConfig
Configuration for the cache manager.

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

#### CacheStats
Cache statistics.

```go
type CacheStats struct {
    Hits       int64         `json:"hits"`
    Misses     int64         `json:"misses"`
    Keys       int64         `json:"keys"`
    Memory     int64         `json:"memory"`
    Uptime     time.Duration `json:"uptime"`
    LastUpdate time.Time     `json:"last_update"`
    Provider   string        `json:"provider"`
}
```

#### ConnectionInfo
Connection information for a cache provider.

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

#### CacheFeature
Represents a cache feature.

```go
type CacheFeature string

const (
    FeatureSet    CacheFeature = "set"
    FeatureGet    CacheFeature = "get"
    FeatureDelete CacheFeature = "delete"
    FeatureExists CacheFeature = "exists"
    FeatureFlush  CacheFeature = "flush"
    FeatureStats  CacheFeature = "stats"
    FeatureTags   CacheFeature = "tags"
    FeatureTTL    CacheFeature = "ttl"
    FeatureBatch  CacheFeature = "batch"
    FeaturePattern CacheFeature = "pattern"
)
```

## Advanced Usage

### Basic Cache Operations

```go
// Set a value with TTL
err := manager.Set(ctx, "session:user123", map[string]interface{}{
    "user_id": "123",
    "role":    "admin",
    "expires": time.Now().Add(24 * time.Hour),
}, 24*time.Hour)

// Get a value
var session map[string]interface{}
err = manager.Get(ctx, "session:user123", &session)

// Check if key exists
exists, err := manager.Exists(ctx, "session:user123")

// Delete a key
err = manager.Delete(ctx, "session:user123")
```

### Cache with Tags

```go
// Set value with tags for easy invalidation
tags := []string{"user", "session", "admin"}
err := manager.SetWithTags(ctx, "user:123:profile", userProfile, 1*time.Hour, tags)

// Invalidate all keys with a specific tag
err = manager.InvalidateByTag(ctx, "user") // Invalidates all user-related cache entries
```

### Batch Operations

```go
// Set multiple values at once
items := map[string]interface{}{
    "user:1": map[string]string{"name": "John", "email": "john@example.com"},
    "user:2": map[string]string{"name": "Jane", "email": "jane@example.com"},
    "user:3": map[string]string{"name": "Bob", "email": "bob@example.com"},
}

err := manager.SetMultiple(ctx, items, 1*time.Hour)

// Get multiple values
keys := []string{"user:1", "user:2", "user:3"}
results, err := manager.GetMultiple(ctx, keys)

// Delete multiple keys
err = manager.DeleteMultiple(ctx, keys)
```

### Pattern Matching

```go
// Find all keys matching a pattern
userKeys, err := manager.GetKeys(ctx, "user:*")
sessionKeys, err := manager.GetKeys(ctx, "session:*")
```

### TTL Management

```go
// Set TTL for existing key
err := manager.SetTTL(ctx, "user:123", 2*time.Hour)

// Get current TTL
ttl, err := manager.GetTTL(ctx, "user:123")
fmt.Printf("Key expires in: %v\n", ttl)
```

### Provider-Specific Operations

```go
// Use specific provider
err := manager.SetWithProvider(ctx, "redis", "key", "value", 1*time.Hour)
err = manager.SetWithProvider(ctx, "memcached", "key", "value", 1*time.Hour)

// Get from specific provider
var value string
err = manager.GetWithProvider(ctx, "redis", "key", &value)
```

### Cache Statistics

```go
// Get statistics from all providers
stats, err := manager.GetStats(ctx)
if err != nil {
    log.Fatal(err)
}

for provider, stat := range stats {
    fmt.Printf("Provider: %s\n", provider)
    fmt.Printf("  Hits: %d\n", stat.Hits)
    fmt.Printf("  Misses: %d\n", stat.Misses)
    fmt.Printf("  Hit Rate: %.2f%%\n", float64(stat.Hits)/float64(stat.Hits+stat.Misses)*100)
    fmt.Printf("  Keys: %d\n", stat.Keys)
    fmt.Printf("  Memory: %d bytes\n", stat.Memory)
}
```

### Cache Warming

```go
// Warm cache with frequently accessed data
func warmCache(manager *cache.CacheManager) error {
    ctx := context.Background()
    
    // Load user profiles
    users := loadUsersFromDatabase()
    for _, user := range users {
        key := fmt.Sprintf("user:%d", user.ID)
        err := manager.SetWithTags(ctx, key, user, 1*time.Hour, []string{"user", "profile"})
        if err != nil {
            return err
        }
    }
    
    // Load configuration
    config := loadConfiguration()
    err := manager.SetWithTags(ctx, "config", config, 24*time.Hour, []string{"config"})
    
    return err
}
```

### Cache-Aside Pattern

```go
func getUser(manager *cache.CacheManager, userID string) (*User, error) {
    ctx := context.Background()
    cacheKey := fmt.Sprintf("user:%s", userID)
    
    // Try to get from cache first
    var user User
    err := manager.Get(ctx, cacheKey, &user)
    if err == nil {
        return &user, nil // Cache hit
    }
    
    // Cache miss - load from database
    user, err = loadUserFromDatabase(userID)
    if err != nil {
        return nil, err
    }
    
    // Store in cache for next time
    manager.SetWithTags(ctx, cacheKey, user, 1*time.Hour, []string{"user"})
    
    return &user, nil
}
```

### Write-Through Pattern

```go
func updateUser(manager *cache.CacheManager, user *User) error {
    ctx := context.Background()
    
    // Update database first
    err := updateUserInDatabase(user)
    if err != nil {
        return err
    }
    
    // Update cache
    cacheKey := fmt.Sprintf("user:%s", user.ID)
    err = manager.SetWithTags(ctx, cacheKey, user, 1*time.Hour, []string{"user"})
    
    return err
}
```

### Write-Behind Pattern

```go
func updateUserAsync(manager *cache.CacheManager, user *User) error {
    ctx := context.Background()
    cacheKey := fmt.Sprintf("user:%s", user.ID)
    
    // Update cache immediately
    err := manager.SetWithTags(ctx, cacheKey, user, 1*time.Hour, []string{"user"})
    if err != nil {
        return err
    }
    
    // Queue database update for later
    go func() {
        time.Sleep(5 * time.Second) // Delay for batching
        updateUserInDatabase(user)
    }()
    
    return nil
}
```

### Cache Invalidation Strategies

```go
// Time-based invalidation
func scheduleCacheInvalidation(manager *cache.CacheManager) {
    ticker := time.NewTicker(1 * time.Hour)
    go func() {
        for range ticker.C {
            // Invalidate expired sessions
            manager.InvalidateByTag(context.Background(), "session")
        }
    }()
}

// Event-based invalidation
func onUserUpdate(manager *cache.CacheManager, userID string) {
    ctx := context.Background()
    
    // Invalidate user-specific cache
    manager.Delete(ctx, fmt.Sprintf("user:%s", userID))
    
    // Invalidate related caches
    manager.InvalidateByTag(ctx, "user_profile")
    manager.InvalidateByTag(ctx, "user_permissions")
}
```

### Health Monitoring

```go
// Check provider health
func checkCacheHealth(manager *cache.CacheManager) {
    ctx := context.Background()
    
    // Test basic operations
    testKey := "health_check"
    testValue := "ok"
    
    // Set test value
    err := manager.Set(ctx, testKey, testValue, 1*time.Minute)
    if err != nil {
        log.Printf("Cache health check failed - Set: %v", err)
        return
    }
    
    // Get test value
    var retrievedValue string
    err = manager.Get(ctx, testKey, &retrievedValue)
    if err != nil {
        log.Printf("Cache health check failed - Get: %v", err)
        return
    }
    
    // Clean up
    manager.Delete(ctx, testKey)
    
    if retrievedValue == testValue {
        log.Println("Cache health check passed")
    } else {
        log.Printf("Cache health check failed - value mismatch: expected %s, got %s", testValue, retrievedValue)
    }
}
```

## Error Handling

The library provides comprehensive error handling:

```go
err := manager.Set(ctx, "key", "value", 1*time.Hour)
if err != nil {
    // Handle different types of errors
    switch {
    case strings.Contains(err.Error(), "connection"):
        log.Printf("Cache connection error: %v", err)
    case strings.Contains(err.Error(), "timeout"):
        log.Printf("Cache operation timeout: %v", err)
    case strings.Contains(err.Error(), "not found"):
        log.Printf("Cache key not found: %v", err)
    default:
        log.Printf("Cache operation failed: %v", err)
    }
}
```

## Best Practices

1. **Key Naming**: Use consistent, hierarchical key naming conventions
2. **TTL Management**: Set appropriate TTL values based on data freshness requirements
3. **Tagging**: Use tags for efficient cache invalidation
4. **Batch Operations**: Use batch operations for better performance
5. **Error Handling**: Implement proper error handling and fallback strategies
6. **Monitoring**: Monitor cache hit rates and performance metrics
7. **Memory Management**: Be aware of memory usage with in-memory providers
8. **Serialization**: Ensure proper serialization/deserialization of complex types
9. **Security**: Consider encryption for sensitive cached data
10. **Testing**: Test cache behavior in different scenarios

## Contributing

Contributions are welcome! Please read the contributing guidelines and submit pull requests for any improvements.

## License

This library is licensed under the MIT License. See the LICENSE file for details.
