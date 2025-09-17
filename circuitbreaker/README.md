# Circuit Breaker Library

The Circuit Breaker library provides a unified interface for circuit breaker operations across multiple providers including GoBreaker and custom implementations. It offers comprehensive circuit breaker capabilities with support for various states (closed, open, half-open), fallback mechanisms, retry logic, and advanced features like bulkhead isolation, rate limiting, health checks, and comprehensive monitoring.

## Features

- **Multi-Provider Support**: GoBreaker, custom, and more providers
- **Circuit States**: Closed, open, and half-open states
- **Fallback Mechanisms**: Automatic fallback when circuit is open
- **Retry Logic**: Configurable retry with different backoff strategies
- **Bulkhead Isolation**: Resource isolation and protection
- **Rate Limiting**: Request rate limiting capabilities
- **Health Checks**: Circuit health monitoring
- **Comprehensive Monitoring**: Detailed statistics and metrics
- **Configuration Management**: Dynamic circuit breaker configuration
- **Batch Operations**: Bulk circuit breaker operations

## Supported Providers

- **GoBreaker**: Popular Go circuit breaker implementation
- **Custom**: Custom circuit breaker providers
- **Hystrix**: Hystrix-compatible circuit breakers

## Installation

```bash
go get github.com/anasamu/go-micro-libs/circuitbreaker
```

## Quick Start

```go
package main

import (
    "context"
    "fmt"
    "log"
    "time"

    "github.com/anasamu/go-micro-libs/circuitbreaker"
    "github.com/anasamu/go-micro-libs/circuitbreaker/types"
    "github.com/sirupsen/logrus"
)

func main() {
    // Create logger
    logger := logrus.New()

    // Create circuit breaker manager
    config := &circuitbreaker.ManagerConfig{
        DefaultProvider: "gobreaker",
        RetryAttempts:   3,
        RetryDelay:      1 * time.Second,
        Timeout:         30 * time.Second,
        FallbackEnabled: true,
    }
    manager := circuitbreaker.NewCircuitBreakerManager(config, logger)

    // Register GoBreaker provider (example)
    // gobreakerProvider := gobreaker.NewGoBreakerProvider()
    // manager.RegisterProvider(gobreakerProvider)

    // Configure a circuit breaker
    cbConfig := &types.CircuitBreakerConfig{
        Name:                "api-service",
        MaxRequests:         10,
        Interval:            10 * time.Second,
        Timeout:             60 * time.Second,
        MaxConsecutiveFails: 5,
        FailureThreshold:    0.5,
        SuccessThreshold:    3,
        FallbackEnabled:     true,
        RetryEnabled:        true,
        RetryAttempts:       3,
        RetryDelay:          time.Second,
    }

    err := manager.Configure(context.Background(), "api-service", cbConfig)
    if err != nil {
        log.Fatal(err)
    }

    // Execute a function through the circuit breaker
    result, err := manager.Execute(context.Background(), "api-service", func() (interface{}, error) {
        // Simulate API call
        return "API response", nil
    })

    if err != nil {
        log.Printf("Circuit breaker execution failed: %v", err)
    } else {
        fmt.Printf("Result: %v, State: %s\n", result.Result, result.State)
    }
}
```

## API Reference

### CircuitBreakerManager

The main manager for handling circuit breaker operations across multiple providers.

#### Methods

##### `NewCircuitBreakerManager(config *ManagerConfig, logger *logrus.Logger) *CircuitBreakerManager`
Creates a new circuit breaker manager with the given configuration and logger.

##### `RegisterProvider(provider CircuitBreakerProvider) error`
Registers a new circuit breaker provider.

**Parameters:**
- `provider`: The circuit breaker provider to register

**Returns:**
- `error`: Any error that occurred during registration

##### `GetProvider(name string) (CircuitBreakerProvider, error)`
Retrieves a specific provider by name.

##### `GetDefaultProvider() (CircuitBreakerProvider, error)`
Returns the default circuit breaker provider.

##### `Execute(ctx context.Context, name string, fn func() (interface{}, error)) (*types.ExecutionResult, error)`
Executes a function through the circuit breaker using the default provider.

**Parameters:**
- `ctx`: Context for cancellation and timeouts
- `name`: Name of the circuit breaker
- `fn`: Function to execute

**Returns:**
- `*types.ExecutionResult`: Execution result with state and metrics
- `error`: Any error that occurred

##### `ExecuteWithProvider(ctx context.Context, providerName string, name string, fn func() (interface{}, error)) (*types.ExecutionResult, error)`
Executes a function through the circuit breaker using a specific provider.

##### `ExecuteWithFallback(ctx context.Context, name string, fn func() (interface{}, error), fallback func() (interface{}, error)) (*types.ExecutionResult, error)`
Executes a function with fallback through the circuit breaker using the default provider.

##### `ExecuteWithFallbackAndProvider(ctx context.Context, providerName string, name string, fn func() (interface{}, error), fallback func() (interface{}, error)) (*types.ExecutionResult, error)`
Executes a function with fallback through the circuit breaker using a specific provider.

##### `GetState(ctx context.Context, name string) (types.CircuitState, error)`
Returns the state of a circuit breaker using the default provider.

##### `GetStateWithProvider(ctx context.Context, providerName string, name string) (types.CircuitState, error)`
Returns the state of a circuit breaker using a specific provider.

##### `GetStats(ctx context.Context, name string) (*types.CircuitBreakerStats, error)`
Returns circuit breaker statistics using the default provider.

##### `GetStatsWithProvider(ctx context.Context, providerName string, name string) (*types.CircuitBreakerStats, error)`
Returns circuit breaker statistics using a specific provider.

##### `Reset(ctx context.Context, name string) error`
Resets a circuit breaker using the default provider.

##### `ResetWithProvider(ctx context.Context, providerName string, name string) error`
Resets a circuit breaker using a specific provider.

##### `Configure(ctx context.Context, name string, config *types.CircuitBreakerConfig) error`
Configures a circuit breaker using the default provider.

##### `ConfigureWithProvider(ctx context.Context, providerName string, name string, config *types.CircuitBreakerConfig) error`
Configures a circuit breaker using a specific provider.

##### `GetConfig(ctx context.Context, name string) (*types.CircuitBreakerConfig, error)`
Returns circuit breaker configuration using the default provider.

##### `GetConfigWithProvider(ctx context.Context, providerName string, name string) (*types.CircuitBreakerConfig, error)`
Returns circuit breaker configuration using a specific provider.

##### `GetAllStates(ctx context.Context) (map[string]map[string]types.CircuitState, error)`
Returns states of all circuit breakers from all providers.

##### `GetAllStats(ctx context.Context) (map[string]map[string]*types.CircuitBreakerStats, error)`
Returns statistics of all circuit breakers from all providers.

##### `ResetAll(ctx context.Context) error`
Resets all circuit breakers from all providers.

##### `Close() error`
Closes all circuit breaker providers.

##### `ListProviders() []string`
Returns a list of registered provider names.

##### `GetProviderInfo() map[string]*types.ProviderInfo`
Returns information about all registered providers.

### Types

#### ManagerConfig
Configuration for the circuit breaker manager.

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

#### CircuitState
Represents the state of a circuit breaker.

```go
const (
    StateClosed   CircuitState = "closed"   // Normal operation
    StateOpen     CircuitState = "open"     // Circuit is open, failing fast
    StateHalfOpen CircuitState = "halfopen" // Testing if service is back
)
```

#### CircuitBreakerConfig
Holds circuit breaker configuration.

```go
type CircuitBreakerConfig struct {
    Name                string                                                `json:"name"`
    MaxRequests         uint32                                                `json:"max_requests"`
    Interval            time.Duration                                         `json:"interval"`
    Timeout             time.Duration                                         `json:"timeout"`
    ReadyToTrip         func(counts Counts) bool                              `json:"-"`
    OnStateChange       func(name string, from CircuitState, to CircuitState) `json:"-"`
    IsSuccessful        func(err error) bool                                  `json:"-"`
    MaxConsecutiveFails uint32                                                `json:"max_consecutive_fails"`
    FailureThreshold    float64                                               `json:"failure_threshold"`
    SuccessThreshold    uint32                                                `json:"success_threshold"`
    FallbackEnabled     bool                                                  `json:"fallback_enabled"`
    RetryEnabled        bool                                                  `json:"retry_enabled"`
    RetryAttempts       int                                                   `json:"retry_attempts"`
    RetryDelay          time.Duration                                         `json:"retry_delay"`
    Metadata            map[string]string                                     `json:"metadata"`
}
```

#### ExecutionResult
Represents the result of a circuit breaker execution.

```go
type ExecutionResult struct {
    Result   interface{}   `json:"result"`
    Error    error         `json:"error,omitempty"`
    Duration time.Duration `json:"duration"`
    State    CircuitState  `json:"state"`
    Fallback bool          `json:"fallback"`
    Retry    bool          `json:"retry"`
    Attempts int           `json:"attempts"`
}
```

#### CircuitBreakerStats
Represents circuit breaker statistics.

```go
type CircuitBreakerStats struct {
    Requests             int64         `json:"requests"`
    Successes            int64         `json:"successes"`
    Failures             int64         `json:"failures"`
    Timeouts             int64         `json:"timeouts"`
    Rejects              int64         `json:"rejects"`
    State                CircuitState  `json:"state"`
    LastFailureTime      time.Time     `json:"last_failure_time"`
    LastSuccessTime      time.Time     `json:"last_success_time"`
    ConsecutiveFailures  int64         `json:"consecutive_failures"`
    ConsecutiveSuccesses int64         `json:"consecutive_successes"`
    Uptime               time.Duration `json:"uptime"`
    LastUpdate           time.Time     `json:"last_update"`
    Provider             string        `json:"provider"`
}
```

## Advanced Usage

### Basic Circuit Breaker Usage

```go
// Configure a circuit breaker
config := &types.CircuitBreakerConfig{
    Name:                "payment-service",
    MaxRequests:         10,
    Interval:            10 * time.Second,
    Timeout:             60 * time.Second,
    MaxConsecutiveFails: 5,
    FailureThreshold:    0.5,
    SuccessThreshold:    3,
    FallbackEnabled:     true,
    RetryEnabled:        true,
    RetryAttempts:       3,
    RetryDelay:          time.Second,
    ReadyToTrip: func(counts types.Counts) bool {
        return counts.ConsecutiveFailures >= 5
    },
    IsSuccessful: func(err error) bool {
        return err == nil
    },
    OnStateChange: func(name string, from, to types.CircuitState) {
        fmt.Printf("Circuit breaker %s changed from %s to %s\n", name, from, to)
    },
}

err := manager.Configure(ctx, "payment-service", config)

// Execute function through circuit breaker
result, err := manager.Execute(ctx, "payment-service", func() (interface{}, error) {
    // Simulate payment processing
    return processPayment(), nil
})

if err != nil {
    log.Printf("Payment processing failed: %v", err)
} else {
    fmt.Printf("Payment processed: %v\n", result.Result)
}
```

### Fallback Mechanisms

```go
// Execute with fallback
result, err := manager.ExecuteWithFallback(ctx, "payment-service", 
    func() (interface{}, error) {
        // Primary payment service
        return primaryPaymentService.ProcessPayment()
    },
    func() (interface{}, error) {
        // Fallback payment service
        return fallbackPaymentService.ProcessPayment()
    },
)

if err != nil {
    log.Printf("Both primary and fallback failed: %v", err)
} else {
    if result.Fallback {
        fmt.Printf("Used fallback service: %v\n", result.Result)
    } else {
        fmt.Printf("Used primary service: %v\n", result.Result)
    }
}
```

### Custom Success Criteria

```go
// Configure circuit breaker with custom success criteria
config := &types.CircuitBreakerConfig{
    Name:                "api-service",
    MaxRequests:         20,
    Interval:            15 * time.Second,
    Timeout:             30 * time.Second,
    MaxConsecutiveFails: 3,
    FailureThreshold:    0.3,
    SuccessThreshold:    2,
    IsSuccessful: func(err error) bool {
        // Consider 4xx errors as successful (client errors)
        if err == nil {
            return true
        }
        
        // Check if it's a client error (4xx)
        if httpErr, ok := err.(*HTTPError); ok {
            return httpErr.StatusCode >= 400 && httpErr.StatusCode < 500
        }
        
        return false
    },
    ReadyToTrip: func(counts types.Counts) bool {
        // Trip if failure rate is high or consecutive failures
        failureRate := float64(counts.TotalFailures) / float64(counts.Requests)
        return failureRate > 0.5 || counts.ConsecutiveFailures >= 5
    },
}

err := manager.Configure(ctx, "api-service", config)
```

### State Monitoring

```go
// Monitor circuit breaker state
ticker := time.NewTicker(5 * time.Second)
defer ticker.Stop()

for {
    select {
    case <-ctx.Done():
        return
    case <-ticker.C:
        state, err := manager.GetState(ctx, "payment-service")
        if err != nil {
            log.Printf("Failed to get circuit breaker state: %v", err)
            continue
        }

        stats, err := manager.GetStats(ctx, "payment-service")
        if err != nil {
            log.Printf("Failed to get circuit breaker stats: %v", err)
            continue
        }

        fmt.Printf("Circuit Breaker State: %s\n", state)
        fmt.Printf("Requests: %d, Successes: %d, Failures: %d\n", 
            stats.Requests, stats.Successes, stats.Failures)
        fmt.Printf("Consecutive Failures: %d, Consecutive Successes: %d\n",
            stats.ConsecutiveFailures, stats.ConsecutiveSuccesses)

        // Alert if circuit is open
        if state == types.StateOpen {
            fmt.Printf("ALERT: Circuit breaker is OPEN for payment-service\n")
        }
    }
}
```

### Bulk Operations

```go
// Get states of all circuit breakers
allStates, err := manager.GetAllStates(ctx)
if err != nil {
    log.Printf("Failed to get all states: %v", err)
    return
}

for providerName, states := range allStates {
    fmt.Printf("Provider: %s\n", providerName)
    for circuitName, state := range states {
        fmt.Printf("  %s: %s\n", circuitName, state)
    }
}

// Get statistics of all circuit breakers
allStats, err := manager.GetAllStats(ctx)
if err != nil {
    log.Printf("Failed to get all stats: %v", err)
    return
}

for providerName, stats := range allStats {
    fmt.Printf("Provider: %s\n", providerName)
    for circuitName, stat := range stats {
        fmt.Printf("  %s: Requests=%d, Successes=%d, Failures=%d, State=%s\n",
            circuitName, stat.Requests, stat.Successes, stat.Failures, stat.State)
    }
}

// Reset all circuit breakers
err = manager.ResetAll(ctx)
if err != nil {
    log.Printf("Failed to reset all circuit breakers: %v", err)
}
```

### HTTP Middleware Integration

```go
func circuitBreakerMiddleware(manager *circuitbreaker.CircuitBreakerManager) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            // Create circuit breaker name based on route
            circuitName := fmt.Sprintf("http-%s-%s", r.Method, r.URL.Path)
            
            // Execute request through circuit breaker
            result, err := manager.Execute(r.Context(), circuitName, func() (interface{}, error) {
                // Create a response recorder
                recorder := httptest.NewRecorder()
                
                // Execute the handler
                next.ServeHTTP(recorder, r)
                
                // Check if response indicates failure
                if recorder.Code >= 500 {
                    return nil, fmt.Errorf("server error: %d", recorder.Code)
                }
                
                // Copy response
                for key, values := range recorder.Header() {
                    for _, value := range values {
                        w.Header().Add(key, value)
                    }
                }
                w.WriteHeader(recorder.Code)
                w.Write(recorder.Body.Bytes())
                
                return recorder.Code, nil
            })
            
            if err != nil {
                // Circuit breaker is open or function failed
                http.Error(w, "Service temporarily unavailable", http.StatusServiceUnavailable)
                return
            }
            
            // Log circuit breaker result
            if result.Fallback {
                log.Printf("Used fallback for %s %s", r.Method, r.URL.Path)
            }
        })
    }
}

// Use the middleware
http.Handle("/api/", circuitBreakerMiddleware(manager))
```

### Advanced Configuration

```go
// Configure multiple circuit breakers with different settings
configs := map[string]*types.CircuitBreakerConfig{
    "fast-service": {
        Name:                "fast-service",
        MaxRequests:         100,
        Interval:            5 * time.Second,
        Timeout:             10 * time.Second,
        MaxConsecutiveFails: 10,
        FailureThreshold:    0.1,
        SuccessThreshold:    5,
        FallbackEnabled:     false,
        RetryEnabled:        true,
        RetryAttempts:       2,
        RetryDelay:          100 * time.Millisecond,
    },
    "slow-service": {
        Name:                "slow-service",
        MaxRequests:         5,
        Interval:            30 * time.Second,
        Timeout:             120 * time.Second,
        MaxConsecutiveFails: 3,
        FailureThreshold:    0.3,
        SuccessThreshold:    2,
        FallbackEnabled:     true,
        RetryEnabled:        true,
        RetryAttempts:       5,
        RetryDelay:          5 * time.Second,
    },
    "critical-service": {
        Name:                "critical-service",
        MaxRequests:         50,
        Interval:            10 * time.Second,
        Timeout:             30 * time.Second,
        MaxConsecutiveFails: 2,
        FailureThreshold:    0.05,
        SuccessThreshold:    10,
        FallbackEnabled:     true,
        RetryEnabled:        true,
        RetryAttempts:       10,
        RetryDelay:          time.Second,
    },
}

// Configure all circuit breakers
for name, config := range configs {
    err := manager.Configure(ctx, name, config)
    if err != nil {
        log.Printf("Failed to configure circuit breaker %s: %v", name, err)
    }
}
```

### Error Handling

```go
result, err := manager.Execute(ctx, "payment-service", func() (interface{}, error) {
    return processPayment()
})

if err != nil {
    // Handle different types of errors
    switch {
    case strings.Contains(err.Error(), "circuit open"):
        log.Printf("Circuit breaker is open: %v", err)
        // Use fallback or return cached response
    case strings.Contains(err.Error(), "timeout"):
        log.Printf("Request timeout: %v", err)
        // Handle timeout
    case strings.Contains(err.Error(), "max requests"):
        log.Printf("Max requests exceeded: %v", err)
        // Handle rate limiting
    default:
        log.Printf("Circuit breaker execution failed: %v", err)
    }
    return
}

// Handle execution result
if result.Fallback {
    log.Printf("Used fallback function")
}

if result.Retry {
    log.Printf("Function was retried %d times", result.Attempts)
}

fmt.Printf("Execution successful: %v (Duration: %v, State: %s)\n", 
    result.Result, result.Duration, result.State)
```

### Configuration Management

```go
// Custom configuration
config := &circuitbreaker.ManagerConfig{
    DefaultProvider: "gobreaker",
    RetryAttempts:   5,
    RetryDelay:      2 * time.Second,
    Timeout:         60 * time.Second,
    FallbackEnabled: true,
    Metadata: map[string]string{
        "environment": "production",
        "version":     "1.0.0",
    },
}

manager := circuitbreaker.NewCircuitBreakerManager(config, logger)
```

## Best Practices

1. **Threshold Configuration**: Set appropriate failure thresholds based on service characteristics
2. **Timeout Settings**: Configure timeouts based on service response times
3. **Fallback Strategy**: Always implement fallback mechanisms for critical services
4. **Monitoring**: Monitor circuit breaker states and statistics
5. **Testing**: Test circuit breaker behavior in different scenarios
6. **Documentation**: Document circuit breaker configurations and policies
7. **Gradual Rollout**: Gradually increase circuit breaker coverage
8. **Alerting**: Set up alerts for circuit breaker state changes
9. **Recovery**: Have recovery procedures for when circuits are open
10. **Performance**: Monitor the performance impact of circuit breakers

## Contributing

Contributions are welcome! Please read the contributing guidelines and submit pull requests for any improvements.

## License

This library is licensed under the MIT License. See the LICENSE file for details.
