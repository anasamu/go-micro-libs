# Failover Library

The Failover library provides a unified interface for failover operations across multiple providers including Consul and Kubernetes. It offers comprehensive failover capabilities with support for endpoint management, health checking, automatic failover, load balancing, and advanced features like circuit breaking, retry policies, and comprehensive monitoring.

## Features

- **Multi-Provider Support**: Consul, Kubernetes providers
- **Endpoint Management**: Register, update, and manage service endpoints
- **Health Checking**: Comprehensive health check capabilities
- **Automatic Failover**: Intelligent failover with configurable strategies
- **Load Balancing**: Multiple load balancing algorithms
- **Circuit Breaking**: Circuit breaker pattern implementation
- **Retry Policies**: Configurable retry mechanisms
- **Service Discovery**: Integration with service discovery systems
- **Monitoring**: Comprehensive statistics and event tracking
- **Configuration Management**: Dynamic configuration updates
- **High Availability**: Built-in high availability features

## Supported Providers

- **Consul**: HashiCorp Consul for service discovery and health checking
- **Kubernetes**: Kubernetes for container orchestration and service management
- **Custom**: Custom failover providers

## Installation

```bash
go get github.com/anasamu/go-micro-libs/failover
```

## Quick Start

```go
package main

import (
    "context"
    "fmt"
    "log"
    "time"

    "github.com/anasamu/go-micro-libs/failover"
    "github.com/anasamu/go-micro-libs/failover/types"
    "github.com/sirupsen/logrus"
)

func main() {
    // Create logger
    logger := logrus.New()
    logger.SetLevel(logrus.InfoLevel)

    // Create failover manager
    config := &failover.ManagerConfig{
        DefaultProvider: "consul",
        RetryAttempts:   3,
        RetryDelay:      time.Second,
        Timeout:         30 * time.Second,
        FallbackEnabled: true,
    }

    manager := failover.NewFailoverManager(config, logger)

    // Register providers (example with Consul)
    // consulProvider := consul.NewProvider(consulConfig)
    // manager.RegisterProvider(consulProvider)

    ctx := context.Background()

    // Register service endpoints
    endpoint1 := &types.ServiceEndpoint{
        ID:          "service-1",
        Name:        "user-service",
        Address:     "192.168.1.10",
        Port:        8080,
        Protocol:    "http",
        HealthCheck: &types.HealthCheck{
            Path:     "/health",
            Interval: 30 * time.Second,
            Timeout:  5 * time.Second,
        },
        Metadata: map[string]string{
            "version": "1.0.0",
            "region":  "us-east-1",
        },
        Tags: []string{"api", "user"},
    }

    if err := manager.RegisterEndpoint(ctx, endpoint1); err != nil {
        log.Fatalf("Failed to register endpoint: %v", err)
    }

    endpoint2 := &types.ServiceEndpoint{
        ID:          "service-2",
        Name:        "user-service",
        Address:     "192.168.1.11",
        Port:        8080,
        Protocol:    "http",
        HealthCheck: &types.HealthCheck{
            Path:     "/health",
            Interval: 30 * time.Second,
            Timeout:  5 * time.Second,
        },
        Metadata: map[string]string{
            "version": "1.0.0",
            "region":  "us-east-1",
        },
        Tags: []string{"api", "user"},
    }

    if err := manager.RegisterEndpoint(ctx, endpoint2); err != nil {
        log.Fatalf("Failed to register endpoint: %v", err)
    }

    // Configure failover
    failoverConfig := &types.FailoverConfig{
        Strategy:        types.StrategyRoundRobin,
        HealthCheck:     true,
        MaxRetries:      3,
        RetryDelay:      time.Second,
        CircuitBreaker: &types.CircuitBreakerConfig{
            FailureThreshold: 5,
            RecoveryTimeout:  30 * time.Second,
            HalfOpenMaxCalls: 3,
        },
        LoadBalancer: &types.LoadBalancerConfig{
            Algorithm: types.LoadBalancerRoundRobin,
            Weights:   map[string]int{"service-1": 1, "service-2": 1},
        },
    }

    if err := manager.Configure(ctx, failoverConfig); err != nil {
        log.Fatalf("Failed to configure failover: %v", err)
    }

    // Select endpoint with failover
    result, err := manager.SelectEndpoint(ctx, failoverConfig)
    if err != nil {
        log.Fatalf("Failed to select endpoint: %v", err)
    }

    fmt.Printf("Selected endpoint: %s (%s:%d)\n", 
        result.Endpoint.ID, result.Endpoint.Address, result.Endpoint.Port)

    // Execute with failover
    executeResult, err := manager.ExecuteWithFailover(ctx, failoverConfig, 
        func(endpoint *types.ServiceEndpoint) (interface{}, error) {
            // Simulate API call
            fmt.Printf("Calling API on %s:%d\n", endpoint.Address, endpoint.Port)
            return "success", nil
        })
    if err != nil {
        log.Fatalf("Failed to execute with failover: %v", err)
    }

    fmt.Printf("Execution result: %v\n", executeResult.Result)

    // Health check all endpoints
    healthStatus, err := manager.HealthCheckAll(ctx)
    if err != nil {
        log.Fatalf("Failed to check health: %v", err)
    }

    for endpointID, status := range healthStatus {
        fmt.Printf("Endpoint %s: %s\n", endpointID, status)
    }

    // Get statistics
    stats, err := manager.GetStats(ctx)
    if err != nil {
        log.Fatalf("Failed to get stats: %v", err)
    }

    for provider, stat := range stats {
        fmt.Printf("Provider %s: %+v\n", provider, stat)
    }

    // Close manager
    if err := manager.Close(); err != nil {
        log.Printf("Error closing manager: %v", err)
    }
}
```

## Configuration

### Manager Configuration

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

### Failover Configuration

```go
type FailoverConfig struct {
    Strategy        FailoverStrategy        `json:"strategy"`
    HealthCheck     bool                    `json:"health_check"`
    MaxRetries      int                     `json:"max_retries"`
    RetryDelay      time.Duration           `json:"retry_delay"`
    CircuitBreaker  *CircuitBreakerConfig   `json:"circuit_breaker"`
    LoadBalancer    *LoadBalancerConfig     `json:"load_balancer"`
    Timeout         time.Duration           `json:"timeout"`
    Metadata        map[string]interface{}  `json:"metadata"`
}
```

### Circuit Breaker Configuration

```go
type CircuitBreakerConfig struct {
    FailureThreshold int           `json:"failure_threshold"`
    RecoveryTimeout  time.Duration `json:"recovery_timeout"`
    HalfOpenMaxCalls int           `json:"half_open_max_calls"`
    SuccessThreshold int           `json:"success_threshold"`
}
```

### Load Balancer Configuration

```go
type LoadBalancerConfig struct {
    Algorithm LoadBalancerAlgorithm `json:"algorithm"`
    Weights   map[string]int        `json:"weights"`
    Sticky    bool                  `json:"sticky"`
}
```

## API Reference

### Endpoint Management
- `RegisterEndpoint(ctx, endpoint)` - Register a service endpoint
- `DeregisterEndpoint(ctx, endpointID)` - Deregister an endpoint
- `UpdateEndpoint(ctx, endpoint)` - Update endpoint information
- `GetEndpoint(ctx, endpointID)` - Get endpoint information
- `ListEndpoints(ctx)` - List all registered endpoints

### Failover Operations
- `SelectEndpoint(ctx, config)` - Select an endpoint with failover
- `ExecuteWithFailover(ctx, config, fn)` - Execute function with failover
- `Configure(ctx, config)` - Configure failover settings
- `GetConfig(ctx)` - Get current configuration

### Health Checking
- `HealthCheck(ctx, endpointID)` - Check health of specific endpoint
- `HealthCheckAll(ctx)` - Check health of all endpoints

### Provider Management
- `RegisterProvider(provider)` - Register a new provider
- `GetProvider(name)` - Get a specific provider
- `GetDefaultProvider()` - Get the default provider
- `ListProviders()` - List all registered providers
- `GetProviderInfo()` - Get provider information

### Monitoring and Statistics
- `GetStats(ctx)` - Get statistics from all providers
- `GetEvents(ctx, limit)` - Get failover events
- `Close()` - Close all providers

## Service Endpoint Structure

```go
type ServiceEndpoint struct {
    ID          string            `json:"id"`
    Name        string            `json:"name"`
    Address     string            `json:"address"`
    Port        int               `json:"port"`
    Protocol    string            `json:"protocol"`
    HealthCheck *HealthCheck      `json:"health_check"`
    Metadata    map[string]string `json:"metadata"`
    Tags        []string          `json:"tags"`
    Weight      int               `json:"weight"`
    Priority    int               `json:"priority"`
    CreatedAt   time.Time         `json:"created_at"`
    UpdatedAt   time.Time         `json:"updated_at"`
}
```

## Health Check Structure

```go
type HealthCheck struct {
    Path     string        `json:"path"`
    Interval time.Duration `json:"interval"`
    Timeout  time.Duration `json:"timeout"`
    Method   string        `json:"method"`
    Headers  map[string]string `json:"headers"`
    Body     string        `json:"body"`
}
```

## Failover Result Structure

```go
type FailoverResult struct {
    Endpoint     *ServiceEndpoint `json:"endpoint"`
    Result       interface{}      `json:"result"`
    Attempts     int              `json:"attempts"`
    Duration     time.Duration    `json:"duration"`
    Success      bool             `json:"success"`
    Error        string           `json:"error,omitempty"`
    Metadata     map[string]interface{} `json:"metadata"`
}
```

## Failover Strategies

### Available Strategies
- `StrategyRoundRobin` - Round-robin selection
- `StrategyRandom` - Random selection
- `StrategyWeighted` - Weighted selection
- `StrategyLeastConnections` - Least connections selection
- `StrategyHealthBased` - Health-based selection
- `StrategyGeographic` - Geographic selection

### Load Balancer Algorithms
- `LoadBalancerRoundRobin` - Round-robin algorithm
- `LoadBalancerRandom` - Random algorithm
- `LoadBalancerWeighted` - Weighted algorithm
- `LoadBalancerLeastConnections` - Least connections algorithm
- `LoadBalancerIPHash` - IP hash algorithm

## Health Status

```go
type HealthStatus int

const (
    HealthUnknown HealthStatus = iota
    HealthHealthy
    HealthUnhealthy
    HealthDegraded
)
```

## Error Handling

The library provides comprehensive error handling with specific error types:

```go
type FailoverError struct {
    Type    ErrorType `json:"type"`
    Message string    `json:"message"`
    Code    int       `json:"code"`
    Details map[string]interface{} `json:"details"`
}
```

### Error Types
- `ErrorTypeConnection` - Connection-related errors
- `ErrorTypeValidation` - Validation errors
- `ErrorTypeNotFound` - Resource not found errors
- `ErrorTypeTimeout` - Timeout errors
- `ErrorTypeCircuitBreaker` - Circuit breaker errors
- `ErrorTypeInternal` - Internal server errors

## Best Practices

### Endpoint Management
1. **Consistent Naming**: Use consistent naming conventions for endpoints
2. **Health Checks**: Implement proper health check endpoints
3. **Metadata**: Include relevant metadata for endpoint identification
4. **Tags**: Use tags for endpoint categorization

### Failover Configuration
1. **Strategy Selection**: Choose appropriate failover strategies
2. **Circuit Breakers**: Configure circuit breakers for fault tolerance
3. **Retry Policies**: Implement appropriate retry policies
4. **Timeouts**: Set reasonable timeout values

### Monitoring
1. **Health Checks**: Regular health checks for all endpoints
2. **Statistics**: Monitor failover statistics and performance
3. **Events**: Track failover events for debugging
4. **Alerting**: Set up alerts for critical failures

## Examples

### Microservice Load Balancing

```go
// Configure load balancing for microservices
config := &types.FailoverConfig{
    Strategy: types.StrategyRoundRobin,
    HealthCheck: true,
    LoadBalancer: &types.LoadBalancerConfig{
        Algorithm: types.LoadBalancerWeighted,
        Weights: map[string]int{
            "api-server-1": 3,
            "api-server-2": 2,
            "api-server-3": 1,
        },
    },
}

// Execute API calls with load balancing
result, err := manager.ExecuteWithFailover(ctx, config, 
    func(endpoint *types.ServiceEndpoint) (interface{}, error) {
        // Make HTTP request to endpoint
        return makeHTTPRequest(endpoint)
    })
```

### Database Failover

```go
// Configure database failover
config := &types.FailoverConfig{
    Strategy: types.StrategyHealthBased,
    CircuitBreaker: &types.CircuitBreakerConfig{
        FailureThreshold: 3,
        RecoveryTimeout:  60 * time.Second,
    },
    MaxRetries: 2,
    RetryDelay: 5 * time.Second,
}

// Execute database operations with failover
result, err := manager.ExecuteWithFailover(ctx, config, 
    func(endpoint *types.ServiceEndpoint) (interface{}, error) {
        // Execute database query
        return executeDatabaseQuery(endpoint)
    })
```

### Service Discovery Integration

```go
// Register endpoints from service discovery
endpoints := discoverServices("user-service")
for _, endpoint := range endpoints {
    serviceEndpoint := &types.ServiceEndpoint{
        ID:       endpoint.ID,
        Name:     endpoint.Name,
        Address:  endpoint.Address,
        Port:     endpoint.Port,
        Protocol: "http",
        HealthCheck: &types.HealthCheck{
            Path:     "/health",
            Interval: 30 * time.Second,
        },
        Metadata: endpoint.Metadata,
        Tags:     endpoint.Tags,
    }
    
    manager.RegisterEndpoint(ctx, serviceEndpoint)
}
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Submit a pull request

## License

This library is licensed under the MIT License. See the LICENSE file for details.
