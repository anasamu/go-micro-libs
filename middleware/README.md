# Middleware Library

The Middleware library provides a unified interface for middleware operations across multiple providers including authentication, caching, circuit breaking, communication, failover, logging, messaging, monitoring, rate limiting, and storage. It offers comprehensive middleware capabilities with support for request/response processing, middleware chains, HTTP middleware, and advanced features like configuration management, health monitoring, and comprehensive statistics.

## Features

- **Multi-Provider Support**: Authentication, caching, circuit breaking, communication, failover, logging, messaging, monitoring, rate limiting, storage providers
- **Request/Response Processing**: Comprehensive request and response processing
- **Middleware Chains**: Chain multiple middleware components together
- **HTTP Middleware**: Native HTTP middleware support
- **Configuration Management**: Dynamic configuration updates
- **Health Monitoring**: Comprehensive health checks and monitoring
- **Statistics**: Detailed statistics and performance metrics
- **Error Handling**: Comprehensive error handling and reporting
- **Provider Management**: Flexible provider registration and management
- **Chain Management**: Create and manage middleware chains
- **HTTP Integration**: Seamless HTTP handler integration

## Supported Providers

- **Authentication**: JWT, OAuth, API key authentication
- **Caching**: Redis, Memcached, in-memory caching
- **Circuit Breaking**: Circuit breaker pattern implementation
- **Communication**: HTTP, gRPC, WebSocket communication
- **Failover**: Service failover and load balancing
- **Logging**: Structured logging with multiple backends
- **Messaging**: Message queue integration
- **Monitoring**: Performance and health monitoring
- **Rate Limiting**: Request rate limiting and throttling
- **Storage**: File and object storage integration
- **Custom**: Custom middleware providers

## Installation

```bash
go get github.com/anasamu/go-micro-libs/middleware
```

## Quick Start

```go
package main

import (
    "context"
    "fmt"
    "log"
    "net/http"
    "time"

    "github.com/anasamu/go-micro-libs/middleware"
    "github.com/anasamu/go-micro-libs/middleware/types"
    "github.com/sirupsen/logrus"
)

func main() {
    // Create logger
    logger := logrus.New()
    logger.SetLevel(logrus.InfoLevel)

    // Create middleware manager
    config := &middleware.ManagerConfig{
        DefaultProvider: "default",
        RetryAttempts:   3,
        RetryDelay:      5 * time.Second,
        Timeout:         30 * time.Second,
    }

    manager := middleware.NewMiddlewareManager(config, logger)

    // Register providers (example with authentication)
    // authProvider := auth.NewProvider(authConfig)
    // manager.RegisterProvider(authProvider)

    ctx := context.Background()

    // Create middleware configuration
    authConfig := &types.MiddlewareConfig{
        Name: "authentication",
        Type: "auth",
        Settings: map[string]interface{}{
            "jwt_secret": "your-secret-key",
            "required_claims": []string{"user_id", "role"},
            "token_header": "Authorization",
        },
    }

    // Create middleware chain
    chain, err := manager.CreateChain(ctx, "auth", authConfig)
    if err != nil {
        log.Fatalf("Failed to create middleware chain: %v", err)
    }

    fmt.Printf("Middleware chain created: %s\n", chain.Name)

    // Process request through middleware
    request := &types.MiddlewareRequest{
        ID:      "req-123",
        Type:    "http",
        Method:  "GET",
        Path:    "/api/users",
        Headers: map[string]string{
            "Authorization": "Bearer jwt-token",
            "Content-Type":  "application/json",
        },
        Body:    []byte(`{"user_id": "123"}`),
        Metadata: map[string]interface{}{
            "client_ip": "192.168.1.1",
            "user_agent": "Mozilla/5.0",
        },
    }

    response, err := manager.ProcessRequest(ctx, "auth", request)
    if err != nil {
        log.Fatalf("Failed to process request: %v", err)
    }

    fmt.Printf("Request processed successfully: %v\n", response.Success)
    fmt.Printf("Response status: %d\n", response.StatusCode)

    // Create HTTP middleware
    httpMiddleware, err := manager.CreateHTTPMiddleware("auth", authConfig)
    if err != nil {
        log.Fatalf("Failed to create HTTP middleware: %v", err)
    }

    // Create HTTP handler
    handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(http.StatusOK)
        w.Write([]byte("Hello, World!"))
    })

    // Wrap handler with middleware
    wrappedHandler, err := manager.WrapHTTPHandler("auth", handler, authConfig)
    if err != nil {
        log.Fatalf("Failed to wrap HTTP handler: %v", err)
    }

    // Set up HTTP server
    http.Handle("/api/", wrappedHandler)
    
    fmt.Println("HTTP server started on :8080")
    log.Fatal(http.ListenAndServe(":8080", nil))

    // Get statistics
    stats := manager.GetStats(ctx)
    for provider, stat := range stats {
        fmt.Printf("Provider %s: %+v\n", provider, stat)
    }

    // Health check
    healthResults := manager.HealthCheck(ctx)
    for provider, err := range healthResults {
        if err != nil {
            fmt.Printf("Provider %s health check failed: %v\n", provider, err)
        } else {
            fmt.Printf("Provider %s is healthy\n", provider)
        }
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
    Metadata        map[string]string `json:"metadata"`
}
```

### Middleware Configuration

```go
type MiddlewareConfig struct {
    Name     string                 `json:"name"`
    Type     string                 `json:"type"`
    Settings map[string]interface{} `json:"settings"`
    Metadata map[string]interface{} `json:"metadata"`
}
```

### Middleware Request Structure

```go
type MiddlewareRequest struct {
    ID       string                 `json:"id"`
    Type     string                 `json:"type"`
    Method   string                 `json:"method,omitempty"`
    Path     string                 `json:"path,omitempty"`
    Headers  map[string]string      `json:"headers,omitempty"`
    Body     []byte                 `json:"body,omitempty"`
    Metadata map[string]interface{} `json:"metadata,omitempty"`
}
```

### Middleware Response Structure

```go
type MiddlewareResponse struct {
    ID         string                 `json:"id"`
    Success    bool                   `json:"success"`
    StatusCode int                    `json:"status_code,omitempty"`
    Headers    map[string]string      `json:"headers,omitempty"`
    Body       []byte                 `json:"body,omitempty"`
    Metadata   map[string]interface{} `json:"metadata,omitempty"`
    Error      string                 `json:"error,omitempty"`
}
```

## API Reference

### Core Operations
- `ProcessRequest(ctx, providerName, request)` - Process request through middleware
- `ProcessResponse(ctx, providerName, response)` - Process response through middleware
- `CreateChain(ctx, providerName, config)` - Create middleware chain
- `ExecuteChain(ctx, providerName, chain, request)` - Execute middleware chain
- `GetChain(name)` - Get middleware chain by name

### HTTP Middleware
- `CreateHTTPMiddleware(providerName, config)` - Create HTTP middleware
- `WrapHTTPHandler(providerName, handler, config)` - Wrap HTTP handler with middleware

### Provider Management
- `RegisterProvider(provider)` - Register middleware provider
- `GetProvider(name)` - Get provider by name
- `GetDefaultProvider()` - Get default provider

### Monitoring and Health
- `GetStats(ctx)` - Get statistics from all providers
- `HealthCheck(ctx)` - Perform health checks
- `Close()` - Close all providers

## Middleware Types

### Authentication Middleware
```go
authConfig := &types.MiddlewareConfig{
    Name: "jwt-auth",
    Type: "auth",
    Settings: map[string]interface{}{
        "jwt_secret": "your-secret-key",
        "required_claims": []string{"user_id", "role"},
        "token_header": "Authorization",
        "token_prefix": "Bearer",
    },
}
```

### Caching Middleware
```go
cacheConfig := &types.MiddlewareConfig{
    Name: "redis-cache",
    Type: "cache",
    Settings: map[string]interface{}{
        "redis_url": "redis://localhost:6379",
        "ttl": 300, // 5 minutes
        "key_prefix": "api:",
    },
}
```

### Rate Limiting Middleware
```go
rateLimitConfig := &types.MiddlewareConfig{
    Name: "rate-limiter",
    Type: "ratelimit",
    Settings: map[string]interface{}{
        "requests_per_minute": 100,
        "burst_size": 10,
        "key_by": "ip", // or "user", "header"
    },
}
```

### Circuit Breaker Middleware
```go
circuitBreakerConfig := &types.MiddlewareConfig{
    Name: "circuit-breaker",
    Type: "circuitbreaker",
    Settings: map[string]interface{}{
        "failure_threshold": 5,
        "recovery_timeout": 30 * time.Second,
        "half_open_max_calls": 3,
    },
}
```

### Logging Middleware
```go
loggingConfig := &types.MiddlewareConfig{
    Name: "request-logger",
    Type: "logging",
    Settings: map[string]interface{}{
        "log_level": "info",
        "log_format": "json",
        "include_body": false,
        "include_headers": true,
    },
}
```

## Middleware Chain Structure

```go
type MiddlewareChain struct {
    Name        string                 `json:"name"`
    Type        string                 `json:"type"`
    Middlewares []MiddlewareConfig     `json:"middlewares"`
    Metadata    map[string]interface{} `json:"metadata"`
    CreatedAt   time.Time              `json:"created_at"`
    UpdatedAt   time.Time              `json:"updated_at"`
}
```

## HTTP Middleware Integration

### Basic HTTP Middleware
```go
// Create HTTP middleware
middleware, err := manager.CreateHTTPMiddleware("auth", authConfig)
if err != nil {
    log.Fatal(err)
}

// Use with HTTP handler
handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    w.Write([]byte("Hello, World!"))
})

wrappedHandler := middleware(handler)
http.Handle("/api/", wrappedHandler)
```

### Multiple Middleware Chain
```go
// Create multiple middleware configurations
authConfig := &types.MiddlewareConfig{
    Name: "auth",
    Type: "auth",
    Settings: map[string]interface{}{
        "jwt_secret": "secret",
    },
}

loggingConfig := &types.MiddlewareConfig{
    Name: "logging",
    Type: "logging",
    Settings: map[string]interface{}{
        "log_level": "info",
    },
}

rateLimitConfig := &types.MiddlewareConfig{
    Name: "rate-limit",
    Type: "ratelimit",
    Settings: map[string]interface{}{
        "requests_per_minute": 100,
    },
}

// Create middleware chain
chain, err := manager.CreateChain(ctx, "api-chain", &types.MiddlewareConfig{
    Name: "api-chain",
    Type: "chain",
    Settings: map[string]interface{}{
        "middlewares": []string{"rate-limit", "auth", "logging"},
    },
})
```

## Error Handling

The library provides comprehensive error handling with specific error types:

```go
type MiddlewareError struct {
    Type    ErrorType `json:"type"`
    Message string    `json:"message"`
    Code    int       `json:"code"`
    Details map[string]interface{} `json:"details"`
}
```

### Error Types
- `ErrorTypeValidation` - Validation errors
- `ErrorTypeAuthentication` - Authentication errors
- `ErrorTypeAuthorization` - Authorization errors
- `ErrorTypeRateLimit` - Rate limiting errors
- `ErrorTypeCircuitBreaker` - Circuit breaker errors
- `ErrorTypeInternal` - Internal server errors

## Best Practices

### Middleware Design
1. **Single Responsibility**: Each middleware should have a single responsibility
2. **Stateless**: Middleware should be stateless when possible
3. **Error Handling**: Implement proper error handling
4. **Performance**: Consider performance implications

### Chain Management
1. **Order Matters**: Order middleware carefully in chains
2. **Early Returns**: Use early returns for performance
3. **Error Propagation**: Handle errors appropriately
4. **Logging**: Include appropriate logging

### Configuration
1. **Environment Variables**: Use environment variables for configuration
2. **Validation**: Validate configuration on startup
3. **Defaults**: Provide sensible defaults
4. **Documentation**: Document configuration options

## Examples

### API Gateway with Multiple Middleware

```go
// Set up API gateway with multiple middleware
func setupAPIGateway(manager *middleware.MiddlewareManager) http.Handler {
    // Rate limiting middleware
    rateLimitConfig := &types.MiddlewareConfig{
        Name: "rate-limit",
        Type: "ratelimit",
        Settings: map[string]interface{}{
            "requests_per_minute": 1000,
            "burst_size": 100,
        },
    }

    // Authentication middleware
    authConfig := &types.MiddlewareConfig{
        Name: "auth",
        Type: "auth",
        Settings: map[string]interface{}{
            "jwt_secret": os.Getenv("JWT_SECRET"),
            "required_claims": []string{"user_id"},
        },
    }

    // Logging middleware
    loggingConfig := &types.MiddlewareConfig{
        Name: "logging",
        Type: "logging",
        Settings: map[string]interface{}{
            "log_level": "info",
            "log_format": "json",
        },
    }

    // Create middleware chain
    chain, err := manager.CreateChain(context.Background(), "api-gateway", &types.MiddlewareConfig{
        Name: "api-gateway",
        Type: "chain",
        Settings: map[string]interface{}{
            "middlewares": []string{"rate-limit", "auth", "logging"},
        },
    })
    if err != nil {
        log.Fatal(err)
    }

    // Create HTTP handler
    handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Your API logic here
        w.WriteHeader(http.StatusOK)
        w.Write([]byte("API Response"))
    })

    // Wrap with middleware
    wrappedHandler, err := manager.WrapHTTPHandler("api-gateway", handler, &types.MiddlewareConfig{
        Name: "api-gateway",
        Type: "chain",
    })
    if err != nil {
        log.Fatal(err)
    }

    return wrappedHandler
}
```

### Microservice Communication

```go
// Set up microservice communication middleware
func setupMicroserviceMiddleware(manager *middleware.MiddlewareManager) {
    // Circuit breaker for external services
    circuitBreakerConfig := &types.MiddlewareConfig{
        Name: "circuit-breaker",
        Type: "circuitbreaker",
        Settings: map[string]interface{}{
            "failure_threshold": 5,
            "recovery_timeout": 30 * time.Second,
        },
    }

    // Retry middleware
    retryConfig := &types.MiddlewareConfig{
        Name: "retry",
        Type: "retry",
        Settings: map[string]interface{}{
            "max_attempts": 3,
            "backoff": "exponential",
        },
    }

    // Timeout middleware
    timeoutConfig := &types.MiddlewareConfig{
        Name: "timeout",
        Type: "timeout",
        Settings: map[string]interface{}{
            "timeout": 30 * time.Second,
        },
    }

    // Create communication chain
    chain, err := manager.CreateChain(context.Background(), "microservice", &types.MiddlewareConfig{
        Name: "microservice",
        Type: "chain",
        Settings: map[string]interface{}{
            "middlewares": []string{"timeout", "retry", "circuit-breaker"},
        },
    })
    if err != nil {
        log.Fatal(err)
    }

    // Use chain for service calls
    request := &types.MiddlewareRequest{
        ID:   "service-call-123",
        Type: "grpc",
        Metadata: map[string]interface{}{
            "service": "user-service",
            "method":  "GetUser",
        },
    }

    response, err := manager.ExecuteChain(context.Background(), "microservice", chain, request)
    if err != nil {
        log.Printf("Service call failed: %v", err)
        return
    }

    fmt.Printf("Service call successful: %v\n", response.Success)
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
