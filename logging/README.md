# Logging Library

The Logging library provides a unified interface for logging operations across multiple providers including console, file, and Elasticsearch. It offers comprehensive logging capabilities with structured logging, multiple log levels, batch operations, search functionality, and advanced features like filtering, aggregation, and real-time monitoring.

## Features

- **Multi-Provider Support**: Console, file, Elasticsearch, and more
- **Structured Logging**: JSON and text format support with rich metadata
- **Multiple Log Levels**: Trace, Debug, Info, Warn, Error, Fatal, Panic
- **Context Logging**: Context-aware logging with request tracing
- **Batch Operations**: Efficient batch logging for high-throughput scenarios
- **Search and Query**: Advanced log search and filtering capabilities
- **Real-time Monitoring**: Live log streaming and monitoring
- **Retention Management**: Configurable log retention policies
- **Compression**: Built-in log compression for storage efficiency
- **Health Monitoring**: Provider health checks and statistics

## Supported Providers

- **Console**: Standard console output logging
- **File**: File-based logging with rotation
- **Elasticsearch**: Elasticsearch integration for log aggregation
- **Custom**: Custom logging providers

## Installation

```bash
go get github.com/anasamu/go-micro-libs/logging
```

## Quick Start

```go
package main

import (
    "context"
    "fmt"
    "log"
    "time"

    "github.com/anasamu/go-micro-libs/logging"
    "github.com/anasamu/go-micro-libs/logging/types"
    "github.com/sirupsen/logrus"
)

func main() {
    // Create logger
    logger := logrus.New()

    // Create logging manager with default config
    config := &logging.ManagerConfig{
        DefaultProvider: "console",
        RetryAttempts:   3,
        RetryDelay:      time.Second,
        Timeout:         30 * time.Second,
        FallbackEnabled: true,
    }
    
    manager := logging.NewLoggingManager(config, logger)

    // Register console provider (example)
    // consoleProvider := console.NewConsoleProvider()
    // manager.RegisterProvider(consoleProvider)

    // Log a message
    ctx := context.Background()
    err := manager.Info(ctx, "Application started successfully", map[string]interface{}{
        "version": "1.0.0",
        "port":    8080,
        "env":     "production",
    })
    
    if err != nil {
        log.Fatal(err)
    }

    fmt.Println("Log message sent successfully")
}
```

## API Reference

### LoggingManager

The main manager for handling logging operations across multiple providers.

#### Methods

##### `NewLoggingManager(config *ManagerConfig, logger *logrus.Logger) *LoggingManager`
Creates a new logging manager with the given configuration and logger.

##### `RegisterProvider(provider types.LoggingProvider) error`
Registers a new logging provider.

**Parameters:**
- `provider`: The logging provider to register

**Returns:**
- `error`: Any error that occurred during registration

##### `GetProvider(name string) (types.LoggingProvider, error)`
Retrieves a specific provider by name.

##### `GetDefaultProvider() (types.LoggingProvider, error)`
Returns the default logging provider.

##### `Log(ctx context.Context, level types.LogLevel, message string, fields map[string]interface{}) error`
Logs a message using the default provider.

**Parameters:**
- `ctx`: Context for cancellation and timeouts
- `level`: Log level (Trace, Debug, Info, Warn, Error, Fatal, Panic)
- `message`: Log message
- `fields`: Additional structured fields

**Returns:**
- `error`: Any error that occurred

##### `LogWithProvider(ctx context.Context, providerName string, level types.LogLevel, message string, fields map[string]interface{}) error`
Logs a message using a specific provider.

##### `LogWithContext(ctx context.Context, level types.LogLevel, message string, fields map[string]interface{}) error`
Logs a message with context using the default provider.

##### `LogWithContextAndProvider(ctx context.Context, providerName string, level types.LogLevel, message string, fields map[string]interface{}) error`
Logs a message with context using a specific provider.

##### `Info(ctx context.Context, message string, fields ...map[string]interface{}) error`
Logs an info level message using the default provider.

##### `Debug(ctx context.Context, message string, fields ...map[string]interface{}) error`
Logs a debug level message using the default provider.

##### `Warn(ctx context.Context, message string, fields ...map[string]interface{}) error`
Logs a warning level message using the default provider.

##### `Error(ctx context.Context, message string, fields ...map[string]interface{}) error`
Logs an error level message using the default provider.

##### `Fatal(ctx context.Context, message string, fields ...map[string]interface{}) error`
Logs a fatal level message using the default provider.

##### `Panic(ctx context.Context, message string, fields ...map[string]interface{}) error`
Logs a panic level message using the default provider.

##### `Infof(ctx context.Context, format string, args ...interface{}) error`
Logs a formatted info level message using the default provider.

##### `Debugf(ctx context.Context, format string, args ...interface{}) error`
Logs a formatted debug level message using the default provider.

##### `Warnf(ctx context.Context, format string, args ...interface{}) error`
Logs a formatted warning level message using the default provider.

##### `Errorf(ctx context.Context, format string, args ...interface{}) error`
Logs a formatted error level message using the default provider.

##### `Fatalf(ctx context.Context, format string, args ...interface{}) error`
Logs a formatted fatal level message using the default provider.

##### `Panicf(ctx context.Context, format string, args ...interface{}) error`
Logs a formatted panic level message using the default provider.

##### `LogBatch(ctx context.Context, entries []types.LogEntry) error`
Logs multiple entries using the default provider.

##### `Search(ctx context.Context, query types.LogQuery) ([]types.LogEntry, error)`
Searches logs using the default provider.

##### `GetStats(ctx context.Context) (map[string]*types.LoggingStats, error)`
Returns logging statistics from all providers.

##### `Close() error`
Closes all providers and cleans up resources.

### Types

#### ManagerConfig
Configuration for the logging manager.

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

#### LogLevel
Represents the logging level.

```go
type LogLevel string

const (
    LevelTrace LogLevel = "trace"
    LevelDebug LogLevel = "debug"
    LevelInfo  LogLevel = "info"
    LevelWarn  LogLevel = "warn"
    LevelError LogLevel = "error"
    LevelFatal LogLevel = "fatal"
    LevelPanic LogLevel = "panic"
)
```

#### LogEntry
Represents a structured log entry.

```go
type LogEntry struct {
    Timestamp  time.Time              `json:"timestamp"`
    Level      LogLevel               `json:"level"`
    Message    string                 `json:"message"`
    Service    string                 `json:"service"`
    Version    string                 `json:"version"`
    TraceID    string                 `json:"trace_id,omitempty"`
    SpanID     string                 `json:"span_id,omitempty"`
    UserID     string                 `json:"user_id,omitempty"`
    TenantID   string                 `json:"tenant_id,omitempty"`
    RequestID  string                 `json:"request_id,omitempty"`
    IPAddress  string                 `json:"ip_address,omitempty"`
    UserAgent  string                 `json:"user_agent,omitempty"`
    Method     string                 `json:"method,omitempty"`
    Path       string                 `json:"path,omitempty"`
    StatusCode int                    `json:"status_code,omitempty"`
    Duration   int64                  `json:"duration,omitempty"`
    Error      string                 `json:"error,omitempty"`
    Fields     map[string]interface{} `json:"fields,omitempty"`
    Provider   string                 `json:"provider"`
}
```

#### LogQuery
Represents a log search query.

```go
type LogQuery struct {
    Levels    []LogLevel             `json:"levels,omitempty"`
    Services  []string               `json:"services,omitempty"`
    StartTime *time.Time             `json:"start_time,omitempty"`
    EndTime   *time.Time             `json:"end_time,omitempty"`
    Message   string                 `json:"message,omitempty"`
    Fields    map[string]interface{} `json:"fields,omitempty"`
    Limit     int                    `json:"limit,omitempty"`
    Offset    int                    `json:"offset,omitempty"`
    SortBy    string                 `json:"sort_by,omitempty"`
    SortOrder string                 `json:"sort_order,omitempty"`
}
```

#### LoggingStats
Logging statistics.

```go
type LoggingStats struct {
    TotalLogs     int64              `json:"total_logs"`
    LogsByLevel   map[LogLevel]int64 `json:"logs_by_level"`
    LogsByService map[string]int64   `json:"logs_by_service"`
    StorageSize   int64              `json:"storage_size"`
    Uptime        time.Duration      `json:"uptime"`
    LastUpdate    time.Time          `json:"last_update"`
    Provider      string             `json:"provider"`
}
```

## Advanced Usage

### Basic Logging

```go
// Log with different levels
err := manager.Info(ctx, "User logged in", map[string]interface{}{
    "user_id": "123",
    "ip":      "192.168.1.100",
})

err = manager.Warn(ctx, "High memory usage detected", map[string]interface{}{
    "memory_usage": "85%",
    "threshold":    "80%",
})

err = manager.Error(ctx, "Database connection failed", map[string]interface{}{
    "error":        "connection timeout",
    "retry_count":  3,
    "database":     "postgresql",
})

// Formatted logging
err = manager.Infof(ctx, "Processing request %d for user %s", requestID, userID)
err = manager.Errorf(ctx, "Failed to process request %d: %v", requestID, err)
```

### Structured Logging with Context

```go
// Log with request context
ctx = context.WithValue(ctx, "request_id", "req-123")
ctx = context.WithValue(ctx, "user_id", "user-456")
ctx = context.WithValue(ctx, "tenant_id", "tenant-789")

err := manager.LogWithContext(ctx, types.LevelInfo, "Processing payment", map[string]interface{}{
    "amount":     99.99,
    "currency":   "USD",
    "payment_method": "credit_card",
})
```

### Batch Logging

```go
// Log multiple entries at once
entries := []types.LogEntry{
    {
        Timestamp: time.Now(),
        Level:     types.LevelInfo,
        Message:   "User action performed",
        Service:   "user-service",
        Fields: map[string]interface{}{
            "action": "profile_update",
            "user_id": "123",
        },
    },
    {
        Timestamp: time.Now(),
        Level:     types.LevelInfo,
        Message:   "Email sent",
        Service:   "email-service",
        Fields: map[string]interface{}{
            "recipient": "user@example.com",
            "template":  "welcome",
        },
    },
}

err := manager.LogBatch(ctx, entries)
```

### Log Search and Query

```go
// Search logs by level
query := types.LogQuery{
    Levels: []types.LogLevel{types.LevelError, types.LevelFatal},
    Limit:  100,
}

results, err := manager.Search(ctx, query)
if err != nil {
    log.Fatal(err)
}

for _, entry := range results {
    fmt.Printf("[%s] %s: %s\n", entry.Level, entry.Timestamp.Format(time.RFC3339), entry.Message)
}

// Search logs by service and time range
startTime := time.Now().Add(-24 * time.Hour)
endTime := time.Now()

query = types.LogQuery{
    Services:  []string{"user-service", "payment-service"},
    StartTime: &startTime,
    EndTime:   &endTime,
    Message:   "error",
    Limit:     50,
}

results, err = manager.Search(ctx, query)

// Search logs by custom fields
query = types.LogQuery{
    Fields: map[string]interface{}{
        "user_id": "123",
        "action":  "login",
    },
    SortBy:    "timestamp",
    SortOrder: "desc",
    Limit:     10,
}

results, err = manager.Search(ctx, query)
```

### HTTP Request Logging

```go
func logHTTPRequest(manager *logging.LoggingManager, r *http.Request, statusCode int, duration time.Duration) {
    ctx := context.Background()
    
    fields := map[string]interface{}{
        "method":      r.Method,
        "path":        r.URL.Path,
        "status_code": statusCode,
        "duration":    duration.Milliseconds(),
        "user_agent":  r.UserAgent(),
        "ip_address":  getClientIP(r),
    }
    
    // Add user ID if available
    if userID := r.Header.Get("X-User-ID"); userID != "" {
        fields["user_id"] = userID
    }
    
    // Add request ID if available
    if requestID := r.Header.Get("X-Request-ID"); requestID != "" {
        fields["request_id"] = requestID
    }
    
    level := types.LevelInfo
    if statusCode >= 400 {
        level = types.LevelWarn
    }
    if statusCode >= 500 {
        level = types.LevelError
    }
    
    manager.LogWithProvider(ctx, "console", level, "HTTP request processed", fields)
}
```

### Error Logging with Stack Traces

```go
func logError(manager *logging.LoggingManager, err error, context map[string]interface{}) {
    ctx := context.Background()
    
    fields := map[string]interface{}{
        "error": err.Error(),
    }
    
    // Add stack trace if available
    if stack := getStackTrace(err); stack != "" {
        fields["stack_trace"] = stack
    }
    
    // Merge additional context
    for key, value := range context {
        fields[key] = value
    }
    
    manager.Error(ctx, "Application error occurred", fields)
}

func getStackTrace(err error) string {
    // Implementation to get stack trace
    return ""
}
```

### Performance Logging

```go
func logPerformance(manager *logging.LoggingManager, operation string, duration time.Duration, metadata map[string]interface{}) {
    ctx := context.Background()
    
    fields := map[string]interface{}{
        "operation": operation,
        "duration":  duration.Milliseconds(),
        "duration_ns": duration.Nanoseconds(),
    }
    
    // Add performance metadata
    for key, value := range metadata {
        fields[key] = value
    }
    
    level := types.LevelInfo
    if duration > 1*time.Second {
        level = types.LevelWarn
    }
    if duration > 5*time.Second {
        level = types.LevelError
    }
    
    manager.LogWithProvider(ctx, "console", level, "Performance measurement", fields)
}
```

### Business Event Logging

```go
func logBusinessEvent(manager *logging.LoggingManager, event string, userID string, data map[string]interface{}) {
    ctx := context.Background()
    
    fields := map[string]interface{}{
        "event_type": "business_event",
        "event":      event,
        "user_id":    userID,
        "timestamp":  time.Now().Unix(),
    }
    
    // Add event-specific data
    for key, value := range data {
        fields[key] = value
    }
    
    manager.Info(ctx, fmt.Sprintf("Business event: %s", event), fields)
}

// Usage
logBusinessEvent(manager, "user_registration", "user-123", map[string]interface{}{
    "email":      "user@example.com",
    "source":     "web",
    "campaign":   "summer-2024",
    "referral":   "friend-456",
})
```

### Audit Logging

```go
func logAuditEvent(manager *logging.LoggingManager, action string, resource string, userID string, details map[string]interface{}) {
    ctx := context.Background()
    
    fields := map[string]interface{}{
        "audit_type": "security_event",
        "action":     action,
        "resource":   resource,
        "user_id":    userID,
        "timestamp":  time.Now().Unix(),
        "ip_address": getCurrentIP(),
        "user_agent": getUserAgent(),
    }
    
    // Add audit details
    for key, value := range details {
        fields[key] = value
    }
    
    manager.Info(ctx, fmt.Sprintf("Audit: %s on %s", action, resource), fields)
}

// Usage
logAuditEvent(manager, "login", "user_account", "user-123", map[string]interface{}{
    "success":     true,
    "method":      "password",
    "session_id":  "sess-789",
})
```

### Log Statistics and Monitoring

```go
// Get logging statistics
stats, err := manager.GetStats(ctx)
if err != nil {
    log.Fatal(err)
}

for provider, stat := range stats {
    fmt.Printf("Provider: %s\n", provider)
    fmt.Printf("  Total logs: %d\n", stat.TotalLogs)
    fmt.Printf("  Storage size: %d bytes\n", stat.StorageSize)
    fmt.Printf("  Uptime: %v\n", stat.Uptime)
    
    fmt.Println("  Logs by level:")
    for level, count := range stat.LogsByLevel {
        fmt.Printf("    %s: %d\n", level, count)
    }
    
    fmt.Println("  Logs by service:")
    for service, count := range stat.LogsByService {
        fmt.Printf("    %s: %d\n", service, count)
    }
}
```

### Provider-Specific Operations

```go
// Log to specific provider
err := manager.InfoWithProvider(ctx, "elasticsearch", "Indexing document", map[string]interface{}{
    "document_id": "doc-123",
    "index":       "products",
})

err = manager.ErrorWithProvider(ctx, "file", "File operation failed", map[string]interface{}{
    "file_path": "/data/important.txt",
    "operation": "read",
})

// Use different providers for different log levels
err = manager.DebugWithProvider(ctx, "console", "Debug information", map[string]interface{}{
    "variable": "value",
})

err = manager.ErrorWithProvider(ctx, "elasticsearch", "Application error", map[string]interface{}{
    "error": "database connection failed",
})
```

### Log Rotation and Retention

```go
// Configure log retention
config := &logging.ManagerConfig{
    DefaultProvider: "file",
    RetryAttempts:   3,
    RetryDelay:      time.Second,
    Timeout:         30 * time.Second,
    FallbackEnabled: true,
    Metadata: map[string]string{
        "retention_days": "30",
        "max_file_size":  "100MB",
        "max_files":      "10",
        "compress":       "true",
    },
}

manager := logging.NewLoggingManager(config, logger)
```

### Error Handling

```go
err := manager.Info(ctx, "Log message", map[string]interface{}{
    "key": "value",
})
if err != nil {
    // Handle different types of errors
    switch {
    case strings.Contains(err.Error(), "connection"):
        log.Printf("Logging provider connection error: %v", err)
    case strings.Contains(err.Error(), "timeout"):
        log.Printf("Logging operation timeout: %v", err)
    case strings.Contains(err.Error(), "quota"):
        log.Printf("Logging quota exceeded: %v", err)
    default:
        log.Printf("Logging operation failed: %v", err)
    }
}
```

## Best Practices

1. **Structured Logging**: Use structured logging with consistent field names
2. **Log Levels**: Use appropriate log levels for different types of messages
3. **Context**: Include relevant context in log messages
4. **Performance**: Use batch logging for high-throughput scenarios
5. **Security**: Avoid logging sensitive information like passwords or tokens
6. **Retention**: Implement appropriate log retention policies
7. **Monitoring**: Monitor log volume and storage usage
8. **Search**: Design log messages for easy searching and filtering
9. **Error Handling**: Implement proper error handling for logging operations
10. **Testing**: Test logging in different scenarios and environments

## Contributing

Contributions are welcome! Please read the contributing guidelines and submit pull requests for any improvements.

## License

This library is licensed under the MIT License. See the LICENSE file for details.
