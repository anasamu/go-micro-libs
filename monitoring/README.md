# Monitoring Library

The Monitoring library provides a unified interface for monitoring operations across multiple providers including Prometheus, Jaeger, and Elasticsearch. It offers comprehensive monitoring capabilities with metrics collection, distributed tracing, log aggregation, alerting, and advanced features like health checks, performance monitoring, and real-time dashboards.

## Features

- **Multi-Provider Support**: Prometheus, Jaeger, Elasticsearch, and more
- **Metrics Collection**: Custom metrics, counters, gauges, and histograms
- **Distributed Tracing**: End-to-end request tracing across services
- **Log Aggregation**: Centralized log collection and analysis
- **Alerting**: Real-time alerting and notification systems
- **Health Checks**: Service health monitoring and status reporting
- **Performance Monitoring**: Application performance metrics and profiling
- **Real-time Dashboards**: Live monitoring dashboards and visualizations
- **Batch Operations**: Efficient batch data submission
- **Sampling**: Configurable sampling rates for performance optimization

## Supported Providers

- **Prometheus**: Metrics collection and monitoring
- **Jaeger**: Distributed tracing
- **Elasticsearch**: Log aggregation and search
- **Custom**: Custom monitoring providers

## Installation

```bash
go get github.com/anasamu/go-micro-libs/monitoring
```

## Quick Start

```go
package main

import (
    "context"
    "fmt"
    "log"
    "time"

    "github.com/anasamu/go-micro-libs/monitoring"
    "github.com/anasamu/go-micro-libs/monitoring/types"
    "github.com/sirupsen/logrus"
)

func main() {
    // Create logger
    logger := logrus.New()

    // Create monitoring manager with default config
    config := monitoring.DefaultManagerConfig()
    manager := monitoring.NewMonitoringManager(config, logger)

    // Register Prometheus provider (example)
    // prometheusProvider := prometheus.NewPrometheusProvider("localhost:9090")
    // manager.RegisterProvider(prometheusProvider)

    // Submit metrics
    ctx := context.Background()
    metricReq := &types.MetricRequest{
        Metrics: []types.Metric{
            {
                Name:   "http_requests_total",
                Type:   "counter",
                Value:  1,
                Labels: map[string]string{
                    "method": "GET",
                    "path":   "/api/users",
                    "status": "200",
                },
            },
        },
    }

    err := manager.SubmitMetrics(ctx, "prometheus", metricReq)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Println("Metrics submitted successfully")
}
```

## API Reference

### MonitoringManager

The main manager for handling monitoring operations across multiple providers.

#### Methods

##### `NewMonitoringManager(config *ManagerConfig, logger *logrus.Logger) *MonitoringManager`
Creates a new monitoring manager with the given configuration and logger.

##### `RegisterProvider(provider MonitoringProvider) error`
Registers a new monitoring provider.

**Parameters:**
- `provider`: The monitoring provider to register

**Returns:**
- `error`: Any error that occurred during registration

##### `GetProvider(name string) (MonitoringProvider, error)`
Retrieves a specific provider by name.

##### `GetDefaultProvider() (MonitoringProvider, error)`
Returns the default monitoring provider.

##### `Connect(ctx context.Context, providerName string) error`
Connects to a monitoring system using the specified provider.

##### `Disconnect(ctx context.Context, providerName string) error`
Disconnects from a monitoring system using the specified provider.

##### `Ping(ctx context.Context, providerName string) error`
Pings a monitoring system to check connectivity.

##### `SubmitMetrics(ctx context.Context, providerName string, request *types.MetricRequest) error`
Submits metrics using the specified provider.

**Parameters:**
- `ctx`: Context for cancellation and timeouts
- `providerName`: Name of the provider to use
- `request`: Metric request with metrics data

**Returns:**
- `error`: Any error that occurred

##### `QueryMetrics(ctx context.Context, providerName string, request *types.QueryRequest) (*types.QueryResponse, error)`
Queries metrics using the specified provider.

##### `SubmitLogs(ctx context.Context, providerName string, request *types.LogRequest) error`
Submits logs using the specified provider.

##### `QueryLogs(ctx context.Context, providerName string, request *types.QueryRequest) (*types.QueryResponse, error)`
Queries logs using the specified provider.

##### `SubmitTraces(ctx context.Context, providerName string, request *types.TraceRequest) error`
Submits traces using the specified provider.

##### `QueryTraces(ctx context.Context, providerName string, request *types.QueryRequest) (*types.QueryResponse, error)`
Queries traces using the specified provider.

##### `SubmitAlerts(ctx context.Context, providerName string, request *types.AlertRequest) error`
Submits alerts using the specified provider.

##### `QueryAlerts(ctx context.Context, providerName string, request *types.QueryRequest) (*types.QueryResponse, error)`
Queries alerts using the specified provider.

##### `HealthCheck(ctx context.Context, providerName string, request *types.HealthCheckRequest) (*types.HealthCheckResponse, error)`
Performs health check using the specified provider.

##### `HealthCheckAll(ctx context.Context) map[string]*types.HealthCheckResponse`
Performs health check on all providers.

##### `GetStats(ctx context.Context, providerName string) (*types.MonitoringStats, error)`
Gets statistics from a specific provider.

##### `GetSupportedProviders() []string`
Returns a list of registered providers.

##### `GetProviderCapabilities(providerName string) ([]types.MonitoringFeature, *types.ConnectionInfo, error)`
Returns capabilities of a specific provider.

##### `IsProviderConnected(providerName string) bool`
Checks if a provider is connected.

##### `GetConnectedProviders() []string`
Returns a list of connected providers.

##### `Close() error`
Closes all monitoring connections.

### Types

#### ManagerConfig
Configuration for the monitoring manager.

```go
type ManagerConfig struct {
    DefaultProvider string            `json:"default_provider"`
    RetryAttempts   int               `json:"retry_attempts"`
    RetryDelay      time.Duration     `json:"retry_delay"`
    Timeout         time.Duration     `json:"timeout"`
    BatchSize       int               `json:"batch_size"`
    FlushInterval   time.Duration     `json:"flush_interval"`
    BufferSize      int               `json:"buffer_size"`
    SamplingRate    float64           `json:"sampling_rate"`
    EnableTracing   bool              `json:"enable_tracing"`
    EnableMetrics   bool              `json:"enable_metrics"`
    EnableLogging   bool              `json:"enable_logging"`
    EnableAlerting  bool              `json:"enable_alerting"`
    Metadata        map[string]string `json:"metadata"`
}
```

#### MetricRequest
Represents a metric submission request.

```go
type MetricRequest struct {
    Metrics []Metric `json:"metrics"`
}
```

#### Metric
Represents a single metric.

```go
type Metric struct {
    Name      string            `json:"name"`
    Type      string            `json:"type"` // counter, gauge, histogram, summary
    Value     float64           `json:"value"`
    Labels    map[string]string `json:"labels"`
    Timestamp time.Time         `json:"timestamp"`
}
```

#### LogRequest
Represents a log submission request.

```go
type LogRequest struct {
    Logs []LogEntry `json:"logs"`
}
```

#### LogEntry
Represents a log entry.

```go
type LogEntry struct {
    Level     string                 `json:"level"`
    Message   string                 `json:"message"`
    Timestamp time.Time              `json:"timestamp"`
    Service   string                 `json:"service"`
    Fields    map[string]interface{} `json:"fields"`
}
```

#### TraceRequest
Represents a trace submission request.

```go
type TraceRequest struct {
    Traces []Trace `json:"traces"`
}
```

#### Trace
Represents a distributed trace.

```go
type Trace struct {
    TraceID     string            `json:"trace_id"`
    SpanID      string            `json:"span_id"`
    ParentID    string            `json:"parent_id,omitempty"`
    ServiceName string            `json:"service_name"`
    Operation   string            `json:"operation"`
    StartTime   time.Time         `json:"start_time"`
    Duration    time.Duration     `json:"duration"`
    Tags        map[string]string `json:"tags"`
    Logs        []TraceLog        `json:"logs,omitempty"`
}
```

#### TraceLog
Represents a log entry within a trace.

```go
type TraceLog struct {
    Timestamp time.Time              `json:"timestamp"`
    Fields    map[string]interface{} `json:"fields"`
}
```

#### AlertRequest
Represents an alert submission request.

```go
type AlertRequest struct {
    Alerts []Alert `json:"alerts"`
}
```

#### Alert
Represents an alert.

```go
type Alert struct {
    Name      string                 `json:"name"`
    Severity  string                 `json:"severity"` // critical, warning, info
    Message   string                 `json:"message"`
    Timestamp time.Time              `json:"timestamp"`
    Labels    map[string]string      `json:"labels"`
    Metadata  map[string]interface{} `json:"metadata"`
}
```

#### HealthCheckRequest
Represents a health check request.

```go
type HealthCheckRequest struct {
    Service string        `json:"service"`
    Timeout time.Duration `json:"timeout"`
}
```

#### HealthCheckResponse
Represents a health check response.

```go
type HealthCheckResponse struct {
    Service   string                 `json:"service"`
    Status    string                 `json:"status"` // healthy, unhealthy, degraded
    Timestamp time.Time              `json:"timestamp"`
    Metadata  map[string]interface{} `json:"metadata"`
}
```

#### QueryRequest
Represents a query request.

```go
type QueryRequest struct {
    Query   string                 `json:"query"`
    Start   time.Time              `json:"start"`
    End     time.Time              `json:"end"`
    Step    time.Duration          `json:"step"`
    Options map[string]interface{} `json:"options"`
}
```

#### QueryResponse
Represents a query response.

```go
type QueryResponse struct {
    Data    interface{}            `json:"data"`
    Status  string                 `json:"status"`
    Error   string                 `json:"error,omitempty"`
    Metadata map[string]interface{} `json:"metadata"`
}
```

## Advanced Usage

### Metrics Collection

```go
// Submit counter metrics
metricReq := &types.MetricRequest{
    Metrics: []types.Metric{
        {
            Name:   "http_requests_total",
            Type:   "counter",
            Value:  1,
            Labels: map[string]string{
                "method": "GET",
                "path":   "/api/users",
                "status": "200",
            },
            Timestamp: time.Now(),
        },
    },
}

err := manager.SubmitMetrics(ctx, "prometheus", metricReq)

// Submit gauge metrics
metricReq = &types.MetricRequest{
    Metrics: []types.Metric{
        {
            Name:   "memory_usage_bytes",
            Type:   "gauge",
            Value:  1024 * 1024 * 100, // 100MB
            Labels: map[string]string{
                "service": "user-service",
                "instance": "instance-1",
            },
            Timestamp: time.Now(),
        },
    },
}

err = manager.SubmitMetrics(ctx, "prometheus", metricReq)

// Submit histogram metrics
metricReq = &types.MetricRequest{
    Metrics: []types.Metric{
        {
            Name:   "http_request_duration_seconds",
            Type:   "histogram",
            Value:  0.5, // 500ms
            Labels: map[string]string{
                "method": "POST",
                "path":   "/api/orders",
                "le":     "1.0", // bucket
            },
            Timestamp: time.Now(),
        },
    },
}

err = manager.SubmitMetrics(ctx, "prometheus", metricReq)
```

### Distributed Tracing

```go
// Create a trace
trace := types.Trace{
    TraceID:     "trace-123",
    SpanID:      "span-456",
    ServiceName: "user-service",
    Operation:   "get_user",
    StartTime:   time.Now(),
    Duration:    50 * time.Millisecond,
    Tags: map[string]string{
        "user_id": "123",
        "method":  "GET",
        "path":    "/api/users/123",
    },
    Logs: []types.TraceLog{
        {
            Timestamp: time.Now(),
            Fields: map[string]interface{}{
                "event": "user_found",
                "user_id": "123",
            },
        },
    },
}

traceReq := &types.TraceRequest{
    Traces: []types.Trace{trace},
}

err := manager.SubmitTraces(ctx, "jaeger", traceReq)

// Create child span
childTrace := types.Trace{
    TraceID:     "trace-123",
    SpanID:      "span-789",
    ParentID:    "span-456",
    ServiceName: "database-service",
    Operation:   "query_users",
    StartTime:   time.Now(),
    Duration:    20 * time.Millisecond,
    Tags: map[string]string{
        "query": "SELECT * FROM users WHERE id = ?",
        "rows":  "1",
    },
}

traceReq = &types.TraceRequest{
    Traces: []types.Trace{childTrace},
}

err = manager.SubmitTraces(ctx, "jaeger", traceReq)
```

### Log Aggregation

```go
// Submit structured logs
logReq := &types.LogRequest{
    Logs: []types.LogEntry{
        {
            Level:     "info",
            Message:   "User authentication successful",
            Timestamp: time.Now(),
            Service:   "auth-service",
            Fields: map[string]interface{}{
                "user_id":    "123",
                "ip_address": "192.168.1.100",
                "method":     "password",
            },
        },
        {
            Level:     "error",
            Message:   "Database connection failed",
            Timestamp: time.Now(),
            Service:   "user-service",
            Fields: map[string]interface{}{
                "error":      "connection timeout",
                "database":   "postgresql",
                "retry_count": 3,
            },
        },
    },
}

err := manager.SubmitLogs(ctx, "elasticsearch", logReq)
```

### Alerting

```go
// Submit alerts
alertReq := &types.AlertRequest{
    Alerts: []types.Alert{
        {
            Name:      "high_error_rate",
            Severity:  "critical",
            Message:   "Error rate exceeded threshold",
            Timestamp: time.Now(),
            Labels: map[string]string{
                "service": "user-service",
                "environment": "production",
            },
            Metadata: map[string]interface{}{
                "threshold": 0.05,
                "current_rate": 0.08,
                "duration": "5m",
            },
        },
        {
            Name:      "high_memory_usage",
            Severity:  "warning",
            Message:   "Memory usage is high",
            Timestamp: time.Now(),
            Labels: map[string]string{
                "service": "payment-service",
                "instance": "instance-1",
            },
            Metadata: map[string]interface{}{
                "usage_percent": 85,
                "threshold": 80,
            },
        },
    },
}

err := manager.SubmitAlerts(ctx, "prometheus", alertReq)
```

### Health Checks

```go
// Perform health check
healthReq := &types.HealthCheckRequest{
    Service: "user-service",
    Timeout: 5 * time.Second,
}

response, err := manager.HealthCheck(ctx, "prometheus", healthReq)
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Service: %s, Status: %s\n", response.Service, response.Status)

// Check health of all services
allHealth := manager.HealthCheckAll(ctx)
for service, health := range allHealth {
    fmt.Printf("Service: %s, Status: %s\n", service, health.Status)
    if health.Status != "healthy" {
        fmt.Printf("  Metadata: %+v\n", health.Metadata)
    }
}
```

### Querying Data

```go
// Query metrics
queryReq := &types.QueryRequest{
    Query: "rate(http_requests_total[5m])",
    Start: time.Now().Add(-1 * time.Hour),
    End:   time.Now(),
    Step:  1 * time.Minute,
}

response, err := manager.QueryMetrics(ctx, "prometheus", queryReq)
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Query result: %+v\n", response.Data)

// Query logs
logQueryReq := &types.QueryRequest{
    Query: "service:user-service AND level:error",
    Start: time.Now().Add(-24 * time.Hour),
    End:   time.Now(),
    Options: map[string]interface{}{
        "size": 100,
        "sort": "timestamp:desc",
    },
}

response, err = manager.QueryLogs(ctx, "elasticsearch", logQueryReq)

// Query traces
traceQueryReq := &types.QueryRequest{
    Query: "service_name:user-service AND operation:get_user",
    Start: time.Now().Add(-1 * time.Hour),
    End:   time.Now(),
    Options: map[string]interface{}{
        "limit": 50,
    },
}

response, err = manager.QueryTraces(ctx, "jaeger", traceQueryReq)
```

### HTTP Middleware for Monitoring

```go
func monitoringMiddleware(manager *monitoring.MonitoringManager) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            start := time.Now()
            
            // Create trace
            traceID := generateTraceID()
            spanID := generateSpanID()
            
            trace := types.Trace{
                TraceID:     traceID,
                SpanID:      spanID,
                ServiceName: "web-service",
                Operation:   fmt.Sprintf("%s %s", r.Method, r.URL.Path),
                StartTime:   start,
                Tags: map[string]string{
                    "http.method": r.Method,
                    "http.path":   r.URL.Path,
                    "http.user_agent": r.UserAgent(),
                },
            }
            
            // Wrap response writer to capture status code
            wrapped := &responseWriter{ResponseWriter: w, statusCode: 200}
            
            // Process request
            next.ServeHTTP(wrapped, r)
            
            // Calculate duration
            duration := time.Since(start)
            trace.Duration = duration
            
            // Add response tags
            trace.Tags["http.status_code"] = fmt.Sprintf("%d", wrapped.statusCode)
            trace.Tags["http.duration_ms"] = fmt.Sprintf("%.2f", float64(duration.Nanoseconds())/1e6)
            
            // Submit trace
            traceReq := &types.TraceRequest{
                Traces: []types.Trace{trace},
            }
            manager.SubmitTraces(context.Background(), "jaeger", traceReq)
            
            // Submit metrics
            metricReq := &types.MetricRequest{
                Metrics: []types.Metric{
                    {
                        Name:   "http_requests_total",
                        Type:   "counter",
                        Value:  1,
                        Labels: map[string]string{
                            "method": r.Method,
                            "path":   r.URL.Path,
                            "status": fmt.Sprintf("%d", wrapped.statusCode),
                        },
                        Timestamp: time.Now(),
                    },
                    {
                        Name:   "http_request_duration_seconds",
                        Type:   "histogram",
                        Value:  duration.Seconds(),
                        Labels: map[string]string{
                            "method": r.Method,
                            "path":   r.URL.Path,
                        },
                        Timestamp: time.Now(),
                    },
                },
            }
            manager.SubmitMetrics(context.Background(), "prometheus", metricReq)
        })
    }
}

type responseWriter struct {
    http.ResponseWriter
    statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
    rw.statusCode = code
    rw.ResponseWriter.WriteHeader(code)
}
```

### Performance Monitoring

```go
func monitorFunction(manager *monitoring.MonitoringManager, functionName string, fn func() error) error {
    start := time.Now()
    
    // Submit start metric
    metricReq := &types.MetricRequest{
        Metrics: []types.Metric{
            {
                Name:   "function_calls_total",
                Type:   "counter",
                Value:  1,
                Labels: map[string]string{
                    "function": functionName,
                },
                Timestamp: time.Now(),
            },
        },
    }
    manager.SubmitMetrics(context.Background(), "prometheus", metricReq)
    
    // Execute function
    err := fn()
    
    // Calculate duration
    duration := time.Since(start)
    
    // Submit duration metric
    metricReq = &types.MetricRequest{
        Metrics: []types.Metric{
            {
                Name:   "function_duration_seconds",
                Type:   "histogram",
                Value:  duration.Seconds(),
                Labels: map[string]string{
                    "function": functionName,
                    "status":   getStatus(err),
                },
                Timestamp: time.Now(),
            },
        },
    }
    manager.SubmitMetrics(context.Background(), "prometheus", metricReq)
    
    return err
}

func getStatus(err error) string {
    if err != nil {
        return "error"
    }
    return "success"
}
```

### Batch Operations

```go
// Submit multiple metrics in batch
metrics := []types.Metric{
    {
        Name:   "cpu_usage_percent",
        Type:   "gauge",
        Value:  75.5,
        Labels: map[string]string{"instance": "server-1"},
        Timestamp: time.Now(),
    },
    {
        Name:   "memory_usage_bytes",
        Type:   "gauge",
        Value:  1024 * 1024 * 512, // 512MB
        Labels: map[string]string{"instance": "server-1"},
        Timestamp: time.Now(),
    },
    {
        Name:   "disk_usage_percent",
        Type:   "gauge",
        Value:  60.2,
        Labels: map[string]string{"instance": "server-1"},
        Timestamp: time.Now(),
    },
}

metricReq := &types.MetricRequest{
    Metrics: metrics,
}

err := manager.SubmitMetrics(ctx, "prometheus", metricReq)
```

### Error Handling

```go
err := manager.SubmitMetrics(ctx, "prometheus", metricReq)
if err != nil {
    // Handle different types of errors
    switch {
    case strings.Contains(err.Error(), "connection"):
        log.Printf("Monitoring provider connection error: %v", err)
    case strings.Contains(err.Error(), "timeout"):
        log.Printf("Monitoring operation timeout: %v", err)
    case strings.Contains(err.Error(), "quota"):
        log.Printf("Monitoring quota exceeded: %v", err)
    default:
        log.Printf("Monitoring operation failed: %v", err)
    }
}
```

## Best Practices

1. **Metric Naming**: Use consistent, descriptive metric names
2. **Labeling**: Use meaningful labels for metric dimensions
3. **Sampling**: Implement appropriate sampling rates for high-volume data
4. **Batch Operations**: Use batch operations for better performance
5. **Error Handling**: Implement comprehensive error handling
6. **Health Checks**: Regular health checks for monitoring systems
7. **Alerting**: Set up meaningful alerts with appropriate thresholds
8. **Retention**: Configure appropriate data retention policies
9. **Security**: Secure monitoring endpoints and data
10. **Testing**: Test monitoring in different scenarios

## Contributing

Contributions are welcome! Please read the contributing guidelines and submit pull requests for any improvements.

## License

This library is licensed under the MIT License. See the LICENSE file for details.
