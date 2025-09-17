# Chaos Engineering Library

The Chaos Engineering library provides a unified interface for chaos engineering experiments across multiple providers including Kubernetes, HTTP, and Messaging systems. It offers comprehensive chaos testing capabilities with support for various experiment types (pod failures, network latency, CPU stress, HTTP errors, message delays), experiment management, and advanced features like experiment monitoring, result tracking, and automated cleanup.

## Features

- **Multi-Provider Support**: Kubernetes, HTTP, and Messaging chaos providers
- **Experiment Types**: Pod failures, network latency, CPU stress, memory stress, HTTP errors, message delays
- **Experiment Management**: Start, stop, monitor, and list experiments
- **Result Tracking**: Comprehensive experiment results and metrics
- **Automated Cleanup**: Automatic cleanup of chaos experiments
- **Provider Management**: Easy provider registration and management
- **Context Support**: Full context support for cancellation and timeouts
- **Thread Safety**: Thread-safe operations with proper locking

## Supported Providers

- **Kubernetes**: Pod failures, network latency, CPU/memory stress
- **HTTP**: HTTP latency, errors, and timeouts
- **Messaging**: Message delays, loss, and reordering
- **Custom**: Custom chaos providers

## Installation

```bash
go get github.com/anasamu/go-micro-libs/chaos
```

## Quick Start

```go
package main

import (
    "context"
    "fmt"
    "log"
    "time"

    "github.com/anasamu/go-micro-libs/chaos"
    "github.com/anasamu/go-micro-libs/chaos/types"
)

func main() {
    // Create chaos manager
    manager := chaos.NewManager()

    // Register Kubernetes provider (example)
    // kubernetesProvider := kubernetes.NewProvider()
    // manager.RegisterProvider(chaos.ChaosTypeKubernetes, kubernetesProvider)

    // Initialize all providers
    ctx := context.Background()
    err := manager.Initialize(ctx)
    if err != nil {
        log.Fatal(err)
    }

    // Create a pod failure experiment
    config := types.ExperimentConfig{
        Type:       chaos.ChaosTypeKubernetes,
        Experiment: chaos.PodFailure,
        Duration:   "5m",
        Intensity:  0.5,
        Target:     "app-pod",
        Parameters: map[string]interface{}{
            "namespace": "default",
            "selector":  "app=myapp",
        },
    }

    // Start the experiment
    result, err := manager.StartExperiment(ctx, config)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Experiment started: %s, Status: %s\n", result.ID, result.Status)

    // Monitor the experiment
    time.Sleep(2 * time.Minute)
    status, err := manager.GetExperimentStatus(ctx, chaos.ChaosTypeKubernetes, result.ID)
    if err != nil {
        log.Printf("Failed to get experiment status: %v", err)
    } else {
        fmt.Printf("Experiment status: %s\n", status.Status)
    }

    // Stop the experiment
    err = manager.StopExperiment(ctx, chaos.ChaosTypeKubernetes, result.ID)
    if err != nil {
        log.Printf("Failed to stop experiment: %v", err)
    } else {
        fmt.Println("Experiment stopped successfully")
    }
}
```

## API Reference

### Manager

The main manager for handling chaos engineering experiments across multiple providers.

#### Methods

##### `NewManager() *Manager`
Creates a new chaos manager.

##### `RegisterProvider(chaosType ChaosType, provider ChaosProvider)`
Registers a chaos provider for a specific chaos type.

**Parameters:**
- `chaosType`: The type of chaos (Kubernetes, HTTP, Messaging)
- `provider`: The chaos provider to register

##### `Initialize(ctx context.Context) error`
Initializes all registered providers.

**Parameters:**
- `ctx`: Context for cancellation and timeouts

**Returns:**
- `error`: Any error that occurred during initialization

##### `StartExperiment(ctx context.Context, config ExperimentConfig) (*ExperimentResult, error)`
Starts a chaos experiment.

**Parameters:**
- `ctx`: Context for cancellation and timeouts
- `config`: Experiment configuration

**Returns:**
- `*ExperimentResult`: Experiment result with ID and status
- `error`: Any error that occurred

##### `StopExperiment(ctx context.Context, chaosType ChaosType, experimentID string) error`
Stops a chaos experiment.

**Parameters:**
- `ctx`: Context for cancellation and timeouts
- `chaosType`: The type of chaos experiment
- `experimentID`: ID of the experiment to stop

**Returns:**
- `error`: Any error that occurred

##### `GetExperimentStatus(ctx context.Context, chaosType ChaosType, experimentID string) (*ExperimentResult, error)`
Gets the status of a chaos experiment.

##### `ListExperiments(ctx context.Context, chaosType ChaosType) ([]*ExperimentResult, error)`
Lists all experiments for a specific chaos type.

##### `Cleanup(ctx context.Context) error`
Cleans up all providers.

##### `GetAvailableProviders() []ChaosType`
Returns a list of available chaos providers.

##### `DefaultManager() *Manager`
Creates a manager with default providers (requires manual provider registration).

### Types

#### ChaosType
Represents the type of chaos experiment.

```go
const (
    ChaosTypeKubernetes ChaosType = "kubernetes"
    ChaosTypeHTTP       ChaosType = "http"
    ChaosTypeMessaging  ChaosType = "messaging"
)
```

#### ExperimentType
Represents the specific type of experiment.

```go
const (
    // Kubernetes experiments
    PodFailure     ExperimentType = "pod_failure"
    NetworkLatency ExperimentType = "network_latency"
    CPUStress      ExperimentType = "cpu_stress"
    MemoryStress   ExperimentType = "memory_stress"

    // HTTP experiments
    HTTPLatency ExperimentType = "http_latency"
    HTTPError   ExperimentType = "http_error"
    HTTPTimeout ExperimentType = "http_timeout"

    // Messaging experiments
    MessageDelay   ExperimentType = "message_delay"
    MessageLoss    ExperimentType = "message_loss"
    MessageReorder ExperimentType = "message_reorder"
)
```

#### ExperimentConfig
Holds configuration for a chaos experiment.

```go
type ExperimentConfig struct {
    Type       ChaosType              `json:"type"`
    Experiment ExperimentType         `json:"experiment"`
    Duration   string                 `json:"duration,omitempty"`
    Intensity  float64                `json:"intensity,omitempty"`
    Target     string                 `json:"target,omitempty"`
    Parameters map[string]interface{} `json:"parameters,omitempty"`
}
```

#### ExperimentResult
Holds the result of a chaos experiment.

```go
type ExperimentResult struct {
    ID        string                 `json:"id"`
    Status    string                 `json:"status"`
    Message   string                 `json:"message,omitempty"`
    Metrics   map[string]interface{} `json:"metrics,omitempty"`
    StartTime string                 `json:"start_time,omitempty"`
    EndTime   string                 `json:"end_time,omitempty"`
}
```

#### ChaosProvider
Defines the interface for chaos providers.

```go
type ChaosProvider interface {
    Initialize(ctx context.Context, config map[string]interface{}) error
    StartExperiment(ctx context.Context, config ExperimentConfig) (*ExperimentResult, error)
    StopExperiment(ctx context.Context, experimentID string) error
    GetExperimentStatus(ctx context.Context, experimentID string) (*ExperimentResult, error)
    ListExperiments(ctx context.Context) ([]*ExperimentResult, error)
    Cleanup(ctx context.Context) error
}
```

## Advanced Usage

### Kubernetes Chaos Experiments

```go
// Pod failure experiment
podFailureConfig := types.ExperimentConfig{
    Type:       chaos.ChaosTypeKubernetes,
    Experiment: chaos.PodFailure,
    Duration:   "10m",
    Intensity:  0.3, // 30% of pods
    Target:     "app-deployment",
    Parameters: map[string]interface{}{
        "namespace":     "production",
        "selector":      "app=myapp",
        "failure_mode":  "random",
        "recovery_time": "2m",
    },
}

result, err := manager.StartExperiment(ctx, podFailureConfig)

// Network latency experiment
networkLatencyConfig := types.ExperimentConfig{
    Type:       chaos.ChaosTypeKubernetes,
    Experiment: chaos.NetworkLatency,
    Duration:   "15m",
    Intensity:  0.5,
    Target:     "service-mesh",
    Parameters: map[string]interface{}{
        "namespace":    "default",
        "latency":      "100ms",
        "jitter":       "50ms",
        "packet_loss":  0.1,
        "bandwidth":    "1Mbps",
    },
}

result, err = manager.StartExperiment(ctx, networkLatencyConfig)

// CPU stress experiment
cpuStressConfig := types.ExperimentConfig{
    Type:       chaos.ChaosTypeKubernetes,
    Experiment: chaos.CPUStress,
    Duration:   "20m",
    Intensity:  0.8, // 80% CPU usage
    Target:     "worker-nodes",
    Parameters: map[string]interface{}{
        "namespace":    "default",
        "cpu_percent":  80,
        "duration":     "20m",
        "workers":      4,
    },
}

result, err = manager.StartExperiment(ctx, cpuStressConfig)

// Memory stress experiment
memoryStressConfig := types.ExperimentConfig{
    Type:       chaos.ChaosTypeKubernetes,
    Experiment: chaos.MemoryStress,
    Duration:   "10m",
    Intensity:  0.7, // 70% memory usage
    Target:     "database-pods",
    Parameters: map[string]interface{}{
        "namespace":     "database",
        "memory_percent": 70,
        "duration":      "10m",
        "workers":       2,
    },
}

result, err = manager.StartExperiment(ctx, memoryStressConfig)
```

### HTTP Chaos Experiments

```go
// HTTP latency experiment
httpLatencyConfig := types.ExperimentConfig{
    Type:       chaos.ChaosTypeHTTP,
    Experiment: chaos.HTTPLatency,
    Duration:   "5m",
    Intensity:  0.6,
    Target:     "api-gateway",
    Parameters: map[string]interface{}{
        "url_pattern":  "/api/v1/*",
        "latency":      "200ms",
        "jitter":       "100ms",
        "probability":  0.5,
    },
}

result, err := manager.StartExperiment(ctx, httpLatencyConfig)

// HTTP error experiment
httpErrorConfig := types.ExperimentConfig{
    Type:       chaos.ChaosTypeHTTP,
    Experiment: chaos.HTTPError,
    Duration:   "3m",
    Intensity:  0.3,
    Target:     "payment-service",
    Parameters: map[string]interface{}{
        "url_pattern":  "/api/payments/*",
        "error_code":   500,
        "error_message": "Internal Server Error",
        "probability":  0.3,
    },
}

result, err = manager.StartExperiment(ctx, httpErrorConfig)

// HTTP timeout experiment
httpTimeoutConfig := types.ExperimentConfig{
    Type:       chaos.ChaosTypeHTTP,
    Experiment: chaos.HTTPTimeout,
    Duration:   "7m",
    Intensity:  0.4,
    Target:     "external-api",
    Parameters: map[string]interface{}{
        "url_pattern":  "/api/external/*",
        "timeout":      "30s",
        "probability":  0.4,
    },
}

result, err = manager.StartExperiment(ctx, httpTimeoutConfig)
```

### Messaging Chaos Experiments

```go
// Message delay experiment
messageDelayConfig := types.ExperimentConfig{
    Type:       chaos.ChaosTypeMessaging,
    Experiment: chaos.MessageDelay,
    Duration:   "8m",
    Intensity:  0.5,
    Target:     "order-queue",
    Parameters: map[string]interface{}{
        "topic":       "orders",
        "delay":       "5s",
        "jitter":      "2s",
        "probability": 0.5,
    },
}

result, err := manager.StartExperiment(ctx, messageDelayConfig)

// Message loss experiment
messageLossConfig := types.ExperimentConfig{
    Type:       chaos.ChaosTypeMessaging,
    Experiment: chaos.MessageLoss,
    Duration:   "6m",
    Intensity:  0.2,
    Target:     "notification-queue",
    Parameters: map[string]interface{}{
        "topic":       "notifications",
        "loss_rate":   0.2,
        "pattern":     "random",
    },
}

result, err = manager.StartExperiment(ctx, messageLossConfig)

// Message reorder experiment
messageReorderConfig := types.ExperimentConfig{
    Type:       chaos.ChaosTypeMessaging,
    Experiment: chaos.MessageReorder,
    Duration:   "4m",
    Intensity:  0.3,
    Target:     "event-stream",
    Parameters: map[string]interface{}{
        "topic":       "events",
        "reorder_rate": 0.3,
        "window_size":  10,
    },
}

result, err = manager.StartExperiment(ctx, messageReorderConfig)
```

### Experiment Monitoring

```go
// Start an experiment
config := types.ExperimentConfig{
    Type:       chaos.ChaosTypeKubernetes,
    Experiment: chaos.PodFailure,
    Duration:   "10m",
    Intensity:  0.5,
    Target:     "app-pods",
}

result, err := manager.StartExperiment(ctx, config)
if err != nil {
    log.Fatal(err)
}

experimentID := result.ID

// Monitor experiment status
ticker := time.NewTicker(30 * time.Second)
defer ticker.Stop()

for {
    select {
    case <-ctx.Done():
        return
    case <-ticker.C:
        status, err := manager.GetExperimentStatus(ctx, chaos.ChaosTypeKubernetes, experimentID)
        if err != nil {
            log.Printf("Failed to get experiment status: %v", err)
            continue
        }

        fmt.Printf("Experiment %s: Status=%s, Message=%s\n", 
            experimentID, status.Status, status.Message)

        if status.Metrics != nil {
            fmt.Printf("Metrics: %+v\n", status.Metrics)
        }

        // Check if experiment is complete
        if status.Status == "completed" || status.Status == "failed" {
            fmt.Printf("Experiment %s finished with status: %s\n", experimentID, status.Status)
            return
        }
    }
}
```

### Batch Experiment Management

```go
// Start multiple experiments
experiments := []types.ExperimentConfig{
    {
        Type:       chaos.ChaosTypeKubernetes,
        Experiment: chaos.PodFailure,
        Duration:   "5m",
        Intensity:  0.3,
        Target:     "frontend-pods",
    },
    {
        Type:       chaos.ChaosTypeHTTP,
        Experiment: chaos.HTTPLatency,
        Duration:   "3m",
        Intensity:  0.5,
        Target:     "api-service",
    },
    {
        Type:       chaos.ChaosTypeMessaging,
        Experiment: chaos.MessageDelay,
        Duration:   "4m",
        Intensity:  0.4,
        Target:     "event-queue",
    },
}

var experimentIDs []string
for _, config := range experiments {
    result, err := manager.StartExperiment(ctx, config)
    if err != nil {
        log.Printf("Failed to start experiment: %v", err)
        continue
    }
    experimentIDs = append(experimentIDs, result.ID)
    fmt.Printf("Started experiment: %s\n", result.ID)
}

// Monitor all experiments
for _, experimentID := range experimentIDs {
    go func(id string) {
        for {
            status, err := manager.GetExperimentStatus(ctx, chaos.ChaosTypeKubernetes, id)
            if err != nil {
                log.Printf("Failed to get status for experiment %s: %v", id, err)
                return
            }

            if status.Status == "completed" || status.Status == "failed" {
                fmt.Printf("Experiment %s completed with status: %s\n", id, status.Status)
                return
            }

            time.Sleep(10 * time.Second)
        }
    }(experimentID)
}

// Stop all experiments after monitoring
time.Sleep(2 * time.Minute)
for _, experimentID := range experimentIDs {
    err := manager.StopExperiment(ctx, chaos.ChaosTypeKubernetes, experimentID)
    if err != nil {
        log.Printf("Failed to stop experiment %s: %v", experimentID, err)
    } else {
        fmt.Printf("Stopped experiment: %s\n", experimentID)
    }
}
```

### Experiment Listing and Cleanup

```go
// List all experiments for a chaos type
experiments, err := manager.ListExperiments(ctx, chaos.ChaosTypeKubernetes)
if err != nil {
    log.Printf("Failed to list experiments: %v", err)
    return
}

fmt.Printf("Found %d Kubernetes experiments:\n", len(experiments))
for _, exp := range experiments {
    fmt.Printf("  ID: %s, Status: %s, Start: %s\n", 
        exp.ID, exp.Status, exp.StartTime)
    
    if exp.Metrics != nil {
        fmt.Printf("    Metrics: %+v\n", exp.Metrics)
    }
}

// Cleanup all providers
err = manager.Cleanup(ctx)
if err != nil {
    log.Printf("Failed to cleanup: %v", err)
} else {
    fmt.Println("Cleanup completed successfully")
}

// Get available providers
providers := manager.GetAvailableProviders()
fmt.Printf("Available chaos providers: %v\n", providers)
```

### Error Handling

```go
result, err := manager.StartExperiment(ctx, config)
if err != nil {
    // Handle different types of errors
    switch {
    case strings.Contains(err.Error(), "provider not found"):
        log.Printf("Chaos provider not found: %v", err)
    case strings.Contains(err.Error(), "invalid config"):
        log.Printf("Invalid experiment configuration: %v", err)
    case strings.Contains(err.Error(), "experiment already running"):
        log.Printf("Experiment already running: %v", err)
    case strings.Contains(err.Error(), "insufficient permissions"):
        log.Printf("Insufficient permissions for chaos experiment: %v", err)
    default:
        log.Printf("Failed to start experiment: %v", err)
    }
    return
}

// Handle experiment result
if result.Status == "started" {
    fmt.Printf("Experiment started successfully: %s\n", result.ID)
} else if result.Status == "failed" {
    fmt.Printf("Experiment failed to start: %s\n", result.Message)
}
```

## Best Practices

1. **Experiment Design**: Design experiments with clear objectives and success criteria
2. **Gradual Intensity**: Start with low intensity and gradually increase
3. **Monitoring**: Always monitor experiments and have rollback plans
4. **Safety**: Ensure experiments don't affect critical production systems
5. **Documentation**: Document experiment results and learnings
6. **Automation**: Automate experiment execution and cleanup
7. **Team Coordination**: Coordinate with teams before running experiments
8. **Recovery**: Have recovery procedures in place
9. **Testing**: Test chaos experiments in staging environments first
10. **Compliance**: Ensure experiments comply with organizational policies

## Contributing

Contributions are welcome! Please read the contributing guidelines and submit pull requests for any improvements.

## License

This library is licensed under the MIT License. See the LICENSE file for details.
