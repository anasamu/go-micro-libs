# Scheduling Library

The Scheduling library provides a unified interface for task scheduling operations across multiple providers including Cron and Redis. It offers comprehensive task scheduling capabilities with support for various schedule types (cron, one-time, interval), different task handlers (HTTP, command, function, message), retry policies, and advanced features like batch operations, health monitoring, and task dependencies.

## Features

- **Multi-Provider Support**: Cron, Redis, and custom providers
- **Schedule Types**: Cron expressions, one-time, and interval scheduling
- **Task Handlers**: HTTP, command, function, and message handlers
- **Retry Policies**: Configurable retry with different backoff strategies
- **Batch Operations**: Efficient batch task scheduling and management
- **Health Monitoring**: Provider health checks and metrics
- **Task Dependencies**: Task dependency management
- **Notifications**: Task execution notifications
- **Templates**: Task templates for reusable configurations
- **Filtering**: Advanced task filtering and querying

## Supported Providers

- **Cron**: Traditional cron-based scheduling
- **Redis**: Distributed task scheduling with persistence
- **Custom**: Custom scheduling providers

## Installation

```bash
go get github.com/anasamu/go-micro-libs/scheduling
```

## Quick Start

```go
package main

import (
    "context"
    "fmt"
    "log"
    "time"

    "github.com/anasamu/go-micro-libs/scheduling"
    "github.com/anasamu/go-micro-libs/scheduling/types"
    "github.com/sirupsen/logrus"
)

func main() {
    // Create logger
    logger := logrus.New()

    // Create scheduling manager
    config := &scheduling.ManagerConfig{
        DefaultProvider: "cron",
        RetryAttempts:   3,
        RetryDelay:      1 * time.Second,
        Timeout:         30 * time.Second,
        FallbackEnabled: true,
    }
    manager := scheduling.NewSchedulingManager(config, logger)

    // Register Cron provider (example)
    // cronProvider := cron.NewCronProvider()
    // manager.RegisterProvider("cron", cronProvider)

    // Create a task
    task := &types.Task{
        ID:          "task-001",
        Name:        "Daily Report",
        Description: "Generate daily sales report",
        Schedule: &types.Schedule{
            Type:     types.ScheduleTypeCron,
            CronExpr: "0 9 * * *", // Every day at 9 AM
            Timezone: "UTC",
        },
        Handler: &types.TaskHandler{
            Type: types.HandlerTypeHTTP,
            HTTP: &types.HTTPHandler{
                URL:     "https://api.example.com/reports/daily",
                Method:  "POST",
                Headers: map[string]string{
                    "Authorization": "Bearer token",
                    "Content-Type":  "application/json",
                },
                Body:    `{"type": "sales", "date": "{{.date}}"}`,
                Timeout: 30 * time.Second,
            },
        },
        RetryPolicy: &types.RetryPolicy{
            MaxAttempts: 3,
            Delay:       5 * time.Second,
            Backoff:     types.BackoffTypeExponential,
            MaxDelay:    60 * time.Second,
        },
        Timeout: 5 * time.Minute,
        Status:  types.TaskStatusPending,
        Tags:    []string{"report", "daily", "sales"},
        Metadata: map[string]string{
            "department": "sales",
            "priority":   "high",
        },
    }

    // Schedule the task
    ctx := context.Background()
    result, err := manager.ScheduleTask(ctx, task, "cron")
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Task scheduled: %s, Status: %s\n", result.TaskID, result.Status)
}
```

## API Reference

### SchedulingManager

The main manager for handling task scheduling operations across multiple providers.

#### Methods

##### `NewSchedulingManager(config *ManagerConfig, logger *logrus.Logger) *SchedulingManager`
Creates a new scheduling manager with the given configuration and logger.

##### `RegisterProvider(name string, provider SchedulingProvider) error`
Registers a new scheduling provider.

**Parameters:**
- `name`: Name of the provider
- `provider`: The scheduling provider to register

**Returns:**
- `error`: Any error that occurred during registration

##### `GetProvider(name string) (SchedulingProvider, error)`
Retrieves a specific provider by name.

##### `ListProviders() []string`
Returns all registered provider names.

##### `ScheduleTask(ctx context.Context, task *types.Task, providerName string) (*types.TaskResult, error)`
Schedules a task using the specified provider.

**Parameters:**
- `ctx`: Context for cancellation and timeouts
- `task`: Task to schedule
- `providerName`: Name of the provider to use

**Returns:**
- `*types.TaskResult`: Task scheduling result
- `error`: Any error that occurred

##### `CancelTask(ctx context.Context, taskID string, providerName string) error`
Cancels a task using the specified provider.

##### `GetTask(ctx context.Context, taskID string, providerName string) (*types.Task, error)`
Retrieves a task using the specified provider.

##### `ListTasks(ctx context.Context, filter *types.TaskFilter, providerName string) ([]*types.Task, error)`
Lists tasks using the specified provider with optional filtering.

##### `UpdateTask(ctx context.Context, task *types.Task, providerName string) error`
Updates a task using the specified provider.

##### `ScheduleMultiple(ctx context.Context, tasks []*types.Task, providerName string) ([]*types.TaskResult, error)`
Schedules multiple tasks using the specified provider.

##### `CancelMultiple(ctx context.Context, taskIDs []string, providerName string) error`
Cancels multiple tasks using the specified provider.

##### `GetHealth(ctx context.Context) (map[string]*types.HealthStatus, error)`
Returns the health status of all providers.

##### `GetMetrics(ctx context.Context) (map[string]*types.Metrics, error)`
Returns metrics from all providers.

##### `ConnectAll(ctx context.Context) error`
Connects all registered providers.

##### `DisconnectAll(ctx context.Context) error`
Disconnects all registered providers.

### Types

#### ManagerConfig
Configuration for the scheduling manager.

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

#### Task
Represents a scheduled task.

```go
type Task struct {
    ID          string            `json:"id"`
    Name        string            `json:"name"`
    Description string            `json:"description,omitempty"`
    Schedule    *Schedule         `json:"schedule"`
    Handler     *TaskHandler      `json:"handler"`
    RetryPolicy *RetryPolicy      `json:"retry_policy,omitempty"`
    Timeout     time.Duration     `json:"timeout,omitempty"`
    Status      TaskStatus        `json:"status"`
    CreatedAt   time.Time         `json:"created_at"`
    UpdatedAt   time.Time         `json:"updated_at"`
    NextRun     *time.Time        `json:"next_run,omitempty"`
    LastRun     *time.Time        `json:"last_run,omitempty"`
    RunCount    int64             `json:"run_count"`
    Metadata    map[string]string `json:"metadata,omitempty"`
    Tags        []string          `json:"tags,omitempty"`
}
```

#### Schedule
Represents a task schedule.

```go
type Schedule struct {
    Type      ScheduleType  `json:"type"`
    CronExpr  string        `json:"cron_expr,omitempty"`
    StartTime *time.Time    `json:"start_time,omitempty"`
    EndTime   *time.Time    `json:"end_time,omitempty"`
    Interval  time.Duration `json:"interval,omitempty"`
    Timezone  string        `json:"timezone,omitempty"`
}
```

#### TaskHandler
Represents how a task should be executed.

```go
type TaskHandler struct {
    Type     HandlerType      `json:"type"`
    HTTP     *HTTPHandler     `json:"http,omitempty"`
    Command  *CommandHandler  `json:"command,omitempty"`
    Function *FunctionHandler `json:"function,omitempty"`
    Message  *MessageHandler  `json:"message,omitempty"`
}
```

#### RetryPolicy
Represents the retry policy for a task.

```go
type RetryPolicy struct {
    MaxAttempts int           `json:"max_attempts"`
    Delay       time.Duration `json:"delay"`
    Backoff     BackoffType   `json:"backoff"`
    MaxDelay    time.Duration `json:"max_delay,omitempty"`
}
```

#### TaskResult
Represents the result of scheduling a task.

```go
type TaskResult struct {
    TaskID    string     `json:"task_id"`
    Status    TaskStatus `json:"status"`
    Message   string     `json:"message,omitempty"`
    Timestamp time.Time  `json:"timestamp"`
    NextRun   *time.Time `json:"next_run,omitempty"`
}
```

#### TaskFilter
Represents filters for listing tasks.

```go
type TaskFilter struct {
    Status        []TaskStatus `json:"status,omitempty"`
    Tags          []string     `json:"tags,omitempty"`
    CreatedAfter  *time.Time   `json:"created_after,omitempty"`
    CreatedBefore *time.Time   `json:"created_before,omitempty"`
    Limit         int          `json:"limit,omitempty"`
    Offset        int          `json:"offset,omitempty"`
}
```

## Advanced Usage

### Different Schedule Types

```go
// Cron schedule
cronTask := &types.Task{
    ID:   "cron-task",
    Name: "Hourly Backup",
    Schedule: &types.Schedule{
        Type:     types.ScheduleTypeCron,
        CronExpr: "0 * * * *", // Every hour
        Timezone: "UTC",
    },
    Handler: &types.TaskHandler{
        Type: types.HandlerTypeCommand,
        Command: &types.CommandHandler{
            Command: "backup.sh",
            Args:    []string{"--type", "full"},
            Env: map[string]string{
                "BACKUP_DIR": "/backups",
            },
        },
    },
}

// One-time schedule
oneTimeTask := &types.Task{
    ID:   "one-time-task",
    Name: "Database Migration",
    Schedule: &types.Schedule{
        Type:      types.ScheduleTypeOnce,
        StartTime: timePtr(time.Now().Add(1 * time.Hour)),
    },
    Handler: &types.TaskHandler{
        Type: types.HandlerTypeHTTP,
        HTTP: &types.HTTPHandler{
            URL:    "https://api.example.com/migrate",
            Method: "POST",
        },
    },
}

// Interval schedule
intervalTask := &types.Task{
    ID:   "interval-task",
    Name: "Health Check",
    Schedule: &types.Schedule{
        Type:     types.ScheduleTypeInterval,
        Interval: 30 * time.Second,
    },
    Handler: &types.TaskHandler{
        Type: types.HandlerTypeHTTP,
        HTTP: &types.HTTPHandler{
            URL:    "https://api.example.com/health",
            Method: "GET",
        },
    },
}
```

### Different Task Handlers

```go
// HTTP handler
httpTask := &types.Task{
    ID:   "http-task",
    Name: "API Call",
    Handler: &types.TaskHandler{
        Type: types.HandlerTypeHTTP,
        HTTP: &types.HTTPHandler{
            URL:     "https://api.example.com/webhook",
            Method:  "POST",
            Headers: map[string]string{
                "Authorization": "Bearer token",
                "Content-Type":  "application/json",
            },
            Body:    `{"event": "scheduled_task", "timestamp": "{{.timestamp}}"}`,
            Timeout: 30 * time.Second,
        },
    },
}

// Command handler
commandTask := &types.Task{
    ID:   "command-task",
    Name: "System Maintenance",
    Handler: &types.TaskHandler{
        Type: types.HandlerTypeCommand,
        Command: &types.CommandHandler{
            Command: "maintenance.sh",
            Args:    []string{"--cleanup", "--optimize"},
            Env: map[string]string{
                "MAINTENANCE_MODE": "true",
            },
            WorkDir: "/opt/maintenance",
        },
    },
}

// Function handler
functionTask := &types.Task{
    ID:   "function-task",
    Name: "Data Processing",
    Handler: &types.TaskHandler{
        Type: types.HandlerTypeFunction,
        Function: &types.FunctionHandler{
            FunctionName: "processData",
            Parameters: map[string]interface{}{
                "batch_size": 1000,
                "timeout":    300,
            },
        },
    },
}

// Message handler
messageTask := &types.Task{
    ID:   "message-task",
    Name: "Notification",
    Handler: &types.TaskHandler{
        Type: types.HandlerTypeMessage,
        Message: &types.MessageHandler{
            Topic:   "notifications",
            Message: `{"type": "reminder", "message": "Task completed"}`,
            Headers: map[string]string{
                "priority": "high",
            },
        },
    },
}
```

### Retry Policies

```go
// Fixed backoff retry policy
fixedRetryPolicy := &types.RetryPolicy{
    MaxAttempts: 3,
    Delay:       10 * time.Second,
    Backoff:     types.BackoffTypeFixed,
}

// Linear backoff retry policy
linearRetryPolicy := &types.RetryPolicy{
    MaxAttempts: 5,
    Delay:       5 * time.Second,
    Backoff:     types.BackoffTypeLinear,
    MaxDelay:    60 * time.Second,
}

// Exponential backoff retry policy
exponentialRetryPolicy := &types.RetryPolicy{
    MaxAttempts: 3,
    Delay:       2 * time.Second,
    Backoff:     types.BackoffTypeExponential,
    MaxDelay:    120 * time.Second,
}

// Task with retry policy
retryTask := &types.Task{
    ID:   "retry-task",
    Name: "Unreliable Service Call",
    Schedule: &types.Schedule{
        Type:     types.ScheduleTypeCron,
        CronExpr: "0 */6 * * *", // Every 6 hours
    },
    Handler: &types.TaskHandler{
        Type: types.HandlerTypeHTTP,
        HTTP: &types.HTTPHandler{
            URL:    "https://unreliable-api.example.com/data",
            Method: "GET",
        },
    },
    RetryPolicy: exponentialRetryPolicy,
    Timeout:     2 * time.Minute,
}
```

### Batch Operations

```go
// Schedule multiple tasks
tasks := []*types.Task{
    {
        ID:   "task-1",
        Name: "Daily Report",
        Schedule: &types.Schedule{
            Type:     types.ScheduleTypeCron,
            CronExpr: "0 9 * * *",
        },
        Handler: &types.TaskHandler{
            Type: types.HandlerTypeHTTP,
            HTTP: &types.HTTPHandler{
                URL:    "https://api.example.com/reports/daily",
                Method: "POST",
            },
        },
    },
    {
        ID:   "task-2",
        Name: "Weekly Cleanup",
        Schedule: &types.Schedule{
            Type:     types.ScheduleTypeCron,
            CronExpr: "0 2 * * 0", // Every Sunday at 2 AM
        },
        Handler: &types.TaskHandler{
            Type: types.HandlerTypeCommand,
            Command: &types.CommandHandler{
                Command: "cleanup.sh",
            },
        },
    },
    {
        ID:   "task-3",
        Name: "Monthly Backup",
        Schedule: &types.Schedule{
            Type:     types.ScheduleTypeCron,
            CronExpr: "0 1 1 * *", // First day of every month at 1 AM
        },
        Handler: &types.TaskHandler{
            Type: types.HandlerTypeCommand,
            Command: &types.CommandHandler{
                Command: "backup.sh",
                Args:    []string{"--type", "monthly"},
            },
        },
    },
}

results, err := manager.ScheduleMultiple(ctx, tasks, "cron")
if err != nil {
    log.Printf("Failed to schedule multiple tasks: %v", err)
    return
}

fmt.Printf("Scheduled %d tasks successfully\n", len(results))

// Cancel multiple tasks
taskIDs := []string{"task-1", "task-2", "task-3"}
err = manager.CancelMultiple(ctx, taskIDs, "cron")
if err != nil {
    log.Printf("Failed to cancel multiple tasks: %v", err)
}
```

### Task Filtering and Querying

```go
// Filter tasks by status
statusFilter := &types.TaskFilter{
    Status: []types.TaskStatus{
        types.TaskStatusScheduled,
        types.TaskStatusRunning,
    },
    Limit: 50,
}

tasks, err := manager.ListTasks(ctx, statusFilter, "cron")

// Filter tasks by tags
tagFilter := &types.TaskFilter{
    Tags:   []string{"report", "daily"},
    Limit:  100,
    Offset: 0,
}

tasks, err = manager.ListTasks(ctx, tagFilter, "cron")

// Filter tasks by date range
dateFilter := &types.TaskFilter{
    CreatedAfter:  timePtr(time.Now().Add(-7 * 24 * time.Hour)), // Last 7 days
    CreatedBefore: timePtr(time.Now()),
    Limit:         200,
}

tasks, err = manager.ListTasks(ctx, dateFilter, "cron")

// Complex filter
complexFilter := &types.TaskFilter{
    Status: []types.TaskStatus{
        types.TaskStatusCompleted,
        types.TaskStatusFailed,
    },
    Tags: []string{"backup", "maintenance"},
    CreatedAfter: timePtr(time.Now().Add(-30 * 24 * time.Hour)), // Last 30 days
    Limit:        100,
    Offset:       0,
}

tasks, err = manager.ListTasks(ctx, complexFilter, "cron")
```

### Health Monitoring

```go
// Get health status of all providers
health, err := manager.GetHealth(ctx)
if err != nil {
    log.Printf("Failed to get health status: %v", err)
    return
}

for providerName, status := range health {
    fmt.Printf("Provider: %s\n", providerName)
    fmt.Printf("  Status: %s\n", status.Status)
    fmt.Printf("  Message: %s\n", status.Message)
    fmt.Printf("  Timestamp: %v\n", status.Timestamp)
    if status.Details != nil {
        fmt.Printf("  Details: %+v\n", status.Details)
    }
    fmt.Println()
}

// Get metrics from all providers
metrics, err := manager.GetMetrics(ctx)
if err != nil {
    log.Printf("Failed to get metrics: %v", err)
    return
}

for providerName, metric := range metrics {
    fmt.Printf("Provider: %s\n", providerName)
    fmt.Printf("  Total Tasks: %d\n", metric.TotalTasks)
    fmt.Printf("  Scheduled Tasks: %d\n", metric.ScheduledTasks)
    fmt.Printf("  Running Tasks: %d\n", metric.RunningTasks)
    fmt.Printf("  Completed Tasks: %d\n", metric.CompletedTasks)
    fmt.Printf("  Failed Tasks: %d\n", metric.FailedTasks)
    fmt.Printf("  Success Rate: %.2f%%\n", metric.SuccessRate*100)
    fmt.Printf("  Average Run Time: %v\n", metric.AverageRunTime)
    fmt.Println()
}
```

### Task Templates

```go
// Create a task template
template := &types.TaskTemplate{
    ID:          "report-template",
    Name:        "Report Template",
    Description: "Template for generating reports",
    Handler: &types.TaskHandler{
        Type: types.HandlerTypeHTTP,
        HTTP: &types.HTTPHandler{
            URL:     "https://api.example.com/reports/{{.report_type}}",
            Method:  "POST",
            Headers: map[string]string{
                "Authorization": "Bearer {{.token}}",
                "Content-Type":  "application/json",
            },
            Body: `{"type": "{{.report_type}}", "date": "{{.date}}"}`,
        },
    },
    RetryPolicy: &types.RetryPolicy{
        MaxAttempts: 3,
        Delay:       5 * time.Second,
        Backoff:     types.BackoffTypeExponential,
    },
    Timeout: 5 * time.Minute,
    Tags:    []string{"report", "template"},
    Variables: map[string]interface{}{
        "report_type": "daily",
        "token":       "default_token",
        "date":        "{{.date}}",
    },
}

// Create task from template
task := &types.Task{
    ID:          "daily-sales-report",
    Name:        "Daily Sales Report",
    Description: "Generate daily sales report",
    Schedule: &types.Schedule{
        Type:     types.ScheduleTypeCron,
        CronExpr: "0 9 * * *",
    },
    Handler: &types.TaskHandler{
        Type: types.HandlerTypeHTTP,
        HTTP: &types.HTTPHandler{
            URL:     "https://api.example.com/reports/sales",
            Method:  "POST",
            Headers: map[string]string{
                "Authorization": "Bearer sales_token",
                "Content-Type":  "application/json",
            },
            Body: `{"type": "sales", "date": "{{.date}}"}`,
        },
    },
    RetryPolicy: template.RetryPolicy,
    Timeout:     template.Timeout,
    Tags:        []string{"report", "sales", "daily"},
}
```

### Error Handling

```go
result, err := manager.ScheduleTask(ctx, task, "cron")
if err != nil {
    // Handle different types of errors
    switch {
    case strings.Contains(err.Error(), "provider not found"):
        log.Printf("Scheduling provider not found: %v", err)
    case strings.Contains(err.Error(), "invalid schedule"):
        log.Printf("Invalid schedule configuration: %v", err)
    case strings.Contains(err.Error(), "failed to schedule task after"):
        log.Printf("Task scheduling failed after retries: %v", err)
    default:
        log.Printf("Task scheduling failed: %v", err)
    }
    return
}

// Handle task result
if result.Status == types.TaskStatusScheduled {
    fmt.Printf("Task scheduled successfully: %s\n", result.TaskID)
    if result.NextRun != nil {
        fmt.Printf("Next run: %v\n", result.NextRun)
    }
} else {
    fmt.Printf("Task scheduling failed: %s\n", result.Message)
}
```

### Configuration Management

```go
// Custom configuration
config := &scheduling.ManagerConfig{
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

manager := scheduling.NewSchedulingManager(config, logger)
```

## Best Practices

1. **Task Naming**: Use descriptive, hierarchical task names
2. **Schedule Design**: Choose appropriate schedule types for different use cases
3. **Retry Policies**: Implement appropriate retry strategies for different task types
4. **Error Handling**: Implement comprehensive error handling for all operations
5. **Monitoring**: Monitor task execution and provider health
6. **Resource Management**: Use appropriate timeouts and resource limits
7. **Testing**: Test task scheduling in different scenarios
8. **Documentation**: Document task configurations and dependencies
9. **Security**: Secure task handlers and sensitive data
10. **Performance**: Optimize task scheduling for high throughput

## Contributing

Contributions are welcome! Please read the contributing guidelines and submit pull requests for any improvements.

## License

This library is licensed under the MIT License. See the LICENSE file for details.
