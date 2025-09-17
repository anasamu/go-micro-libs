# Event Library

The Event library provides a unified interface for event sourcing operations across multiple providers including Kafka, NATS, and PostgreSQL. It offers comprehensive event sourcing capabilities with support for event storage, retrieval, stream management, snapshots, and advanced features like batch operations, compression, encryption, and comprehensive monitoring.

## Features

- **Multi-Provider Support**: Kafka, NATS, PostgreSQL providers
- **Event Storage**: Append and retrieve events with full metadata
- **Stream Management**: Create, delete, and manage event streams
- **Snapshot Support**: Create and manage snapshots for performance
- **Batch Operations**: Efficient batch event processing
- **Event Retrieval**: Query events by stream, ID, or time range
- **Metadata Support**: Rich event metadata and correlation tracking
- **Compression**: Optional event compression for storage efficiency
- **Encryption**: Optional event encryption for security
- **Retention Management**: Configurable event retention policies
- **Health Monitoring**: Comprehensive health checks and statistics
- **Retry Logic**: Built-in retry mechanisms with configurable policies

## Supported Providers

- **Kafka**: Apache Kafka for high-throughput event streaming
- **NATS**: NATS messaging system for lightweight event processing
- **PostgreSQL**: PostgreSQL for reliable event storage with ACID guarantees
- **Custom**: Custom event sourcing providers

## Installation

```bash
go get github.com/anasamu/go-micro-libs/event
```

## Quick Start

```go
package main

import (
    "context"
    "fmt"
    "log"
    "time"

    "github.com/anasamu/go-micro-libs/event"
    "github.com/anasamu/go-micro-libs/event/types"
    "github.com/sirupsen/logrus"
)

func main() {
    // Create logger
    logger := logrus.New()
    logger.SetLevel(logrus.InfoLevel)

    // Create event sourcing manager
    config := &event.ManagerConfig{
        DefaultProvider:   "postgresql",
        RetryAttempts:     3,
        RetryDelay:        time.Second,
        Timeout:           30 * time.Second,
        MaxEventSize:      1024 * 1024, // 1MB
        MaxBatchSize:      100,
        SnapshotThreshold: 1000,
        RetentionPeriod:   365 * 24 * time.Hour, // 1 year
        Compression:       false,
        Encryption:        false,
    }

    manager := event.NewEventSourcingManager(config, logger)

    // Register providers (example with PostgreSQL)
    // postgresProvider := postgresql.NewProvider(postgresqlConfig)
    // manager.RegisterProvider(postgresProvider)

    ctx := context.Background()

    // Create a stream
    createStreamReq := &types.CreateStreamRequest{
        StreamID:      "user-events",
        Name:          "User Events Stream",
        AggregateID:   "user-123",
        AggregateType: "User",
        Metadata: map[string]interface{}{
            "description": "Stream for user-related events",
            "version":     "1.0",
        },
    }

    if err := manager.CreateStream(ctx, createStreamReq); err != nil {
        log.Fatalf("Failed to create stream: %v", err)
    }

    // Append an event
    appendEventReq := &types.AppendEventRequest{
        StreamID:      "user-events",
        EventType:     "UserCreated",
        EventData: map[string]interface{}{
            "user_id":    "user-123",
            "email":      "user@example.com",
            "name":       "John Doe",
            "created_at": time.Now(),
        },
        EventMetadata: map[string]interface{}{
            "source":     "user-service",
            "version":    "1.0",
            "correlation_id": "req-456",
        },
        CorrelationID: "req-456",
        CausationID:   "cmd-789",
        UserID:        "admin",
        TenantID:      "tenant-1",
        AggregateID:   "user-123",
        AggregateType: "User",
    }

    response, err := manager.AppendEvent(ctx, appendEventReq)
    if err != nil {
        log.Fatalf("Failed to append event: %v", err)
    }

    fmt.Printf("Event appended successfully: %s\n", response.EventID)

    // Retrieve events
    getEventsReq := &types.GetEventsRequest{
        StreamID: "user-events",
        Limit:    10,
        Offset:   0,
    }

    events, err := manager.GetEvents(ctx, getEventsReq)
    if err != nil {
        log.Fatalf("Failed to get events: %v", err)
    }

    fmt.Printf("Retrieved %d events\n", len(events.Events))
    for _, event := range events.Events {
        fmt.Printf("Event: %s - %s\n", event.EventType, event.EventID)
    }

    // Create a snapshot
    createSnapshotReq := &types.CreateSnapshotRequest{
        StreamID:    "user-events",
        AggregateID: "user-123",
        Data: map[string]interface{}{
            "user_id":    "user-123",
            "email":      "user@example.com",
            "name":       "John Doe",
            "version":    1,
            "created_at": time.Now(),
        },
        Metadata: map[string]interface{}{
            "description": "Initial user state",
            "version":     "1.0",
        },
    }

    snapshotResp, err := manager.CreateSnapshot(ctx, createSnapshotReq)
    if err != nil {
        log.Fatalf("Failed to create snapshot: %v", err)
    }

    fmt.Printf("Snapshot created: %s\n", snapshotResp.SnapshotID)

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
    DefaultProvider   string            `json:"default_provider"`
    RetryAttempts     int               `json:"retry_attempts"`
    RetryDelay        time.Duration     `json:"retry_delay"`
    Timeout           time.Duration     `json:"timeout"`
    MaxEventSize      int64             `json:"max_event_size"`
    MaxBatchSize      int               `json:"max_batch_size"`
    SnapshotThreshold int64             `json:"snapshot_threshold"`
    RetentionPeriod   time.Duration     `json:"retention_period"`
    Compression       bool              `json:"compression"`
    Encryption        bool              `json:"encryption"`
    Metadata          map[string]string `json:"metadata"`
}
```

### Provider Configuration

Each provider has its own configuration structure. Refer to the specific provider documentation for details.

## API Reference

### Core Operations

#### Stream Management
- `CreateStream(ctx, request)` - Create a new event stream
- `DeleteStream(ctx, request)` - Delete an event stream
- `StreamExists(ctx, request)` - Check if a stream exists
- `ListStreams(ctx)` - List all available streams
- `GetStreamInfo(ctx, request)` - Get stream information

#### Event Operations
- `AppendEvent(ctx, request)` - Append a single event
- `AppendEventsBatch(ctx, request)` - Append multiple events
- `GetEvents(ctx, request)` - Retrieve events with filtering
- `GetEventByID(ctx, request)` - Get a specific event by ID
- `GetEventsByStream(ctx, request)` - Get events from a specific stream

#### Snapshot Operations
- `CreateSnapshot(ctx, request)` - Create a snapshot
- `GetSnapshot(ctx, request)` - Retrieve a snapshot
- `DeleteSnapshot(ctx, request)` - Delete a snapshot

### Provider Management
- `RegisterProvider(provider)` - Register a new provider
- `GetProvider(name)` - Get a specific provider
- `GetDefaultProvider()` - Get the default provider
- `ListProviders()` - List all registered providers
- `GetProviderInfo()` - Get provider information

### Monitoring and Health
- `GetStats(ctx)` - Get statistics from all providers
- `HealthCheck(ctx)` - Perform health checks
- `Close()` - Close all providers

## Event Structure

```go
type Event struct {
    EventID       string                 `json:"event_id"`
    StreamID      string                 `json:"stream_id"`
    EventType     string                 `json:"event_type"`
    EventData     map[string]interface{} `json:"event_data"`
    EventMetadata map[string]interface{} `json:"event_metadata"`
    Version       int64                  `json:"version"`
    Timestamp     time.Time              `json:"timestamp"`
    CorrelationID string                 `json:"correlation_id"`
    CausationID   string                 `json:"causation_id"`
    UserID        string                 `json:"user_id"`
    TenantID      string                 `json:"tenant_id"`
    AggregateID   string                 `json:"aggregate_id"`
    AggregateType string                 `json:"aggregate_type"`
}
```

## Stream Structure

```go
type StreamInfo struct {
    StreamID      string                 `json:"stream_id"`
    Name          string                 `json:"name"`
    AggregateID   string                 `json:"aggregate_id"`
    AggregateType string                 `json:"aggregate_type"`
    Version       int64                  `json:"version"`
    CreatedAt     time.Time              `json:"created_at"`
    UpdatedAt     time.Time              `json:"updated_at"`
    Metadata      map[string]interface{} `json:"metadata"`
    EventCount    int64                  `json:"event_count"`
    LastEventID   string                 `json:"last_event_id"`
}
```

## Snapshot Structure

```go
type Snapshot struct {
    SnapshotID    string                 `json:"snapshot_id"`
    StreamID      string                 `json:"stream_id"`
    AggregateID   string                 `json:"aggregate_id"`
    Version       int64                  `json:"version"`
    Data          map[string]interface{} `json:"data"`
    Metadata      map[string]interface{} `json:"metadata"`
    CreatedAt     time.Time              `json:"created_at"`
}
```

## Error Handling

The library provides comprehensive error handling with specific error types:

```go
type EventSourcingError struct {
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
- `ErrorTypeConflict` - Conflict errors
- `ErrorTypeTimeout` - Timeout errors
- `ErrorTypeInternal` - Internal server errors

## Best Practices

### Event Design
1. **Immutable Events**: Events should be immutable once created
2. **Meaningful Event Types**: Use descriptive event type names
3. **Rich Metadata**: Include correlation IDs and causation IDs
4. **Versioning**: Implement proper event versioning strategies

### Stream Management
1. **Aggregate Boundaries**: Align streams with aggregate boundaries
2. **Naming Conventions**: Use consistent naming for streams
3. **Lifecycle Management**: Properly manage stream lifecycle

### Performance Optimization
1. **Batch Operations**: Use batch operations for multiple events
2. **Snapshots**: Create snapshots for frequently accessed aggregates
3. **Compression**: Enable compression for large events
4. **Retention Policies**: Implement appropriate retention policies

### Monitoring
1. **Health Checks**: Regular health checks for all providers
2. **Statistics**: Monitor event throughput and latency
3. **Error Tracking**: Track and alert on errors
4. **Performance Metrics**: Monitor performance metrics

## Examples

### E-commerce Order Processing

```go
// Create order stream
createStreamReq := &types.CreateStreamRequest{
    StreamID:      "order-123",
    Name:          "Order Events",
    AggregateID:   "order-123",
    AggregateType: "Order",
}

manager.CreateStream(ctx, createStreamReq)

// Order created event
orderCreatedEvent := &types.AppendEventRequest{
    StreamID:  "order-123",
    EventType: "OrderCreated",
    EventData: map[string]interface{}{
        "order_id":    "order-123",
        "customer_id": "customer-456",
        "items":       []string{"item-1", "item-2"},
        "total":       99.99,
    },
    AggregateID:   "order-123",
    AggregateType: "Order",
}

manager.AppendEvent(ctx, orderCreatedEvent)

// Order paid event
orderPaidEvent := &types.AppendEventRequest{
    StreamID:  "order-123",
    EventType: "OrderPaid",
    EventData: map[string]interface{}{
        "payment_id": "payment-789",
        "amount":     99.99,
        "method":     "credit_card",
    },
    AggregateID:   "order-123",
    AggregateType: "Order",
}

manager.AppendEvent(ctx, orderPaidEvent)
```

### User Management

```go
// User registration events
userRegisteredEvent := &types.AppendEventRequest{
    StreamID:  "user-456",
    EventType: "UserRegistered",
    EventData: map[string]interface{}{
        "user_id":    "user-456",
        "email":      "user@example.com",
        "name":       "Jane Doe",
        "registered_at": time.Now(),
    },
    AggregateID:   "user-456",
    AggregateType: "User",
}

manager.AppendEvent(ctx, userRegisteredEvent)

// User profile updated event
profileUpdatedEvent := &types.AppendEventRequest{
    StreamID:  "user-456",
    EventType: "ProfileUpdated",
    EventData: map[string]interface{}{
        "name":       "Jane Smith",
        "updated_at": time.Now(),
    },
    AggregateID:   "user-456",
    AggregateType: "User",
}

manager.AppendEvent(ctx, profileUpdatedEvent)
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
