# Messaging Library

The Messaging library provides a unified interface for messaging operations across multiple providers including Kafka, NATS, RabbitMQ, and SQS. It offers comprehensive messaging capabilities with pub/sub, request/reply, message routing, filtering, and advanced features like batching, partitioning, and dead letter queues.

## Features

- **Multi-Provider Support**: Kafka, NATS, RabbitMQ, SQS, and more
- **Pub/Sub Messaging**: Publish and subscribe to topics
- **Request/Reply**: Synchronous request-reply patterns
- **Message Routing**: Advanced message routing and filtering
- **Batch Operations**: Efficient batch publishing and processing
- **Message Ordering**: Guaranteed message ordering and deduplication
- **Dead Letter Queues**: Automatic handling of failed messages
- **Message Scheduling**: Delayed and scheduled message delivery
- **Priority Queues**: Message priority handling
- **Health Monitoring**: Provider health checks and statistics

## Supported Providers

- **Kafka**: Apache Kafka with advanced features
- **NATS**: NATS messaging system
- **RabbitMQ**: RabbitMQ message broker
- **SQS**: Amazon Simple Queue Service
- **Custom**: Custom messaging providers

## Installation

```bash
go get github.com/anasamu/go-micro-libs/messaging
```

## Quick Start

```go
package main

import (
    "context"
    "fmt"
    "log"
    "time"

    "github.com/anasamu/go-micro-libs/messaging"
    "github.com/anasamu/go-micro-libs/messaging/types"
    "github.com/sirupsen/logrus"
)

func main() {
    // Create logger
    logger := logrus.New()

    // Create messaging manager with default config
    config := messaging.DefaultManagerConfig()
    manager := messaging.NewMessagingManager(config, logger)

    // Register Kafka provider (example)
    // kafkaProvider := kafka.NewKafkaProvider("localhost:9092")
    // manager.RegisterProvider(kafkaProvider)

    // Connect to messaging system
    ctx := context.Background()
    err := manager.Connect(ctx, "kafka")
    if err != nil {
        log.Fatal(err)
    }

    // Publish a message
    message := messaging.CreateMessage("user.created", "user-service", "notification-service", "users", 
        map[string]interface{}{
            "user_id": "123",
            "name":    "John Doe",
            "email":   "john@example.com",
        })

    publishReq := &types.PublishRequest{
        Topic:   "users",
        Message: message,
    }

    response, err := manager.PublishMessage(ctx, "kafka", publishReq)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Message published: %s\n", response.MessageID)
}
```

## API Reference

### MessagingManager

The main manager for handling messaging operations across multiple providers.

#### Methods

##### `NewMessagingManager(config *ManagerConfig, logger *logrus.Logger) *MessagingManager`
Creates a new messaging manager with the given configuration and logger.

##### `RegisterProvider(provider MessagingProvider) error`
Registers a new messaging provider.

**Parameters:**
- `provider`: The messaging provider to register

**Returns:**
- `error`: Any error that occurred during registration

##### `GetProvider(name string) (MessagingProvider, error)`
Retrieves a specific provider by name.

##### `GetDefaultProvider() (MessagingProvider, error)`
Returns the default messaging provider.

##### `Connect(ctx context.Context, providerName string) error`
Connects to a messaging system using the specified provider.

##### `Disconnect(ctx context.Context, providerName string) error`
Disconnects from a messaging system using the specified provider.

##### `Ping(ctx context.Context, providerName string) error`
Pings a messaging system to check connectivity.

##### `PublishMessage(ctx context.Context, providerName string, request *types.PublishRequest) (*types.PublishResponse, error)`
Publishes a message using the specified provider.

**Parameters:**
- `ctx`: Context for cancellation and timeouts
- `providerName`: Name of the provider to use
- `request`: Publish request with topic and message

**Returns:**
- `*types.PublishResponse`: Publish response with message ID and metadata
- `error`: Any error that occurred

##### `SubscribeToTopic(ctx context.Context, providerName string, request *types.SubscribeRequest, handler types.MessageHandler) error`
Subscribes to a topic using the specified provider.

##### `UnsubscribeFromTopic(ctx context.Context, providerName string, request *types.UnsubscribeRequest) error`
Unsubscribes from a topic using the specified provider.

##### `CreateTopic(ctx context.Context, providerName string, request *types.CreateTopicRequest) error`
Creates a topic using the specified provider.

##### `DeleteTopic(ctx context.Context, providerName string, request *types.DeleteTopicRequest) error`
Deletes a topic using the specified provider.

##### `TopicExists(ctx context.Context, providerName string, request *types.TopicExistsRequest) (bool, error)`
Checks if a topic exists using the specified provider.

##### `ListTopics(ctx context.Context, providerName string) ([]types.TopicInfo, error)`
Lists topics using the specified provider.

##### `PublishBatch(ctx context.Context, providerName string, request *types.PublishBatchRequest) (*types.PublishBatchResponse, error)`
Publishes multiple messages in a batch.

##### `GetTopicInfo(ctx context.Context, providerName string, request *types.GetTopicInfoRequest) (*types.TopicInfo, error)`
Gets topic information using the specified provider.

##### `HealthCheck(ctx context.Context) map[string]error`
Performs health check on all providers.

##### `GetStats(ctx context.Context, providerName string) (*types.MessagingStats, error)`
Gets statistics from a specific provider.

##### `GetSupportedProviders() []string`
Returns a list of registered providers.

##### `GetProviderCapabilities(providerName string) ([]types.MessagingFeature, *types.ConnectionInfo, error)`
Returns capabilities of a specific provider.

##### `Close() error`
Closes all messaging connections.

### Types

#### ManagerConfig
Configuration for the messaging manager.

```go
type ManagerConfig struct {
    DefaultProvider string            `json:"default_provider"`
    RetryAttempts   int               `json:"retry_attempts"`
    RetryDelay      time.Duration     `json:"retry_delay"`
    Timeout         time.Duration     `json:"timeout"`
    MaxMessageSize  int64             `json:"max_message_size"`
    Metadata        map[string]string `json:"metadata"`
}
```

#### Message
Represents a unified message structure.

```go
type Message struct {
    ID            uuid.UUID              `json:"id"`
    Type          string                 `json:"type"`
    Source        string                 `json:"source"`
    Target        string                 `json:"target"`
    Topic         string                 `json:"topic"`
    RoutingKey    string                 `json:"routing_key,omitempty"`
    Payload       map[string]interface{} `json:"payload"`
    Headers       map[string]interface{} `json:"headers,omitempty"`
    Metadata      map[string]interface{} `json:"metadata,omitempty"`
    CreatedAt     time.Time              `json:"created_at"`
    ExpiresAt     *time.Time             `json:"expires_at,omitempty"`
    ScheduledAt   *time.Time             `json:"scheduled_at,omitempty"`
    Priority      int                    `json:"priority,omitempty"`
    TTL           *time.Duration         `json:"ttl,omitempty"`
    CorrelationID string                 `json:"correlation_id,omitempty"`
    ReplyTo       string                 `json:"reply_to,omitempty"`
    ProviderData  map[string]interface{} `json:"provider_data,omitempty"`
}
```

#### PublishRequest
Represents a publish message request.

```go
type PublishRequest struct {
    Topic      string                 `json:"topic"`
    Message    *Message               `json:"message"`
    RoutingKey string                 `json:"routing_key,omitempty"`
    Headers    map[string]interface{} `json:"headers,omitempty"`
    Options    map[string]interface{} `json:"options,omitempty"`
}
```

#### PublishResponse
Represents a publish message response.

```go
type PublishResponse struct {
    MessageID    string                 `json:"message_id"`
    Topic        string                 `json:"topic"`
    Partition    int                    `json:"partition,omitempty"`
    Offset       int64                  `json:"offset,omitempty"`
    Timestamp    time.Time              `json:"timestamp"`
    ProviderData map[string]interface{} `json:"provider_data,omitempty"`
}
```

#### SubscribeRequest
Represents a subscribe request.

```go
type SubscribeRequest struct {
    Topic         string                 `json:"topic"`
    GroupID       string                 `json:"group_id,omitempty"`
    ConsumerID    string                 `json:"consumer_id,omitempty"`
    AutoAck       bool                   `json:"auto_ack"`
    PrefetchCount int                    `json:"prefetch_count,omitempty"`
    StartOffset   string                 `json:"start_offset,omitempty"`
    Filter        map[string]interface{} `json:"filter,omitempty"`
    Options       map[string]interface{} `json:"options,omitempty"`
}
```

#### MessageHandler
Handles incoming messages.

```go
type MessageHandler func(ctx context.Context, message *Message) error
```

#### MessagingStats
Messaging statistics.

```go
type MessagingStats struct {
    PublishedMessages   int64                  `json:"published_messages"`
    ConsumedMessages    int64                  `json:"consumed_messages"`
    FailedMessages      int64                  `json:"failed_messages"`
    ActiveConnections   int                    `json:"active_connections"`
    ActiveSubscriptions int                    `json:"active_subscriptions"`
    ProviderData        map[string]interface{} `json:"provider_data"`
}
```

## Advanced Usage

### Basic Pub/Sub

```go
// Publish a message
message := messaging.CreateMessage("user.created", "user-service", "notification-service", "users", 
    map[string]interface{}{
        "user_id": "123",
        "name":    "John Doe",
        "email":   "john@example.com",
    })

publishReq := &types.PublishRequest{
    Topic:   "users",
    Message: message,
}

response, err := manager.PublishMessage(ctx, "kafka", publishReq)
if err != nil {
    log.Fatal(err)
}

// Subscribe to messages
handler := func(ctx context.Context, message *types.Message) error {
    fmt.Printf("Received message: %s from %s\n", message.Type, message.Source)
    fmt.Printf("Payload: %+v\n", message.Payload)
    return nil
}

subscribeReq := &types.SubscribeRequest{
    Topic:      "users",
    GroupID:    "notification-service",
    AutoAck:    true,
}

err = manager.SubscribeToTopic(ctx, "kafka", subscribeReq, handler)
if err != nil {
    log.Fatal(err)
}
```

### Message with Headers and Metadata

```go
// Create message with headers and metadata
message := messaging.CreateMessage("order.processed", "order-service", "inventory-service", "orders", 
    map[string]interface{}{
        "order_id": "12345",
        "items":    []string{"item1", "item2"},
        "total":    99.99,
    })

// Add headers
message.AddHeader("priority", "high")
message.AddHeader("retry_count", 0)
message.AddHeader("correlation_id", "req-123")

// Add metadata
message.AddMetadata("tenant_id", "tenant-123")
message.AddMetadata("environment", "production")

// Set message properties
message.SetPriority(10)
message.SetTTL(24 * time.Hour)
message.SetCorrelationID("req-123")

publishReq := &types.PublishRequest{
    Topic:   "orders",
    Message: message,
}

response, err := manager.PublishMessage(ctx, "kafka", publishReq)
```

### Batch Publishing

```go
// Create multiple messages
messages := []*types.Message{
    messaging.CreateMessage("user.created", "user-service", "email-service", "users", 
        map[string]interface{}{"user_id": "1", "email": "user1@example.com"}),
    messaging.CreateMessage("user.created", "user-service", "email-service", "users", 
        map[string]interface{}{"user_id": "2", "email": "user2@example.com"}),
    messaging.CreateMessage("user.created", "user-service", "email-service", "users", 
        map[string]interface{}{"user_id": "3", "email": "user3@example.com"}),
}

// Publish batch
batchReq := &types.PublishBatchRequest{
    Topic:    "users",
    Messages: messages,
}

response, err := manager.PublishBatch(ctx, "kafka", batchReq)
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Published %d messages, %d failed\n", response.PublishedCount, response.FailedCount)
```

### Request/Reply Pattern

```go
// Request handler
requestHandler := func(ctx context.Context, message *types.Message) error {
    // Process request
    userID := message.Payload["user_id"].(string)
    user := getUserFromDatabase(userID)
    
    // Send reply
    replyMessage := messaging.CreateMessage("user.info", "user-service", message.Source, "replies", 
        map[string]interface{}{
            "user_id": user.ID,
            "name":    user.Name,
            "email":   user.Email,
        })
    
    replyMessage.SetCorrelationID(message.CorrelationID)
    
    replyReq := &types.PublishRequest{
        Topic:   "replies",
        Message: replyMessage,
    }
    
    _, err := manager.PublishMessage(ctx, "kafka", replyReq)
    return err
}

// Subscribe to requests
subscribeReq := &types.SubscribeRequest{
    Topic:   "user.requests",
    GroupID: "user-service",
    AutoAck: true,
}

err := manager.SubscribeToTopic(ctx, "kafka", subscribeReq, requestHandler)

// Send request and wait for reply
requestMessage := messaging.CreateMessage("user.request", "client-service", "user-service", "user.requests", 
    map[string]interface{}{"user_id": "123"})

requestMessage.SetCorrelationID("req-123")
requestMessage.SetReplyTo("replies")

publishReq := &types.PublishRequest{
    Topic:   "user.requests",
    Message: requestMessage,
}

_, err = manager.PublishMessage(ctx, "kafka", publishReq)
```

### Message Filtering

```go
// Subscribe with filter
subscribeReq := &types.SubscribeRequest{
    Topic:   "orders",
    GroupID: "inventory-service",
    Filter: map[string]interface{}{
        "order_type": "inventory",
        "priority":   "high",
    },
    AutoAck: true,
}

handler := func(ctx context.Context, message *types.Message) error {
    // Only high-priority inventory orders will be processed
    fmt.Printf("Processing inventory order: %+v\n", message.Payload)
    return nil
}

err := manager.SubscribeToTopic(ctx, "kafka", subscribeReq, handler)
```

### Delayed Message Delivery

```go
// Schedule message for future delivery
message := messaging.CreateMessage("reminder.send", "reminder-service", "email-service", "reminders", 
    map[string]interface{}{
        "user_id": "123",
        "message": "Don't forget your appointment tomorrow!",
    })

// Schedule for 1 hour from now
message.SetScheduledTime(time.Now().Add(1 * time.Hour))

publishReq := &types.PublishRequest{
    Topic:   "reminders",
    Message: message,
}

response, err := manager.PublishMessage(ctx, "kafka", publishReq)
```

### Topic Management

```go
// Create topic
createReq := &types.CreateTopicRequest{
    Topic:             "new-topic",
    Partitions:        3,
    ReplicationFactor: 2,
    RetentionPeriod:   &[]time.Duration{7 * 24 * time.Hour}[0], // 7 days
    Config: map[string]interface{}{
        "cleanup.policy": "delete",
        "compression.type": "snappy",
    },
}

err := manager.CreateTopic(ctx, "kafka", createReq)
if err != nil {
    log.Fatal(err)
}

// Check if topic exists
existsReq := &types.TopicExistsRequest{
    Topic: "new-topic",
}

exists, err := manager.TopicExists(ctx, "kafka", existsReq)
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Topic exists: %v\n", exists)

// List all topics
topics, err := manager.ListTopics(ctx, "kafka")
if err != nil {
    log.Fatal(err)
}

for _, topic := range topics {
    fmt.Printf("Topic: %s, Partitions: %d\n", topic.Name, topic.Partitions)
}

// Get topic info
infoReq := &types.GetTopicInfoRequest{
    Topic: "new-topic",
}

info, err := manager.GetTopicInfo(ctx, "kafka", infoReq)
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Topic info: %+v\n", info)
```

### Error Handling and Retry

```go
// Message handler with error handling
handler := func(ctx context.Context, message *types.Message) error {
    // Process message
    err := processMessage(message)
    if err != nil {
        // Log error
        log.Printf("Failed to process message %s: %v", message.ID, err)
        
        // Check retry count
        retryCount, _ := message.GetHeader("retry_count")
        if retryCount == nil {
            retryCount = 0
        }
        
        count := retryCount.(int)
        if count < 3 {
            // Retry with exponential backoff
            delay := time.Duration(count+1) * time.Minute
            message.SetScheduledTime(time.Now().Add(delay))
            message.AddHeader("retry_count", count+1)
            
            // Republish for retry
            publishReq := &types.PublishRequest{
                Topic:   message.Topic,
                Message: message,
            }
            
            _, retryErr := manager.PublishMessage(ctx, "kafka", publishReq)
            if retryErr != nil {
                log.Printf("Failed to retry message: %v", retryErr)
            }
        } else {
            // Send to dead letter queue
            message.AddHeader("error", err.Error())
            message.AddHeader("failed_at", time.Now().Unix())
            
            dlqReq := &types.PublishRequest{
                Topic:   "dead-letter-queue",
                Message: message,
            }
            
            _, dlqErr := manager.PublishMessage(ctx, "kafka", dlqReq)
            if dlqErr != nil {
                log.Printf("Failed to send to DLQ: %v", dlqErr)
            }
        }
        
        return err
    }
    
    return nil
}
```

### Health Monitoring

```go
// Check health of all providers
healthStatus := manager.HealthCheck(ctx)
for provider, err := range healthStatus {
    if err != nil {
        fmt.Printf("Provider %s is unhealthy: %v\n", provider, err)
    } else {
        fmt.Printf("Provider %s is healthy\n", provider)
    }
}

// Get statistics
stats, err := manager.GetStats(ctx, "kafka")
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Published messages: %d\n", stats.PublishedMessages)
fmt.Printf("Consumed messages: %d\n", stats.ConsumedMessages)
fmt.Printf("Failed messages: %d\n", stats.FailedMessages)
fmt.Printf("Active connections: %d\n", stats.ActiveConnections)
```

### Connection Management

```go
// Connect to multiple providers
providers := []string{"kafka", "rabbitmq", "nats"}

for _, provider := range providers {
    err := manager.Connect(ctx, provider)
    if err != nil {
        log.Printf("Failed to connect to %s: %v", provider, err)
    } else {
        log.Printf("Connected to %s successfully", provider)
    }
}

// Check connected providers
connectedProviders := manager.GetConnectedProviders()
fmt.Printf("Connected providers: %v\n", connectedProviders)

// Check if specific provider is connected
isConnected := manager.IsProviderConnected("kafka")
fmt.Printf("Kafka connected: %v\n", isConnected)
```

## Best Practices

1. **Message Design**: Design messages with clear types and consistent payloads
2. **Error Handling**: Implement comprehensive error handling and retry logic
3. **Dead Letter Queues**: Use DLQs for failed message handling
4. **Message Ordering**: Consider message ordering requirements
5. **Batch Operations**: Use batch operations for better performance
6. **Connection Management**: Properly manage connections and subscriptions
7. **Monitoring**: Monitor message throughput and error rates
8. **Security**: Implement proper authentication and authorization
9. **Schema Evolution**: Plan for message schema evolution
10. **Testing**: Test message handling in different scenarios

## Contributing

Contributions are welcome! Please read the contributing guidelines and submit pull requests for any improvements.

## License

This library is licensed under the MIT License. See the LICENSE file for details.
