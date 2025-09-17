# Communication Library

The Communication library provides a unified interface for communication operations across multiple providers including HTTP, WebSocket, GraphQL, gRPC, QUIC, and Server-Sent Events. It offers comprehensive communication capabilities with support for various protocols, real-time messaging, broadcasting, connection management, and advanced features like authentication, rate limiting, load balancing, and comprehensive monitoring.

## Features

- **Multi-Protocol Support**: HTTP, HTTPS, WebSocket, GraphQL, gRPC, QUIC, SSE
- **Real-Time Communication**: WebSocket and Server-Sent Events support
- **Message Broadcasting**: Broadcast messages to multiple connections
- **Connection Management**: Active connection tracking and management
- **Authentication**: Built-in authentication support
- **Rate Limiting**: Request rate limiting capabilities
- **Load Balancing**: Load balancing across multiple instances
- **Health Monitoring**: Provider health checks and statistics
- **Middleware Support**: Extensible middleware architecture
- **Static Files**: Static file serving capabilities

## Supported Providers

- **HTTP**: Standard HTTP/HTTPS communication
- **WebSocket**: Real-time bidirectional communication
- **GraphQL**: GraphQL query and mutation handling
- **gRPC**: High-performance RPC communication
- **QUIC**: Next-generation transport protocol
- **SSE**: Server-Sent Events for real-time updates

## Installation

```bash
go get github.com/anasamu/go-micro-libs/communication
```

## Quick Start

```go
package main

import (
    "context"
    "fmt"
    "log"
    "time"

    "github.com/anasamu/go-micro-libs/communication"
    "github.com/sirupsen/logrus"
)

func main() {
    // Create logger
    logger := logrus.New()

    // Create communication manager with default config
    config := communication.DefaultManagerConfig()
    manager := communication.NewCommunicationManager(config, logger)

    // Register HTTP provider (example)
    // httpProvider := http.NewHTTPProvider()
    // manager.RegisterProvider(httpProvider)

    // Start HTTP server
    ctx := context.Background()
    serverConfig := map[string]interface{}{
        "port":     8080,
        "host":     "localhost",
        "protocol": "http",
    }

    err := manager.Start(ctx, "http", serverConfig)
    if err != nil {
        log.Fatal(err)
    }

    // Handle HTTP request
    request := &communication.Request{
        Method: "GET",
        Path:   "/api/users",
        Headers: map[string]string{
            "Content-Type": "application/json",
        },
        QueryParams: map[string]string{
            "limit": "10",
        },
        RemoteAddr: "127.0.0.1:12345",
        UserAgent:  "Go-Client/1.0",
    }

    response, err := manager.HandleRequest(ctx, "http", request)
    if err != nil {
        log.Printf("Failed to handle request: %v", err)
    } else {
        fmt.Printf("Response: %d %s\n", response.StatusCode, string(response.Body))
    }
}
```

## API Reference

### CommunicationManager

The main manager for handling communication operations across multiple providers.

#### Methods

##### `NewCommunicationManager(config *ManagerConfig, logger *logrus.Logger) *CommunicationManager`
Creates a new communication manager with the given configuration and logger.

##### `RegisterProvider(provider CommunicationProvider) error`
Registers a new communication provider.

**Parameters:**
- `provider`: The communication provider to register

**Returns:**
- `error`: Any error that occurred during registration

##### `GetProvider(name string) (CommunicationProvider, error)`
Retrieves a specific provider by name.

##### `GetDefaultProvider() (CommunicationProvider, error)`
Returns the default communication provider.

##### `Start(ctx context.Context, providerName string, config map[string]interface{}) error`
Starts a communication provider.

**Parameters:**
- `ctx`: Context for cancellation and timeouts
- `providerName`: Name of the provider to start
- `config`: Provider configuration

**Returns:**
- `error`: Any error that occurred

##### `Stop(ctx context.Context, providerName string) error`
Stops a communication provider.

##### `HandleRequest(ctx context.Context, providerName string, request *Request) (*Response, error)`
Handles an HTTP request using the specified provider.

**Parameters:**
- `ctx`: Context for cancellation and timeouts
- `providerName`: Name of the provider to use
- `request`: HTTP request to handle

**Returns:**
- `*Response`: HTTP response
- `error`: Any error that occurred

##### `HandleWebSocket(ctx context.Context, providerName string, request *WebSocketRequest) (*WebSocketResponse, error)`
Handles a WebSocket connection using the specified provider.

##### `SendMessage(ctx context.Context, providerName string, request *SendMessageRequest) (*SendMessageResponse, error)`
Sends a message using the specified provider.

##### `BroadcastMessage(ctx context.Context, providerName string, request *BroadcastRequest) (*BroadcastResponse, error)`
Broadcasts a message using the specified provider.

##### `GetConnections(ctx context.Context, providerName string) ([]ConnectionInfo, error)`
Gets connections from a provider.

##### `GetConnectionCount(ctx context.Context, providerName string) (int, error)`
Gets connection count from a provider.

##### `CloseConnection(ctx context.Context, providerName, connectionID string) error`
Closes a connection using the specified provider.

##### `HealthCheck(ctx context.Context) map[string]error`
Performs health check on all providers.

##### `GetStats(ctx context.Context, providerName string) (*CommunicationStats, error)`
Gets statistics from a provider.

##### `GetSupportedProviders() []string`
Returns a list of registered providers.

##### `GetProviderCapabilities(providerName string) ([]CommunicationFeature, *ConnectionInfo, error)`
Returns capabilities of a provider.

##### `Close() error`
Closes all communication connections.

##### `IsProviderRunning(providerName string) bool`
Checks if a provider is running.

##### `GetRunningProviders() []string`
Returns a list of running providers.

### Types

#### ManagerConfig
Configuration for the communication manager.

```go
type ManagerConfig struct {
    DefaultProvider string            `json:"default_provider"`
    RetryAttempts   int               `json:"retry_attempts"`
    RetryDelay      time.Duration     `json:"retry_delay"`
    Timeout         time.Duration     `json:"timeout"`
    MaxConnections  int               `json:"max_connections"`
    Metadata        map[string]string `json:"metadata"`
}
```

#### Request
Represents an HTTP request.

```go
type Request struct {
    Method      string                 `json:"method"`
    Path        string                 `json:"path"`
    Headers     map[string]string      `json:"headers"`
    QueryParams map[string]string      `json:"query_params"`
    PathParams  map[string]string      `json:"path_params"`
    Body        []byte                 `json:"body"`
    RemoteAddr  string                 `json:"remote_addr"`
    UserAgent   string                 `json:"user_agent"`
    UserID      string                 `json:"user_id,omitempty"`
    Metadata    map[string]interface{} `json:"metadata,omitempty"`
}
```

#### Response
Represents an HTTP response.

```go
type Response struct {
    StatusCode int                    `json:"status_code"`
    Headers    map[string]string      `json:"headers"`
    Body       []byte                 `json:"body"`
    Metadata   map[string]interface{} `json:"metadata,omitempty"`
}
```

#### WebSocketRequest
Represents a WebSocket connection request.

```go
type WebSocketRequest struct {
    Path        string                 `json:"path"`
    Headers     map[string]string      `json:"headers"`
    QueryParams map[string]string      `json:"query_params"`
    RemoteAddr  string                 `json:"remote_addr"`
    UserAgent   string                 `json:"user_agent"`
    UserID      string                 `json:"user_id,omitempty"`
    Metadata    map[string]interface{} `json:"metadata,omitempty"`
}
```

#### WebSocketResponse
Represents a WebSocket connection response.

```go
type WebSocketResponse struct {
    ConnectionID string                 `json:"connection_id"`
    Status       int                    `json:"status"`
    Headers      map[string]string      `json:"headers"`
    Metadata     map[string]interface{} `json:"metadata,omitempty"`
}
```

#### Message
Represents a communication message.

```go
type Message struct {
    ID        string                 `json:"id"`
    Type      string                 `json:"type"`
    Content   interface{}            `json:"content"`
    From      string                 `json:"from,omitempty"`
    To        string                 `json:"to,omitempty"`
    Timestamp time.Time              `json:"timestamp"`
    Headers   map[string]interface{} `json:"headers,omitempty"`
    Metadata  map[string]interface{} `json:"metadata,omitempty"`
}
```

#### ConnectionInfo
Represents connection information.

```go
type ConnectionInfo struct {
    ID          string                 `json:"id"`
    Type        string                 `json:"type"`
    RemoteAddr  string                 `json:"remote_addr"`
    UserAgent   string                 `json:"user_agent"`
    ConnectedAt time.Time              `json:"connected_at"`
    LastSeen    time.Time              `json:"last_seen"`
    UserID      string                 `json:"user_id,omitempty"`
    Metadata    map[string]interface{} `json:"metadata,omitempty"`
}
```

#### CommunicationStats
Represents communication statistics.

```go
type CommunicationStats struct {
    TotalConnections    int                    `json:"total_connections"`
    ActiveConnections   int                    `json:"active_connections"`
    TotalRequests       int64                  `json:"total_requests"`
    TotalMessages       int64                  `json:"total_messages"`
    FailedRequests      int64                  `json:"failed_requests"`
    FailedMessages      int64                  `json:"failed_messages"`
    AverageResponseTime time.Duration          `json:"average_response_time"`
    ProviderData        map[string]interface{} `json:"provider_data"`
}
```

## Advanced Usage

### HTTP Server Setup

```go
// Start HTTP server
httpConfig := map[string]interface{}{
    "port":     8080,
    "host":     "0.0.0.0",
    "protocol": "http",
    "cors": map[string]interface{}{
        "enabled":     true,
        "origins":     []string{"*"},
        "methods":     []string{"GET", "POST", "PUT", "DELETE"},
        "headers":     []string{"Content-Type", "Authorization"},
        "credentials": true,
    },
    "compression": map[string]interface{}{
        "enabled": true,
        "level":   6,
    },
    "rate_limiting": map[string]interface{}{
        "enabled": true,
        "requests_per_minute": 100,
    },
}

err := manager.Start(ctx, "http", httpConfig)
if err != nil {
    log.Fatal(err)
}

// Handle different HTTP requests
requests := []*communication.Request{
    {
        Method: "GET",
        Path:   "/api/users",
        Headers: map[string]string{
            "Accept": "application/json",
        },
    },
    {
        Method: "POST",
        Path:   "/api/users",
        Headers: map[string]string{
            "Content-Type": "application/json",
        },
        Body: []byte(`{"name": "John Doe", "email": "john@example.com"}`),
    },
    {
        Method: "PUT",
        Path:   "/api/users/123",
        Headers: map[string]string{
            "Content-Type": "application/json",
        },
        Body: []byte(`{"name": "Jane Doe"}`),
    },
}

for _, req := range requests {
    response, err := manager.HandleRequest(ctx, "http", req)
    if err != nil {
        log.Printf("Request failed: %v", err)
        continue
    }
    fmt.Printf("%s %s: %d\n", req.Method, req.Path, response.StatusCode)
}
```

### WebSocket Communication

```go
// Start WebSocket server
wsConfig := map[string]interface{}{
    "port": 8081,
    "host": "localhost",
    "path": "/ws",
    "authentication": map[string]interface{}{
        "enabled": true,
        "type":    "jwt",
    },
}

err := manager.Start(ctx, "websocket", wsConfig)
if err != nil {
    log.Fatal(err)
}

// Handle WebSocket connection
wsRequest := &communication.WebSocketRequest{
    Path: "/ws",
    Headers: map[string]string{
        "Authorization": "Bearer jwt_token",
    },
    QueryParams: map[string]string{
        "room": "general",
    },
    RemoteAddr: "127.0.0.1:12345",
    UserAgent:  "WebSocket-Client/1.0",
}

wsResponse, err := manager.HandleWebSocket(ctx, "websocket", wsRequest)
if err != nil {
    log.Printf("WebSocket connection failed: %v", err)
} else {
    fmt.Printf("WebSocket connected: %s\n", wsResponse.ConnectionID)
}

// Send message to WebSocket connection
message := communication.CreateMessage("chat", map[string]interface{}{
    "text": "Hello, World!",
    "user": "john_doe",
})
message.SetFrom("server")

sendRequest := &communication.SendMessageRequest{
    ConnectionID: wsResponse.ConnectionID,
    Message:      message,
}

sendResponse, err := manager.SendMessage(ctx, "websocket", sendRequest)
if err != nil {
    log.Printf("Failed to send message: %v", err)
} else {
    fmt.Printf("Message sent: %s\n", sendResponse.MessageID)
}
```

### Message Broadcasting

```go
// Broadcast message to all connections
broadcastMessage := communication.CreateMessage("notification", map[string]interface{}{
    "title":   "System Maintenance",
    "message": "Scheduled maintenance in 10 minutes",
    "type":    "warning",
})

broadcastRequest := &communication.BroadcastRequest{
    Message: broadcastMessage,
    Filter: map[string]interface{}{
        "room": "general",
    },
}

broadcastResponse, err := manager.BroadcastMessage(ctx, "websocket", broadcastRequest)
if err != nil {
    log.Printf("Broadcast failed: %v", err)
} else {
    fmt.Printf("Broadcast sent to %d connections, %d failed\n", 
        broadcastResponse.SentCount, broadcastResponse.FailedCount)
}

// Broadcast with user filter
userBroadcastMessage := communication.CreateMessage("direct_message", map[string]interface{}{
    "text": "You have a new message",
    "from": "admin",
})

userBroadcastRequest := &communication.BroadcastRequest{
    Message: userBroadcastMessage,
    Filter: map[string]interface{}{
        "user_id": "user_123",
    },
}

userBroadcastResponse, err := manager.BroadcastMessage(ctx, "websocket", userBroadcastRequest)
```

### Connection Management

```go
// Get all connections
connections, err := manager.GetConnections(ctx, "websocket")
if err != nil {
    log.Printf("Failed to get connections: %v", err)
    return
}

fmt.Printf("Total connections: %d\n", len(connections))
for _, conn := range connections {
    fmt.Printf("Connection %s: %s (%s) - Last seen: %v\n", 
        conn.ID, conn.RemoteAddr, conn.UserAgent, conn.LastSeen)
    
    if conn.UserID != "" {
        fmt.Printf("  User ID: %s\n", conn.UserID)
    }
    
    if conn.Metadata != nil {
        fmt.Printf("  Metadata: %+v\n", conn.Metadata)
    }
}

// Get connection count
count, err := manager.GetConnectionCount(ctx, "websocket")
if err != nil {
    log.Printf("Failed to get connection count: %v", err)
} else {
    fmt.Printf("Active connections: %d\n", count)
}

// Close specific connection
err = manager.CloseConnection(ctx, "websocket", "conn_123")
if err != nil {
    log.Printf("Failed to close connection: %v", err)
} else {
    fmt.Println("Connection closed successfully")
}
```

### Health Monitoring

```go
// Perform health check on all providers
healthResults := manager.HealthCheck(ctx)
for providerName, err := range healthResults {
    if err != nil {
        fmt.Printf("Provider %s: UNHEALTHY - %v\n", providerName, err)
    } else {
        fmt.Printf("Provider %s: HEALTHY\n", providerName)
    }
}

// Get statistics from a provider
stats, err := manager.GetStats(ctx, "http")
if err != nil {
    log.Printf("Failed to get stats: %v", err)
    return
}

fmt.Printf("HTTP Server Statistics:\n")
fmt.Printf("  Total Connections: %d\n", stats.TotalConnections)
fmt.Printf("  Active Connections: %d\n", stats.ActiveConnections)
fmt.Printf("  Total Requests: %d\n", stats.TotalRequests)
fmt.Printf("  Total Messages: %d\n", stats.TotalMessages)
fmt.Printf("  Failed Requests: %d\n", stats.FailedRequests)
fmt.Printf("  Failed Messages: %d\n", stats.FailedMessages)
fmt.Printf("  Average Response Time: %v\n", stats.AverageResponseTime)

// Get running providers
runningProviders := manager.GetRunningProviders()
fmt.Printf("Running providers: %v\n", runningProviders)

// Check if specific provider is running
isRunning := manager.IsProviderRunning("websocket")
fmt.Printf("WebSocket provider running: %t\n", isRunning)
```

### Advanced Message Handling

```go
// Create message with headers and metadata
message := communication.CreateMessage("data_update", map[string]interface{}{
    "table":    "users",
    "action":   "insert",
    "record_id": 123,
    "data": map[string]interface{}{
        "name":  "John Doe",
        "email": "john@example.com",
    },
})

// Set message properties
message.SetFrom("database_service")
message.SetTo("notification_service")
message.AddHeader("priority", "high")
message.AddHeader("retry_count", 0)
message.AddMetadata("source", "user_registration")
message.AddMetadata("timestamp", time.Now().Unix())

// Send message with retry logic
maxRetries := 3
for attempt := 0; attempt < maxRetries; attempt++ {
    sendRequest := &communication.SendMessageRequest{
        ConnectionID: "conn_456",
        Message:      message,
        Metadata: map[string]interface{}{
            "attempt": attempt + 1,
            "max_retries": maxRetries,
        },
    }

    sendResponse, err := manager.SendMessage(ctx, "websocket", sendRequest)
    if err == nil {
        fmt.Printf("Message sent successfully: %s\n", sendResponse.MessageID)
        break
    }

    if attempt < maxRetries-1 {
        fmt.Printf("Send attempt %d failed, retrying: %v\n", attempt+1, err)
        time.Sleep(time.Duration(attempt+1) * time.Second)
    } else {
        fmt.Printf("All send attempts failed: %v\n", err)
    }
}
```

### Provider Capabilities

```go
// Get provider capabilities
features, connInfo, err := manager.GetProviderCapabilities("http")
if err != nil {
    log.Printf("Failed to get provider capabilities: %v", err)
    return
}

fmt.Printf("HTTP Provider Features:\n")
for _, feature := range features {
    fmt.Printf("  - %s\n", feature)
}

if connInfo != nil {
    fmt.Printf("Connection Info: %+v\n", connInfo)
}

// Get all supported providers
providers := manager.GetSupportedProviders()
fmt.Printf("Supported providers: %v\n", providers)
```

### Error Handling

```go
response, err := manager.HandleRequest(ctx, "http", request)
if err != nil {
    // Handle different types of errors
    switch {
    case strings.Contains(err.Error(), "provider not found"):
        log.Printf("Communication provider not found: %v", err)
    case strings.Contains(err.Error(), "invalid request"):
        log.Printf("Invalid request format: %v", err)
    case strings.Contains(err.Error(), "connection failed"):
        log.Printf("Connection to provider failed: %v", err)
    case strings.Contains(err.Error(), "timeout"):
        log.Printf("Request timeout: %v", err)
    default:
        log.Printf("Communication request failed: %v", err)
    }
    return
}

// Handle response
if response.StatusCode >= 400 {
    fmt.Printf("Request failed with status: %d\n", response.StatusCode)
    fmt.Printf("Error response: %s\n", string(response.Body))
} else {
    fmt.Printf("Request successful: %d\n", response.StatusCode)
    fmt.Printf("Response: %s\n", string(response.Body))
}
```

### Configuration Management

```go
// Custom configuration
config := &communication.ManagerConfig{
    DefaultProvider: "http",
    RetryAttempts:   5,
    RetryDelay:      2 * time.Second,
    Timeout:         60 * time.Second,
    MaxConnections:  5000,
    Metadata: map[string]string{
        "environment": "production",
        "version":     "1.0.0",
    },
}

manager := communication.NewCommunicationManager(config, logger)
```

## Best Practices

1. **Connection Management**: Monitor and manage connections efficiently
2. **Error Handling**: Implement comprehensive error handling for all operations
3. **Rate Limiting**: Use rate limiting to prevent abuse
4. **Authentication**: Implement proper authentication for WebSocket connections
5. **Message Validation**: Validate all incoming messages
6. **Resource Cleanup**: Properly close connections and clean up resources
7. **Monitoring**: Monitor communication statistics and health
8. **Security**: Implement security measures for all communication channels
9. **Performance**: Optimize for high-throughput communication
10. **Testing**: Test communication in different scenarios and network conditions

## Contributing

Contributions are welcome! Please read the contributing guidelines and submit pull requests for any improvements.

## License

This library is licensed under the MIT License. See the LICENSE file for details.
