# API Library

The API library provides a unified interface for making HTTP requests, GraphQL queries, gRPC calls, and WebSocket connections across multiple providers. It offers comprehensive API management with built-in retry logic, authentication, validation, and monitoring capabilities.

## Features

- **Multi-Protocol Support**: HTTP, GraphQL, gRPC, and WebSocket
- **Provider Management**: Support for multiple API backends
- **Authentication**: Built-in support for various auth methods
- **Retry Logic**: Configurable retry mechanisms with exponential backoff
- **Request Validation**: Automatic request validation and sanitization
- **Batch Operations**: Support for batch requests and responses
- **Streaming**: Real-time streaming for HTTP and WebSocket
- **Monitoring**: Built-in statistics and health monitoring
- **Circuit Breaker**: Automatic circuit breaker patterns
- **Rate Limiting**: Built-in rate limiting capabilities

## Supported Providers

- **HTTP**: Standard HTTP client with advanced features
- **GraphQL**: GraphQL client with query optimization
- **gRPC**: gRPC client with connection pooling
- **WebSocket**: WebSocket client with reconnection logic

## Installation

```bash
go get github.com/anasamu/go-micro-libs/api
```

## Quick Start

```go
package main

import (
    "context"
    "fmt"
    "log"
    "time"

    "github.com/anasamu/go-micro-libs/api"
    "github.com/anasamu/go-micro-libs/api/types"
    "github.com/sirupsen/logrus"
)

func main() {
    // Create logger
    logger := logrus.New()

    // Create API manager with default config
    config := api.DefaultManagerConfig()
    manager := api.NewAPIManager(config, logger)

    // Register HTTP provider (example)
    // httpProvider := http.NewHTTPProvider()
    // manager.RegisterProvider(httpProvider)

    // Create HTTP request
    ctx := context.Background()
    request := types.CreateAPIRequest(types.MethodGET, "https://api.example.com/users")
    request.AddHeader("Content-Type", "application/json")
    request.SetTimeout(30 * time.Second)

    // Send request
    response, err := manager.SendRequest(ctx, "http", request)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Status: %d\n", response.StatusCode)
    fmt.Printf("Body: %v\n", response.Body)
}
```

## API Reference

### APIManager

The main manager for handling API operations across multiple providers.

#### Methods

##### `NewAPIManager(config *ManagerConfig, logger *logrus.Logger) *APIManager`
Creates a new API manager with the given configuration and logger.

##### `RegisterProvider(provider APIProvider) error`
Registers a new API provider.

**Parameters:**
- `provider`: The API provider to register

**Returns:**
- `error`: Any error that occurred during registration

##### `GetProvider(name string) (APIProvider, error)`
Retrieves a specific provider by name.

##### `GetDefaultProvider() (APIProvider, error)`
Returns the default API provider.

##### `Connect(ctx context.Context, providerName string) error`
Connects to an API system using the specified provider.

##### `Disconnect(ctx context.Context, providerName string) error`
Disconnects from an API system using the specified provider.

##### `Ping(ctx context.Context, providerName string) error`
Pings an API system to check connectivity.

##### `SendRequest(ctx context.Context, providerName string, request *types.APIRequest) (*types.APIResponse, error)`
Sends an HTTP request using the specified provider.

**Parameters:**
- `ctx`: Context for cancellation and timeouts
- `providerName`: Name of the provider to use
- `request`: HTTP request with method, URL, headers, and body

**Returns:**
- `*types.APIResponse`: HTTP response with status, headers, and body
- `error`: Any error that occurred

##### `SendBatch(ctx context.Context, providerName string, request *types.BatchRequest) (*types.BatchResponse, error)`
Sends multiple HTTP requests in a batch.

##### `SendGraphQLRequest(ctx context.Context, providerName string, request *types.GraphQLRequest) (*types.GraphQLResponse, error)`
Sends a GraphQL request using the specified provider.

##### `SendgRPCRequest(ctx context.Context, providerName string, request *types.GRPCRequest) (*types.GRPCResponse, error)`
Sends a gRPC request using the specified provider.

##### `ConnectWebSocket(ctx context.Context, providerName string, request *types.WebSocketRequest) (*types.WebSocketResponse, error)`
Connects to a WebSocket using the specified provider.

##### `SendWebSocketMessage(ctx context.Context, providerName string, request *types.WebSocketRequest, message interface{}) (*types.WebSocketResponse, error)`
Sends a message through WebSocket.

##### `CloseWebSocket(ctx context.Context, providerName string, request *types.WebSocketRequest) error`
Closes a WebSocket connection.

##### `StreamRequest(ctx context.Context, providerName string, request *types.APIRequest, handler types.APIHandler) error`
Streams an API request with real-time response handling.

##### `WebSocketStream(ctx context.Context, providerName string, request *types.WebSocketRequest, handler types.WebSocketHandler) error`
Streams WebSocket messages with real-time handling.

##### `HealthCheck(ctx context.Context) map[string]error`
Performs health check on all providers.

##### `GetStats(ctx context.Context, providerName string) (*types.APIStats, error)`
Gets statistics from a specific provider.

##### `GetSupportedProviders() []string`
Returns a list of registered providers.

##### `GetProviderCapabilities(providerName string) ([]types.APIFeature, *types.ConnectionInfo, error)`
Returns capabilities of a specific provider.

##### `Close() error`
Closes all API connections.

### Types

#### ManagerConfig
Configuration for the API manager.

```go
type ManagerConfig struct {
    DefaultProvider string            `json:"default_provider"`
    RetryAttempts   int               `json:"retry_attempts"`
    RetryDelay      time.Duration     `json:"retry_delay"`
    Timeout         time.Duration     `json:"timeout"`
    MaxRequestSize  int64             `json:"max_request_size"`
    Metadata        map[string]string `json:"metadata"`
}
```

#### APIRequest
Represents an HTTP request.

```go
type APIRequest struct {
    ID          uuid.UUID              `json:"id"`
    Method      HTTPMethod             `json:"method"`
    URL         string                 `json:"url"`
    Headers     []Header               `json:"headers,omitempty"`
    QueryParams []QueryParam           `json:"query_params,omitempty"`
    Body        interface{}            `json:"body,omitempty"`
    FormData    []FormData             `json:"form_data,omitempty"`
    Files       []FileUpload           `json:"files,omitempty"`
    Auth        *Authentication        `json:"auth,omitempty"`
    Timeout     time.Duration          `json:"timeout,omitempty"`
    Retries     int                    `json:"retries,omitempty"`
    Metadata    map[string]interface{} `json:"metadata,omitempty"`
    CreatedAt   time.Time              `json:"created_at"`
}
```

#### APIResponse
Represents an HTTP response.

```go
type APIResponse struct {
    ID          uuid.UUID              `json:"id"`
    RequestID   uuid.UUID              `json:"request_id"`
    StatusCode  int                    `json:"status_code"`
    Headers     []Header               `json:"headers,omitempty"`
    Body        interface{}            `json:"body,omitempty"`
    RawBody     []byte                 `json:"raw_body,omitempty"`
    ContentType string                 `json:"content_type,omitempty"`
    Size        int64                  `json:"size"`
    Duration    time.Duration          `json:"duration"`
    Success     bool                   `json:"success"`
    Error       string                 `json:"error,omitempty"`
    Metadata    map[string]interface{} `json:"metadata,omitempty"`
    CreatedAt   time.Time              `json:"created_at"`
}
```

#### GraphQLRequest
Represents a GraphQL request.

```go
type GraphQLRequest struct {
    ID        uuid.UUID              `json:"id"`
    Query     string                 `json:"query"`
    Variables map[string]interface{} `json:"variables,omitempty"`
    Operation string                 `json:"operation,omitempty"`
    Headers   []Header               `json:"headers,omitempty"`
    Auth      *Authentication        `json:"auth,omitempty"`
    Timeout   time.Duration          `json:"timeout,omitempty"`
    Metadata  map[string]interface{} `json:"metadata,omitempty"`
    CreatedAt time.Time              `json:"created_at"`
}
```

#### GRPCRequest
Represents a gRPC request.

```go
type GRPCRequest struct {
    ID        uuid.UUID              `json:"id"`
    Service   string                 `json:"service"`
    Method    string                 `json:"method"`
    Data      interface{}            `json:"data,omitempty"`
    Metadata  map[string]string      `json:"metadata,omitempty"`
    Timeout   time.Duration          `json:"timeout,omitempty"`
    Options   map[string]interface{} `json:"options,omitempty"`
    CreatedAt time.Time              `json:"created_at"`
}
```

#### WebSocketRequest
Represents a WebSocket request.

```go
type WebSocketRequest struct {
    ID        uuid.UUID              `json:"id"`
    URL       string                 `json:"url"`
    Headers   []Header               `json:"headers,omitempty"`
    Auth      *Authentication        `json:"auth,omitempty"`
    Protocols []string               `json:"protocols,omitempty"`
    Timeout   time.Duration          `json:"timeout,omitempty"`
    Metadata  map[string]interface{} `json:"metadata,omitempty"`
    CreatedAt time.Time              `json:"created_at"`
}
```

#### Authentication
Authentication configuration.

```go
type Authentication struct {
    Type         AuthType               `json:"type"`
    Username     string                 `json:"username,omitempty"`
    Password     string                 `json:"password,omitempty"`
    Token        string                 `json:"token,omitempty"`
    APIKey       string                 `json:"api_key,omitempty"`
    APIKeyHeader string                 `json:"api_key_header,omitempty"`
    APIKeyQuery  string                 `json:"api_key_query,omitempty"`
    OAuth2       *OAuth2Config          `json:"oauth2,omitempty"`
    JWT          *JWTConfig             `json:"jwt,omitempty"`
    Custom       map[string]interface{} `json:"custom,omitempty"`
}
```

## Advanced Usage

### HTTP Requests with Authentication

```go
// Create request with Bearer token
request := types.CreateAPIRequest(types.MethodGET, "https://api.example.com/protected")
request.SetAuth(&types.Authentication{
    Type:  types.AuthTypeBearer,
    Token: "your-bearer-token",
})

response, err := manager.SendRequest(ctx, "http", request)
```

### GraphQL Queries

```go
// Create GraphQL request
gqlRequest := types.CreateGraphQLRequest(`
    query GetUser($id: ID!) {
        user(id: $id) {
            id
            name
            email
        }
    }
`)
gqlRequest.AddVariable("id", "123")
gqlRequest.SetAuth(&types.Authentication{
    Type:  types.AuthTypeBearer,
    Token: "your-token",
})

response, err := manager.SendGraphQLRequest(ctx, "graphql", gqlRequest)
```

### gRPC Calls

```go
// Create gRPC request
grpcRequest := types.CreateGRPCRequest("UserService", "GetUser")
grpcRequest.Data = map[string]interface{}{
    "id": "123",
}
grpcRequest.AddMetadata("authorization", "Bearer your-token")

response, err := manager.SendgRPCRequest(ctx, "grpc", grpcRequest)
```

### WebSocket Connections

```go
// Create WebSocket request
wsRequest := types.CreateWebSocketRequest("wss://api.example.com/ws")
wsRequest.SetAuth(&types.Authentication{
    Type:  types.AuthTypeBearer,
    Token: "your-token",
})

// Connect
response, err := manager.ConnectWebSocket(ctx, "websocket", wsRequest)
if err != nil {
    log.Fatal(err)
}

// Send message
message := map[string]interface{}{
    "type": "ping",
    "data": "hello",
}
response, err = manager.SendWebSocketMessage(ctx, "websocket", wsRequest, message)
```

### Streaming Requests

```go
// Stream HTTP response
handler := func(response *types.APIResponse) error {
    fmt.Printf("Received chunk: %v\n", response.Body)
    return nil
}

err := manager.StreamRequest(ctx, "http", request, handler)
```

### Batch Requests

```go
// Create batch request
batchRequest := &types.BatchRequest{
    ID: uuid.New(),
    Requests: []types.APIRequest{
        *types.CreateAPIRequest(types.MethodGET, "https://api.example.com/users"),
        *types.CreateAPIRequest(types.MethodGET, "https://api.example.com/posts"),
    },
    CreatedAt: time.Now(),
}

response, err := manager.SendBatch(ctx, "http", batchRequest)
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
stats, err := manager.GetStats(ctx, "http")
if err == nil {
    fmt.Printf("Total requests: %d\n", stats.TotalRequests)
    fmt.Printf("Success rate: %.2f%%\n", float64(stats.SuccessfulRequests)/float64(stats.TotalRequests)*100)
}
```

## Error Handling

The library provides comprehensive error handling:

```go
response, err := manager.SendRequest(ctx, "http", request)
if err != nil {
    // Handle connection errors, timeouts, etc.
    log.Printf("Request failed: %v", err)
    return
}

if !response.Success {
    // Handle HTTP error responses
    log.Printf("HTTP Error: %d - %s", response.StatusCode, response.Error)
    return
}
```

## Best Practices

1. **Connection Management**: Always close connections when done
2. **Timeout Configuration**: Set appropriate timeouts for different operations
3. **Retry Logic**: Configure retry attempts based on your use case
4. **Authentication**: Use secure authentication methods
5. **Error Handling**: Implement comprehensive error handling
6. **Monitoring**: Monitor API usage and performance
7. **Rate Limiting**: Implement rate limiting to avoid overwhelming APIs
8. **Circuit Breaker**: Use circuit breaker patterns for resilience

## Contributing

Contributions are welcome! Please read the contributing guidelines and submit pull requests for any improvements.

## License

This library is licensed under the MIT License. See the LICENSE file for details.