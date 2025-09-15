# API Library

The API library provides a unified interface for handling third-party API integrations with dynamic headers, requests, and support for multiple protocols including HTTP, GraphQL, and gRPC.

## Features

- **Multi-Protocol Support**: HTTP/HTTPS, GraphQL, gRPC
- **Dynamic Headers**: Add custom headers to any request
- **Flexible Authentication**: Basic, Bearer, API Key, OAuth2, JWT, and custom authentication
- **Request Types**: GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS
- **Content Types**: JSON, XML, Form data, Multipart, Binary
- **Batch Operations**: Send multiple requests in parallel
- **Streaming Support**: Stream large responses
- **Retry Logic**: Built-in retry mechanisms with configurable delays
- **Connection Management**: Automatic connection handling with health checks
- **Error Handling**: Comprehensive error handling and logging
- **Monitoring**: Built-in statistics and health monitoring

## Supported API Features

- HTTP/HTTPS requests
- GraphQL queries and mutations
- gRPC service calls
- WebSocket connections (planned)
- Authentication (Basic, Bearer, API Key, OAuth2, JWT, Custom)
- Rate limiting
- Retry mechanisms
- Circuit breaker patterns
- Request/response transformation
- Pagination support
- Batch processing
- Streaming responses
- File uploads
- Form data submission

## Quick Start

```go
package main

import (
    "context"
    "log"

    "github.com/anasamu/go-micro-libs/api"
    "github.com/anasamu/go-micro-libs/api/providers/http"
    "github.com/anasamu/go-micro-libs/api/types"
    "github.com/sirupsen/logrus"
)

func main() {
    // Create API manager
    apiManager := api.NewAPIManager(nil, logrus.New())

    // Register HTTP provider
    httpProvider := http.NewProvider(logrus.New())
    httpConfig := map[string]interface{}{
        "base_url": "https://api.example.com",
        "timeout":  30,
    }
    httpProvider.Configure(httpConfig)
    apiManager.RegisterProvider(httpProvider)

    // Connect
    ctx := context.Background()
    if err := apiManager.Connect(ctx, "http"); err != nil {
        log.Fatal(err)
    }

    // Send request
    request := types.CreateAPIRequest(types.MethodGET, "https://api.example.com/users")
    request.AddHeader("Accept", "application/json")
    
    response, err := apiManager.SendRequest(ctx, "http", request)
    if err != nil {
        log.Fatal(err)
    }

    log.Printf("Response: %d - %v", response.StatusCode, response.Body)
}
```

## Configuration

### HTTP Provider Configuration

```go
httpConfig := map[string]interface{}{
    "base_url":        "https://api.example.com",    // Base URL for all requests
    "timeout":         30,                           // Request timeout in seconds
    "max_retries":     3,                            // Maximum retry attempts
    "retry_delay":     1,                            // Delay between retries in seconds
    "proxy_url":       "http://proxy:8080",          // Optional proxy URL
    "skip_tls_verify": false,                        // Skip TLS verification
}
```

### GraphQL Provider Configuration

```go
graphqlConfig := map[string]interface{}{
    "endpoint":    "https://api.example.com/graphql", // GraphQL endpoint
    "timeout":     30,                                // Request timeout in seconds
    "max_retries": 3,                                 // Maximum retry attempts
    "retry_delay": 1,                                 // Delay between retries in seconds
}
```

### gRPC Provider Configuration

```go
grpcConfig := map[string]interface{}{
    "address":     "localhost:50051", // gRPC server address
    "use_tls":     false,             // Use TLS encryption
    "timeout":     30,                // Request timeout in seconds
    "max_retries": 3,                 // Maximum retry attempts
    "retry_delay": 1,                 // Delay between retries in seconds
}
```

## Usage Examples

### HTTP Requests

#### GET Request

```go
// Create GET request
request := types.CreateAPIRequest(types.MethodGET, "https://api.example.com/users")
request.AddHeader("Accept", "application/json")
request.AddQueryParam("limit", "10")
request.AddQueryParam("offset", "0")

// Add authentication
auth := &types.Authentication{
    Type:  types.AuthTypeBearer,
    Token: "your-jwt-token",
}
request.SetAuth(auth)

// Send request
response, err := apiManager.SendRequest(ctx, "http", request)
```

#### POST Request with JSON Body

```go
// Create POST request
request := types.CreateAPIRequest(types.MethodPOST, "https://api.example.com/users")
request.AddHeader("Content-Type", "application/json")
request.Body = map[string]interface{}{
    "name":  "John Doe",
    "email": "john@example.com",
}

response, err := apiManager.SendRequest(ctx, "http", request)
```

#### POST Request with Form Data

```go
// Create POST request with form data
request := types.CreateAPIRequest(types.MethodPOST, "https://api.example.com/upload")
request.AddFormData("name", "John Doe")
request.AddFormData("email", "john@example.com")
request.AddFile("avatar", "avatar.jpg", "image/jpeg", imageData)

response, err := apiManager.SendRequest(ctx, "http", request)
```

#### PUT/PATCH Request

```go
// Create PUT request
request := types.CreateAPIRequest(types.MethodPUT, "https://api.example.com/users/123")
request.AddHeader("Content-Type", "application/json")
request.Body = map[string]interface{}{
    "name":  "John Updated",
    "email": "john.updated@example.com",
}

response, err := apiManager.SendRequest(ctx, "http", request)
```

#### DELETE Request

```go
// Create DELETE request
request := types.CreateAPIRequest(types.MethodDELETE, "https://api.example.com/users/123")

response, err := apiManager.SendRequest(ctx, "http", request)
```

### Authentication

#### Bearer Token Authentication

```go
auth := &types.Authentication{
    Type:  types.AuthTypeBearer,
    Token: "your-jwt-token",
}
request.SetAuth(auth)
```

#### Basic Authentication

```go
auth := &types.Authentication{
    Type:     types.AuthTypeBasic,
    Username: "username",
    Password: "password",
}
request.SetAuth(auth)
```

#### API Key Authentication

```go
auth := &types.Authentication{
    Type:         types.AuthTypeAPIKey,
    APIKey:       "your-api-key",
    APIKeyHeader: "X-API-Key", // or APIKeyQuery for query parameter
}
request.SetAuth(auth)
```

#### OAuth2 Authentication

```go
auth := &types.Authentication{
    Type: types.AuthTypeOAuth2,
    OAuth2: &types.OAuth2Config{
        ClientID:     "your-client-id",
        ClientSecret: "your-client-secret",
        TokenURL:     "https://oauth.example.com/token",
        Scopes:       []string{"read", "write"},
    },
}
request.SetAuth(auth)
```

#### Custom Authentication

```go
auth := &types.Authentication{
    Type: types.AuthTypeCustom,
    Custom: map[string]interface{}{
        "headers": map[string]string{
            "X-Custom-Header": "custom-value",
            "Authorization":   "Custom your-token",
        },
    },
}
request.SetAuth(auth)
```

### GraphQL Requests

#### GraphQL Query

```go
query := `
    query GetUsers($limit: Int!, $offset: Int!) {
        users(limit: $limit, offset: $offset) {
            id
            name
            email
        }
    }
`

request := types.CreateGraphQLRequest(query)
request.AddVariable("limit", 10)
request.AddVariable("offset", 0)
request.SetAuth(auth)

response, err := apiManager.SendGraphQLRequest(ctx, "graphql", request)
```

#### GraphQL Mutation

```go
mutation := `
    mutation CreateUser($input: UserInput!) {
        createUser(input: $input) {
            id
            name
            email
        }
    }
`

request := types.CreateGraphQLRequest(mutation)
request.AddVariable("input", map[string]interface{}{
    "name":  "Jane Doe",
    "email": "jane@example.com",
})

response, err := apiManager.SendGraphQLRequest(ctx, "graphql", request)
```

### gRPC Requests

```go
request := types.CreategRPCRequest("UserService", "GetUser")
request.Data = map[string]interface{}{
    "id": "123",
}
request.AddMetadata("authorization", "Bearer your-jwt-token")

response, err := apiManager.SendgRPCRequest(ctx, "grpc", request)
```

### Batch Requests

```go
batchRequest := &types.BatchRequest{
    Requests: []types.APIRequest{
        *getRequest,
        *postRequest,
        *putRequest,
    },
}

response, err := apiManager.SendBatch(ctx, "http", batchRequest)
```

### Streaming Requests

```go
handler := func(response *types.APIResponse) error {
    log.Printf("Received chunk: %s", string(response.RawBody))
    return nil
}

err := apiManager.StreamRequest(ctx, "http", request, handler)
```

### Custom Headers

```go
request := types.CreateAPIRequest(types.MethodGET, "https://api.example.com/data")
request.AddHeader("Accept", "application/json")
request.AddHeader("User-Agent", "MyApp/1.0")
request.AddHeader("X-Custom-Header", "custom-value")
request.AddHeader("Authorization", "Bearer your-token")
```

### Query Parameters

```go
request := types.CreateAPIRequest(types.MethodGET, "https://api.example.com/search")
request.AddQueryParam("q", "search term")
request.AddQueryParam("limit", "20")
request.AddQueryParam("offset", "0")
request.AddQueryParam("sort", "created_at")
request.AddQueryParam("order", "desc")
```

### Request Timeout and Retries

```go
request := types.CreateAPIRequest(types.MethodGET, "https://api.example.com/slow-endpoint")
request.SetTimeout(60 * time.Second)  // 60 second timeout
request.SetRetries(5)                 // Retry up to 5 times
```

### File Upload

```go
request := types.CreateAPIRequest(types.MethodPOST, "https://api.example.com/upload")
request.AddFile("document", "report.pdf", "application/pdf", pdfData)
request.AddFile("image", "photo.jpg", "image/jpeg", imageData)
request.AddFormData("title", "Monthly Report")
request.AddFormData("description", "Q1 2024 report")
```

### Response Handling

```go
response, err := apiManager.SendRequest(ctx, "http", request)
if err != nil {
    log.Printf("Request failed: %v", err)
    return
}

// Check response status
if response.Success {
    log.Printf("Request successful: %d", response.StatusCode)
    
    // Handle JSON response
    if data, ok := response.Body.(map[string]interface{}); ok {
        log.Printf("Response data: %v", data)
    }
    
    // Handle string response
    if data, ok := response.Body.(string); ok {
        log.Printf("Response text: %s", data)
    }
} else {
    log.Printf("Request failed: %s", response.Error)
}

// Access response headers
for _, header := range response.Headers {
    log.Printf("Header: %s = %s", header.Name, header.Value)
}

// Access raw response body
log.Printf("Raw response: %s", string(response.RawBody))
```

## Advanced Features

### Health Checks

```go
// Check health of all providers
healthResults := apiManager.HealthCheck(ctx)
for provider, err := range healthResults {
    if err != nil {
        log.Printf("Provider %s is unhealthy: %v", provider, err)
    } else {
        log.Printf("Provider %s is healthy", provider)
    }
}

// Check if specific provider is connected
if apiManager.IsProviderConnected("http") {
    log.Println("HTTP provider is connected")
}
```

### Statistics

```go
// Get statistics from a provider
stats, err := apiManager.GetStats(ctx, "http")
if err != nil {
    log.Printf("Failed to get stats: %v", err)
} else {
    log.Printf("Total requests: %d", stats.TotalRequests)
    log.Printf("Successful requests: %d", stats.SuccessfulRequests)
    log.Printf("Failed requests: %d", stats.FailedRequests)
    log.Printf("Average response time: %v", stats.AverageResponseTime)
    log.Printf("Active connections: %d", stats.ActiveConnections)
}
```

### Provider Capabilities

```go
// Get provider capabilities
features, connInfo, err := apiManager.GetProviderCapabilities("http")
if err != nil {
    log.Printf("Failed to get capabilities: %v", err)
} else {
    log.Printf("Supported features: %v", features)
    log.Printf("Connection info: %+v", connInfo)
}
```

### Error Handling

```go
response, err := apiManager.SendRequest(ctx, "http", request)
if err != nil {
    // Handle different types of errors
    switch {
    case strings.Contains(err.Error(), "timeout"):
        log.Println("Request timed out")
    case strings.Contains(err.Error(), "connection refused"):
        log.Println("Connection refused")
    case strings.Contains(err.Error(), "authentication"):
        log.Println("Authentication failed")
    default:
        log.Printf("Request failed: %v", err)
    }
    return
}

// Check response for errors
if !response.Success {
    log.Printf("API returned error: %s", response.Error)
    return
}
```

## Best Practices

1. **Connection Management**: Always close connections when done
2. **Error Handling**: Check for errors after each operation
3. **Authentication**: Store credentials securely and use environment variables
4. **Timeouts**: Set appropriate timeouts for different types of requests
5. **Retries**: Configure retry logic for transient failures
6. **Logging**: Enable logging for debugging and monitoring
7. **Rate Limiting**: Implement rate limiting for external APIs
8. **Circuit Breaker**: Use circuit breaker patterns for fault tolerance
9. **Monitoring**: Monitor API usage and performance
10. **Security**: Use HTTPS for all external API calls

## Common Third-Party API Integrations

### REST APIs

```go
// GitHub API
request := types.CreateAPIRequest(types.MethodGET, "https://api.github.com/user")
request.AddHeader("Accept", "application/vnd.github.v3+json")
request.SetAuth(&types.Authentication{
    Type:  types.AuthTypeBearer,
    Token: "your-github-token",
})

// Stripe API
request := types.CreateAPIRequest(types.MethodPOST, "https://api.stripe.com/v1/charges")
request.AddHeader("Content-Type", "application/x-www-form-urlencoded")
request.SetAuth(&types.Authentication{
    Type:         types.AuthTypeAPIKey,
    APIKey:       "your-stripe-secret-key",
    APIKeyHeader: "Authorization",
})
request.AddFormData("amount", "2000")
request.AddFormData("currency", "usd")
request.AddFormData("source", "tok_visa")

// Twilio API
request := types.CreateAPIRequest(types.MethodPOST, "https://api.twilio.com/2010-04-01/Accounts/ACxxx/Messages.json")
request.AddHeader("Content-Type", "application/x-www-form-urlencoded")
request.SetAuth(&types.Authentication{
    Type:     types.AuthTypeBasic,
    Username: "your-twilio-sid",
    Password: "your-twilio-auth-token",
})
```

### GraphQL APIs

```go
// GitHub GraphQL API
query := `
    query($login: String!) {
        user(login: $login) {
            name
            email
            repositories(first: 10) {
                nodes {
                    name
                    description
                }
            }
        }
    }
`

request := types.CreateGraphQLRequest(query)
request.AddVariable("login", "octocat")
request.SetAuth(&types.Authentication{
    Type:  types.AuthTypeBearer,
    Token: "your-github-token",
})
```

### gRPC Services

```go
// Custom gRPC service
request := types.CreategRPCRequest("UserService", "GetUser")
request.Data = map[string]interface{}{
    "id": "123",
}
request.AddMetadata("authorization", "Bearer your-jwt-token")
```

## Troubleshooting

### Common Issues

1. **Connection Timeouts**: Increase timeout values or check network connectivity
2. **Authentication Errors**: Verify credentials and authentication method
3. **Rate Limiting**: Implement backoff strategies or request queuing
4. **SSL/TLS Issues**: Check certificate validity and TLS configuration
5. **Proxy Issues**: Configure proxy settings correctly
6. **Memory Issues**: Use streaming for large responses

### Debugging

```go
// Enable debug logging
logger := logrus.New()
logger.SetLevel(logrus.DebugLevel)

// Check provider status
if !apiManager.IsProviderConnected("http") {
    log.Println("HTTP provider not connected")
}

// Get detailed error information
response, err := apiManager.SendRequest(ctx, "http", request)
if err != nil {
    log.Printf("Detailed error: %+v", err)
}
```

This API library provides a comprehensive solution for integrating with any third-party API, offering flexibility, reliability, and ease of use for all your API integration needs.
