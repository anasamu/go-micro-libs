# AI Library

The AI library provides a unified interface for interacting with multiple AI providers, including OpenAI, Anthropic, Google, xAI, and DeepSeek. It offers comprehensive AI capabilities including chat, text generation, embeddings, and model management with built-in fallback mechanisms and statistics tracking.

## Features

- **Multi-Provider Support**: Seamlessly switch between different AI providers
- **Chat Interface**: Conversational AI with message history and context
- **Text Generation**: Generate text from prompts with various parameters
- **Embeddings**: Generate vector embeddings for text
- **Model Management**: Get information about available models
- **Health Monitoring**: Built-in health checks and statistics
- **Fallback Support**: Automatic failover between providers
- **Token Tracking**: Monitor usage and costs across providers

## Supported Providers

- **OpenAI**: GPT models, embeddings, and chat completions
- **Anthropic**: Claude models and chat completions
- **Google**: Gemini models and chat completions
- **xAI**: Grok models and chat completions
- **DeepSeek**: DeepSeek models and chat completions

## Installation

```bash
go get github.com/anasamu/go-micro-libs/ai
```

## Quick Start

```go
package main

import (
    "context"
    "fmt"
    "log"
    "time"

    "github.com/anasamu/go-micro-libs/ai"
    "github.com/anasamu/go-micro-libs/ai/types"
)

func main() {
    // Create AI manager
    manager := ai.NewAIManager()

    // Add OpenAI provider
    config := &types.ProviderConfig{
        Name:    "openai",
        APIKey:  "your-openai-api-key",
        BaseURL: "https://api.openai.com/v1",
        Timeout: 30 * time.Second,
    }

    err := manager.AddProvider(config)
    if err != nil {
        log.Fatal(err)
    }

    // Chat with AI
    ctx := context.Background()
    chatReq := &types.ChatRequest{
        Messages: []types.Message{
            {
                Role:    "user",
                Content: "Hello, how are you?",
            },
        },
        Model:       "gpt-3.5-turbo",
        Temperature: 0.7,
        MaxTokens:   100,
    }

    response, err := manager.Chat(ctx, "openai", chatReq)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("AI Response: %s\n", response.Choices[0].Message.Content)
}
```

## API Reference

### AIManager

The main manager for handling AI operations across multiple providers.

#### Methods

##### `NewAIManager() *AIManager`
Creates a new AI manager instance.

##### `AddProvider(config *types.ProviderConfig) error`
Adds a new AI provider with the given configuration.

**Parameters:**
- `config`: Provider configuration including name, API key, and settings

**Returns:**
- `error`: Any error that occurred during provider setup

##### `RemoveProvider(name string) error`
Removes an AI provider by name.

##### `GetProvider(name string) (types.AIProvider, error)`
Retrieves a specific provider by name.

##### `ListProviders() []string`
Returns a list of all registered provider names.

##### `Chat(ctx context.Context, providerName string, req *types.ChatRequest) (*types.ChatResponse, error)`
Sends a chat request to a specific provider.

**Parameters:**
- `ctx`: Context for cancellation and timeouts
- `providerName`: Name of the provider to use
- `req`: Chat request with messages and parameters

**Returns:**
- `*types.ChatResponse`: AI response with choices and usage information
- `error`: Any error that occurred

##### `GenerateText(ctx context.Context, providerName string, req *types.TextGenerationRequest) (*types.TextGenerationResponse, error)`
Generates text using a specific provider.

##### `EmbedText(ctx context.Context, providerName string, req *types.EmbeddingRequest) (*types.EmbeddingResponse, error)`
Generates embeddings for text using a specific provider.

##### `GetModelInfo(ctx context.Context, providerName string) ([]types.ModelInfo, error)`
Returns information about available models for a provider.

##### `GetAllModelInfo(ctx context.Context) (map[string][]types.ModelInfo, error)`
Returns model information for all providers.

##### `HealthCheck(ctx context.Context) (map[string]*types.HealthStatus, error)`
Checks the health of all providers.

##### `GetStats() map[string]*types.ProviderStats`
Returns statistics for all providers.

##### `GetProviderStats(providerName string) (*types.ProviderStats, error)`
Returns statistics for a specific provider.

##### `ChatWithFallback(ctx context.Context, primaryProvider string, req *types.ChatRequest) (*types.ChatResponse, error)`
Sends a chat request with automatic fallback to other providers.

##### `GenerateTextWithFallback(ctx context.Context, primaryProvider string, req *types.TextGenerationRequest) (*types.TextGenerationResponse, error)`
Generates text with automatic fallback to other providers.

### Types

#### ProviderConfig
Configuration for an AI provider.

```go
type ProviderConfig struct {
    Name         string            `json:"name"`
    APIKey       string            `json:"api_key"`
    BaseURL      string            `json:"base_url,omitempty"`
    Timeout      time.Duration     `json:"timeout,omitempty"`
    MaxRetries   int               `json:"max_retries,omitempty"`
    Headers      map[string]string `json:"headers,omitempty"`
    Models       []string          `json:"models,omitempty"`
    DefaultModel string            `json:"default_model,omitempty"`
}
```

#### ChatRequest
Request for chat completion.

```go
type ChatRequest struct {
    Messages         []Message `json:"messages"`
    Model            string    `json:"model"`
    Temperature      float64   `json:"temperature,omitempty"`
    MaxTokens        int       `json:"max_tokens,omitempty"`
    Stream           bool      `json:"stream,omitempty"`
    TopP             float64   `json:"top_p,omitempty"`
    FrequencyPenalty float64   `json:"frequency_penalty,omitempty"`
    PresencePenalty  float64   `json:"presence_penalty,omitempty"`
}
```

#### ChatResponse
Response from chat completion.

```go
type ChatResponse struct {
    ID      string   `json:"id"`
    Object  string   `json:"object"`
    Created int64    `json:"created"`
    Model   string   `json:"model"`
    Choices []Choice `json:"choices"`
    Usage   Usage    `json:"usage"`
    Error   *AIError `json:"error,omitempty"`
}
```

#### Message
Represents a chat message.

```go
type Message struct {
    Role    string `json:"role"`
    Content string `json:"content"`
    Name    string `json:"name,omitempty"`
}
```

#### Usage
Token usage information.

```go
type Usage struct {
    PromptTokens     int `json:"prompt_tokens"`
    CompletionTokens int `json:"completion_tokens"`
    TotalTokens      int `json:"total_tokens"`
}
```

#### ProviderStats
Statistics for a provider.

```go
type ProviderStats struct {
    Provider      string    `json:"provider"`
    TotalRequests int64     `json:"total_requests"`
    TotalTokens   int64     `json:"total_tokens"`
    SuccessRate   float64   `json:"success_rate"`
    AvgLatency    float64   `json:"avg_latency_ms"`
    LastUsed      time.Time `json:"last_used"`
}
```

## Advanced Usage

### Multiple Providers with Fallback

```go
// Add multiple providers
openaiConfig := &types.ProviderConfig{
    Name:   "openai",
    APIKey: "your-openai-key",
}

anthropicConfig := &types.ProviderConfig{
    Name:   "anthropic",
    APIKey: "your-anthropic-key",
}

manager.AddProvider(openaiConfig)
manager.AddProvider(anthropicConfig)

// Use fallback - tries OpenAI first, then Anthropic
response, err := manager.ChatWithFallback(ctx, "openai", chatReq)
```

### Text Generation

```go
textReq := &types.TextGenerationRequest{
    Prompt:      "Write a short story about a robot",
    Model:       "gpt-3.5-turbo",
    Temperature: 0.8,
    MaxTokens:   200,
}

response, err := manager.GenerateText(ctx, "openai", textReq)
```

### Embeddings

```go
embedReq := &types.EmbeddingRequest{
    Input: []string{"Hello world", "How are you?"},
    Model: "text-embedding-ada-002",
}

response, err := manager.EmbedText(ctx, "openai", embedReq)
```

### Health Monitoring

```go
// Check health of all providers
healthStatus, err := manager.HealthCheck(ctx)
for provider, status := range healthStatus {
    fmt.Printf("Provider %s: %v\n", provider, status.Healthy)
}

// Get statistics
stats := manager.GetStats()
for provider, stat := range stats {
    fmt.Printf("Provider %s: %d requests, %.2f%% success rate\n", 
        provider, stat.TotalRequests, stat.SuccessRate*100)
}
```

## Error Handling

The library provides comprehensive error handling with specific error types:

```go
response, err := manager.Chat(ctx, "openai", chatReq)
if err != nil {
    // Handle connection errors, API errors, etc.
    log.Printf("Chat failed: %v", err)
    return
}

if response.Error != nil {
    // Handle AI provider specific errors
    log.Printf("AI Error: %s", response.Error.Message)
    return
}
```

## Best Practices

1. **Provider Configuration**: Always set appropriate timeouts and retry limits
2. **Error Handling**: Implement proper error handling for production use
3. **Rate Limiting**: Be aware of provider rate limits and implement backoff strategies
4. **Token Management**: Monitor token usage to control costs
5. **Health Checks**: Regularly check provider health in production
6. **Fallback Strategy**: Use fallback mechanisms for high availability

## Contributing

Contributions are welcome! Please read the contributing guidelines and submit pull requests for any improvements.

## License

This library is licensed under the MIT License. See the LICENSE file for details.
