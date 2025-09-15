# Edge Computing Library

The Edge Computing library provides support for deploying and running microservices at the edge, including CDN edge networks and IoT devices. It supports WASM compilation for lightweight execution and integration with major edge computing platforms.

## Features

- **Multi-Provider Support**: Cloudflare Workers, Fastly Compute, Akamai EdgeWorkers, and WASM runtime
- **WASM Compilation**: Compile Go, Rust, C/C++, and AssemblyScript to WebAssembly
- **Edge Deployment**: Deploy microservices to global edge networks
- **Lightweight Execution**: Optimized for edge computing constraints
- **Unified API**: Consistent interface across all edge providers
- **Fallback Support**: Automatic fallback between providers
- **Monitoring**: Built-in metrics and logging support

## Supported Providers

### Cloudflare Workers
- JavaScript/TypeScript runtime
- Global edge network
- Built-in KV storage and Durable Objects
- WebSocket support

### Fastly Compute
- Rust, JavaScript, TypeScript, Go runtime
- Real-time analytics
- Edge caching integration
- VCL integration

### Akamai EdgeWorkers
- JavaScript runtime
- Edge computing platform
- Real-time personalization
- Security features

### WASM Runtime
- Local WASM execution
- Multi-language support (Go, Rust, C/C++, AssemblyScript)
- TinyGo compilation
- Lightweight deployment

## Installation

```bash
go get github.com/anasamu/go-micro-libs/edge
```

## Quick Start

### Basic Usage

```go
package main

import (
    "context"
    "log"
    
    "github.com/anasamu/go-micro-libs/edge"
    "github.com/anasamu/go-micro-libs/edge/types"
)

func main() {
    // Create edge manager
    manager := edge.NewEdgeManager()
    
    // Add Cloudflare provider
    cloudflareConfig := &types.ProviderConfig{
        Name:      "cloudflare",
        APIKey:    "your-cloudflare-api-key",
        AccountID: "your-account-id",
    }
    
    if err := manager.AddProvider(cloudflareConfig); err != nil {
        log.Fatal("Failed to add Cloudflare provider:", err)
    }
    
    // Deploy a worker
    deployReq := &types.DeployRequest{
        Name:        "my-worker",
        Runtime:     "javascript",
        Code:        []byte("export default { async fetch(request) { return new Response('Hello from edge!'); } }"),
        Environment: map[string]string{
            "ENVIRONMENT": "production",
        },
        Memory:  128,
        Timeout: 30 * time.Second,
        Region:  "global",
        Triggers: []types.Trigger{
            {
                Type: "http",
                Config: map[string]interface{}{
                    "route": "example.com/*",
                },
                Enabled: true,
            },
        },
    }
    
    ctx := context.Background()
    resp, err := manager.Deploy(ctx, "cloudflare", deployReq)
    if err != nil {
        log.Fatal("Deployment failed:", err)
    }
    
    log.Printf("Deployed worker: %s at %s", resp.Name, resp.URL)
}
```

### WASM Compilation

```go
package main

import (
    "context"
    "log"
    
    "github.com/anasamu/go-micro-libs/edge"
    "github.com/anasamu/go-micro-libs/edge/types"
)

func main() {
    manager := edge.NewEdgeManager()
    
    // Set WASM runtime
    manager.SetWASMRuntime(wasm.NewTinyGoRuntime())
    
    // Compile Go code to WASM
    goCode := `
package main

import "syscall/js"

func main() {
    js.Global().Set("add", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
        return args[0].Int() + args[1].Int()
    }))
    
    select {} // Keep the program running
}
`
    
    compilationReq := &types.CompilationRequest{
        SourceCode:   []byte(goCode),
        Language:     "go",
        Target:       "wasm32-unknown-unknown",
        Optimization: "size",
    }
    
    ctx := context.Background()
    resp, err := manager.CompileToWASM(ctx, compilationReq)
    if err != nil {
        log.Fatal("Compilation failed:", err)
    }
    
    log.Printf("Compiled WASM: %d bytes", resp.Size)
    
    // Deploy WASM module
    deployReq := &types.DeployRequest{
        Name:    "my-wasm-module",
        Runtime: "wasm",
        Code:    resp.WasmCode,
    }
    
    deployResp, err := manager.Deploy(ctx, "wasm", deployReq)
    if err != nil {
        log.Fatal("WASM deployment failed:", err)
    }
    
    log.Printf("Deployed WASM module: %s", deployResp.Name)
}
```

### Multi-Provider Deployment with Fallback

```go
package main

import (
    "context"
    "log"
    
    "github.com/anasamu/go-micro-libs/edge"
    "github.com/anasamu/go-micro-libs/edge/types"
)

func main() {
    manager := edge.NewEdgeManager()
    
    // Add multiple providers
    providers := []*types.ProviderConfig{
        {
            Name:      "cloudflare",
            APIKey:    "your-cloudflare-api-key",
            AccountID: "your-account-id",
        },
        {
            Name:   "fastly",
            APIKey: "your-fastly-api-key",
        },
        {
            Name:   "akamai",
            APIKey: "your-akamai-api-key",
        },
    }
    
    for _, config := range providers {
        if err := manager.AddProvider(config); err != nil {
            log.Printf("Failed to add provider %s: %v", config.Name, err)
        }
    }
    
    // Deploy with fallback
    deployReq := &types.DeployRequest{
        Name:    "my-service",
        Runtime: "javascript",
        Code:    []byte("export default { async fetch(request) { return new Response('Hello!'); } }"),
    }
    
    ctx := context.Background()
    resp, err := manager.DeployWithFallback(ctx, "cloudflare", deployReq)
    if err != nil {
        log.Fatal("All providers failed:", err)
    }
    
    log.Printf("Deployed to %s: %s", resp.Status, resp.URL)
}
```

### Invoking Edge Functions

```go
package main

import (
    "context"
    "log"
    
    "github.com/anasamu/go-micro-libs/edge"
    "github.com/anasamu/go-micro-libs/edge/types"
)

func main() {
    manager := edge.NewEdgeManager()
    
    // ... setup providers ...
    
    // Invoke deployed function
    invokeReq := &types.InvokeRequest{
        DeploymentID: "deployment-id",
        Payload:      []byte(`{"name": "world"}`),
        Headers: map[string]string{
            "Content-Type": "application/json",
        },
    }
    
    ctx := context.Background()
    resp, err := manager.Invoke(ctx, "cloudflare", invokeReq)
    if err != nil {
        log.Fatal("Invocation failed:", err)
    }
    
    log.Printf("Response: %s", string(resp.Result))
    log.Printf("Duration: %v", resp.Duration)
}
```

### Monitoring and Logs

```go
package main

import (
    "context"
    "log"
    
    "github.com/anasamu/go-micro-libs/edge"
    "github.com/anasamu/go-micro-libs/edge/types"
)

func main() {
    manager := edge.NewEdgeManager()
    
    // ... setup providers ...
    
    ctx := context.Background()
    
    // Get deployment metrics
    metricsReq := &types.GetMetricsRequest{
        DeploymentID: "deployment-id",
    }
    
    metricsResp, err := manager.GetMetrics(ctx, "cloudflare", metricsReq)
    if err != nil {
        log.Fatal("Failed to get metrics:", err)
    }
    
    metrics := metricsResp.Metrics
    log.Printf("Invocations: %d", metrics.Invocations)
    log.Printf("Errors: %d", metrics.Errors)
    log.Printf("Avg Duration: %.2f ms", metrics.AvgDuration)
    
    // Get logs
    logsReq := &types.GetLogsRequest{
        DeploymentID: "deployment-id",
        Limit:        100,
        Level:        "info",
    }
    
    logsResp, err := manager.GetLogs(ctx, "cloudflare", logsReq)
    if err != nil {
        log.Fatal("Failed to get logs:", err)
    }
    
    for _, logEntry := range logsResp.Logs {
        log.Printf("[%s] %s: %s", logEntry.Level, logEntry.Timestamp, logEntry.Message)
    }
}
```

## Configuration

### Provider Configuration

Each provider has specific configuration options:

```go
// Cloudflare Workers
config := &types.ProviderConfig{
    Name:      "cloudflare",
    APIKey:    "your-api-key",
    AccountID: "your-account-id",
    BaseURL:   "https://api.cloudflare.com/client/v4", // Optional
    Timeout:   30 * time.Second,                        // Optional
    Regions:   []string{"global", "us-east", "eu-west"}, // Optional
}

// Fastly Compute
config := &types.ProviderConfig{
    Name:   "fastly",
    APIKey: "your-api-key",
    BaseURL: "https://api.fastly.com", // Optional
}

// Akamai EdgeWorkers
config := &types.ProviderConfig{
    Name:      "akamai",
    APIKey:    "your-api-key",
    AccountID: "your-group-id",
    BaseURL:   "https://api.akamai.com", // Optional
}

// WASM Runtime
config := &types.ProviderConfig{
    Name: "wasm",
    Config: map[string]interface{}{
        "temp_dir": "/tmp/wasm", // Optional
    },
}
```

## Supported Runtimes

### Cloudflare Workers
- JavaScript
- TypeScript
- WebAssembly (WASM)
- Rust
- Go

### Fastly Compute
- Rust
- JavaScript
- TypeScript
- Go
- WebAssembly

### Akamai EdgeWorkers
- JavaScript
- TypeScript

### WASM Runtime
- Go (via TinyGo)
- Rust (via cargo)
- C/C++ (via Emscripten)
- AssemblyScript

## Error Handling

The library provides comprehensive error handling with provider-specific error codes:

```go
resp, err := manager.Deploy(ctx, "cloudflare", deployReq)
if err != nil {
    log.Fatal("Deployment failed:", err)
}

if resp.Error != nil {
    log.Printf("Deployment error: %s (Code: %s)", resp.Error.Message, resp.Error.Code)
}
```

## Health Checks

Monitor provider health:

```go
ctx := context.Background()
healthStatus, err := manager.HealthCheck(ctx)
if err != nil {
    log.Fatal("Health check failed:", err)
}

for provider, status := range healthStatus {
    if status.Healthy {
        log.Printf("Provider %s is healthy", provider)
    } else {
        log.Printf("Provider %s is unhealthy: %s", provider, status.Message)
    }
}
```

## Statistics

Track provider usage and performance:

```go
stats := manager.GetStats()
for provider, stat := range stats {
    log.Printf("Provider %s:", provider)
    log.Printf("  Total Deployments: %d", stat.TotalDeployments)
    log.Printf("  Total Invocations: %d", stat.TotalInvocations)
    log.Printf("  Success Rate: %.2f%%", stat.SuccessRate*100)
    log.Printf("  Avg Latency: %.2f ms", stat.AvgLatency)
}
```

## Best Practices

1. **Use Fallback**: Always configure multiple providers for high availability
2. **Optimize for Size**: Use WASM for lightweight edge functions
3. **Monitor Performance**: Track metrics and logs for optimization
4. **Handle Errors**: Implement proper error handling and retry logic
5. **Secure Credentials**: Store API keys securely using environment variables
6. **Test Locally**: Use WASM runtime for local testing before deployment

## Examples

See the `examples/` directory for complete working examples:
- Basic deployment
- WASM compilation
- Multi-provider setup
- Monitoring and logging
- Error handling

## Contributing

Contributions are welcome! Please see the main project README for contribution guidelines.

## License

This library is part of the go-micro-libs project and follows the same license.
