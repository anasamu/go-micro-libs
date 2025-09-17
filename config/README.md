# Config Library

The Config library provides a unified interface for configuration management across multiple providers including file-based, environment variables, Consul, and Vault. It offers comprehensive configuration capabilities with support for structured configuration, dynamic updates, change watching, and advanced features like service discovery, health checks, circuit breakers, and load balancing configurations.

## Features

- **Multi-Provider Support**: File, environment variables, Consul, Vault
- **Structured Configuration**: Comprehensive configuration structures for all services
- **Dynamic Updates**: Real-time configuration updates and change watching
- **Service Discovery**: Built-in service configuration and discovery
- **Health Checks**: Service health check configurations
- **Circuit Breakers**: Circuit breaker configuration management
- **Load Balancing**: Load balancer configuration support
- **Custom Configuration**: Dynamic custom configuration support
- **Environment Detection**: Development, staging, and production environment support
- **Thread Safety**: Thread-safe configuration management

## Supported Providers

- **File**: JSON, YAML, TOML configuration files
- **Environment**: Environment variable-based configuration
- **Consul**: Consul KV store configuration
- **Vault**: HashiCorp Vault secrets management

## Installation

```bash
go get github.com/anasamu/go-micro-libs/config
```

## Quick Start

```go
package main

import (
    "fmt"
    "log"

    "github.com/anasamu/go-micro-libs/config"
    "github.com/anasamu/go-micro-libs/config/types"
)

func main() {
    // Create configuration manager
    manager := config.NewManager()

    // Register file provider (example)
    // fileProvider := file.NewFileProvider("config.yaml")
    // manager.RegisterProvider("file", fileProvider)

    // Set current provider
    err := manager.SetCurrentProvider("file")
    if err != nil {
        log.Fatal(err)
    }

    // Load configuration
    cfg, err := manager.Load()
    if err != nil {
        log.Fatal(err)
    }

    // Use configuration
    fmt.Printf("Server running on %s:%s\n", cfg.Server.Host, cfg.Server.Port)
    fmt.Printf("Database URL: %s\n", cfg.GetDatabaseURL())
    fmt.Printf("Environment: %s\n", cfg.Server.Environment)
}
```

## API Reference

### Manager

The main manager for handling configuration operations across multiple providers.

#### Methods

##### `NewManager() *Manager`
Creates a new configuration manager.

##### `RegisterProvider(name string, provider ConfigProvider)`
Registers a configuration provider.

**Parameters:**
- `name`: Name of the provider
- `provider`: The configuration provider to register

##### `SetCurrentProvider(name string) error`
Sets the current active provider.

**Parameters:**
- `name`: Name of the provider to set as current

**Returns:**
- `error`: Any error that occurred

##### `Load() (*Config, error)`
Loads configuration from the current provider.

**Returns:**
- `*Config`: Loaded configuration
- `error`: Any error that occurred

##### `Save(config *Config) error`
Saves configuration to the current provider.

**Parameters:**
- `config`: Configuration to save

**Returns:**
- `error`: Any error that occurred

##### `GetConfig() *Config`
Returns the current configuration.

##### `Watch(callback func(*Config)) error`
Starts watching for configuration changes.

**Parameters:**
- `callback`: Function to call when configuration changes

**Returns:**
- `error`: Any error that occurred

##### `Reload() (*Config, error)`
Reloads configuration from the current provider.

##### `UpdateConfig(updater func(*Config)) error`
Updates the current configuration and saves it.

##### `Close() error`
Closes all configuration providers.

##### `GetProvider(name string) (ConfigProvider, error)`
Returns a specific provider by name.

##### `ListProviders() []string`
Returns a list of all registered provider names.

### Types

#### Config
Holds all configuration for the application.

```go
type Config struct {
    Server     ServerConfig           `mapstructure:"server"`
    Database   DatabaseConfig         `mapstructure:"database"`
    Redis      RedisConfig            `mapstructure:"redis"`
    Vault      VaultConfig            `mapstructure:"vault"`
    Logging    LoggingConfig          `mapstructure:"logging"`
    Monitoring MonitoringConfig       `mapstructure:"monitoring"`
    Storage    StorageConfig          `mapstructure:"storage"`
    Search     SearchConfig           `mapstructure:"search"`
    Auth       AuthConfig             `mapstructure:"auth"`
    RabbitMQ   RabbitMQConfig         `mapstructure:"rabbitmq"`
    Kafka      KafkaConfig            `mapstructure:"kafka"`
    GRPC       GRPCConfig             `mapstructure:"grpc"`
    Services   ServicesConfig         `mapstructure:"services"`
    Custom     map[string]interface{} `mapstructure:",remain"`
}
```

#### ServerConfig
Holds server configuration.

```go
type ServerConfig struct {
    Port         string `mapstructure:"port"`
    Host         string `mapstructure:"host"`
    Environment  string `mapstructure:"environment"`
    ServiceName  string `mapstructure:"service_name"`
    Version      string `mapstructure:"version"`
    ReadTimeout  int    `mapstructure:"read_timeout"`
    WriteTimeout int    `mapstructure:"write_timeout"`
    IdleTimeout  int    `mapstructure:"idle_timeout"`
}
```

#### DatabaseConfig
Holds database configuration.

```go
type DatabaseConfig struct {
    PostgreSQL PostgreSQLConfig `mapstructure:"postgresql"`
    MongoDB    MongoDBConfig    `mapstructure:"mongodb"`
}
```

#### ServiceConfig
Holds individual service configuration.

```go
type ServiceConfig struct {
    Name           string                 `mapstructure:"name"`
    Host           string                 `mapstructure:"host"`
    Port           string                 `mapstructure:"port"`
    Protocol       string                 `mapstructure:"protocol"`
    Version        string                 `mapstructure:"version"`
    Environment    string                 `mapstructure:"environment"`
    HealthCheck    HealthCheckConfig      `mapstructure:"health_check"`
    Retry          RetryConfig            `mapstructure:"retry"`
    Timeout        TimeoutConfig          `mapstructure:"timeout"`
    CircuitBreaker CircuitBreakerConfig   `mapstructure:"circuit_breaker"`
    LoadBalancer   LoadBalancerConfig     `mapstructure:"load_balancer"`
    Metadata       map[string]interface{} `mapstructure:"metadata"`
    Custom         map[string]interface{} `mapstructure:",remain"`
}
```

## Advanced Usage

### Basic Configuration Loading

```go
// Create manager and register providers
manager := config.NewManager()

// Register file provider
fileProvider := file.NewFileProvider("config.yaml")
manager.RegisterProvider("file", fileProvider)

// Register environment provider
envProvider := env.NewEnvProvider()
manager.RegisterProvider("env", envProvider)

// Set current provider
err := manager.SetCurrentProvider("file")
if err != nil {
    log.Fatal(err)
}

// Load configuration
cfg, err := manager.Load()
if err != nil {
    log.Fatal(err)
}

// Use configuration
fmt.Printf("Server: %s:%s\n", cfg.Server.Host, cfg.Server.Port)
fmt.Printf("Database: %s\n", cfg.GetDatabaseURL())
fmt.Printf("Redis: %s\n", cfg.GetRedisURL())
```

### Configuration Watching

```go
// Watch for configuration changes
err := manager.Watch(func(newConfig *types.Config) {
    fmt.Println("Configuration updated!")
    
    // Update application settings
    if newConfig.Server.Environment != cfg.Server.Environment {
        fmt.Printf("Environment changed to: %s\n", newConfig.Server.Environment)
    }
    
    // Update database connection
    if newConfig.Database.PostgreSQL.Host != cfg.Database.PostgreSQL.Host {
        fmt.Printf("Database host changed to: %s\n", newConfig.Database.PostgreSQL.Host)
        // Reconnect to database
    }
    
    // Update current config
    cfg = newConfig
})

if err != nil {
    log.Printf("Failed to watch configuration: %v", err)
}
```

### Service Configuration

```go
// Get service configuration
userService, exists := cfg.GetServiceConfig("user_service")
if exists {
    fmt.Printf("User Service: %s:%s\n", userService.Host, userService.Port)
    fmt.Printf("Protocol: %s\n", userService.Protocol)
    fmt.Printf("Health Check: %s\n", userService.HealthCheck.Path)
}

// Get service URL
userServiceURL, err := cfg.GetServiceURL("user_service")
if err != nil {
    log.Printf("Failed to get service URL: %v", err)
} else {
    fmt.Printf("User Service URL: %s\n", userServiceURL)
}

// Get health check URL
healthURL, err := cfg.GetServiceHealthCheckURL("user_service")
if err != nil {
    log.Printf("Failed to get health check URL: %v", err)
} else {
    fmt.Printf("Health Check URL: %s\n", healthURL)
}

// Get all services
allServices := cfg.GetAllServices()
for name, service := range allServices {
    fmt.Printf("Service %s: %s:%s\n", name, service.Host, service.Port)
}
```

### Custom Configuration

```go
// Set custom configuration values
cfg.SetCustomValue("feature_flags", map[string]bool{
    "new_ui":        true,
    "beta_features": false,
    "debug_mode":    cfg.IsDevelopment(),
})

cfg.SetCustomValue("api_limits", map[string]int{
    "max_requests_per_minute": 1000,
    "max_file_size":          10 * 1024 * 1024, // 10MB
    "max_connections":        100,
})

// Get custom configuration values
featureFlags, exists := cfg.GetCustomValue("feature_flags")
if exists {
    if flags, ok := featureFlags.(map[string]bool); ok {
        fmt.Printf("New UI enabled: %t\n", flags["new_ui"])
    }
}

// Get custom values with type conversion
maxRequests := cfg.GetCustomInt("api_limits.max_requests_per_minute", 100)
debugMode := cfg.GetCustomBool("feature_flags.debug_mode", false)
apiVersion := cfg.GetCustomString("api.version", "v1")

fmt.Printf("Max requests: %d\n", maxRequests)
fmt.Printf("Debug mode: %t\n", debugMode)
fmt.Printf("API version: %s\n", apiVersion)
```

### Environment-Specific Configuration

```go
// Check environment
if cfg.IsDevelopment() {
    fmt.Println("Running in development mode")
    // Enable debug logging
    // Use local database
} else if cfg.IsProduction() {
    fmt.Println("Running in production mode")
    // Enable production logging
    // Use production database
    // Enable monitoring
}

// Environment-specific service configuration
if cfg.IsDevelopment() {
    // Use local services in development
    cfg.SetServiceConfig("user_service", types.ServiceConfig{
        Name:     "user_service",
        Host:     "localhost",
        Port:     "8081",
        Protocol: "http",
    })
} else {
    // Use service discovery in production
    cfg.SetServiceConfig("user_service", types.ServiceConfig{
        Name:     "user_service",
        Host:     "user-service.internal",
        Port:     "80",
        Protocol: "http",
        HealthCheck: types.HealthCheckConfig{
            Enabled:  true,
            Path:     "/health",
            Interval: 30,
        },
        CircuitBreaker: types.CircuitBreakerConfig{
            Enabled:          true,
            FailureThreshold: 5,
            Timeout:          60,
        },
    })
}
```

### Configuration Updates

```go
// Update configuration
err := manager.UpdateConfig(func(config *types.Config) {
    // Update server configuration
    config.Server.Port = "8080"
    config.Server.ReadTimeout = 30
    config.Server.WriteTimeout = 30
    
    // Update database configuration
    config.Database.PostgreSQL.MaxConns = 100
    config.Database.PostgreSQL.MinConns = 10
    
    // Add custom configuration
    config.SetCustomValue("maintenance_mode", false)
    config.SetCustomValue("max_workers", 10)
})

if err != nil {
    log.Printf("Failed to update configuration: %v", err)
}
```

### Provider Management

```go
// List all providers
providers := manager.ListProviders()
fmt.Printf("Available providers: %v\n", providers)

// Switch between providers
err := manager.SetCurrentProvider("env")
if err != nil {
    log.Printf("Failed to switch to env provider: %v", err)
}

// Load from environment provider
envConfig, err := manager.Load()
if err != nil {
    log.Printf("Failed to load from env provider: %v", err)
} else {
    fmt.Printf("Loaded from environment: %s\n", envConfig.Server.Environment)
}

// Switch back to file provider
err = manager.SetCurrentProvider("file")
if err != nil {
    log.Printf("Failed to switch to file provider: %v", err)
}
```

### Advanced Service Configuration

```go
// Configure service with advanced settings
serviceConfig := types.ServiceConfig{
    Name:        "payment_service",
    Host:        "payment-service.internal",
    Port:        "443",
    Protocol:    "https",
    Version:     "v2",
    Environment: "production",
    HealthCheck: types.HealthCheckConfig{
        Enabled:     true,
        Path:        "/health",
        Interval:    30,
        Timeout:     5,
        Retries:     3,
        GracePeriod: 60,
    },
    Retry: types.RetryConfig{
        Enabled:      true,
        MaxAttempts:  3,
        InitialDelay: 100,
        MaxDelay:     1000,
        Multiplier:   2.0,
        Jitter:       true,
    },
    Timeout: types.TimeoutConfig{
        Connect: 5000,
        Read:    10000,
        Write:   10000,
        Total:   30000,
    },
    CircuitBreaker: types.CircuitBreakerConfig{
        Enabled:               true,
        FailureThreshold:      5,
        SuccessThreshold:      3,
        Timeout:               60,
        MaxRequests:           10,
        Interval:              10,
        ErrorPercentThreshold: 50.0,
    },
    LoadBalancer: types.LoadBalancerConfig{
        Strategy:    "round_robin",
        Servers:     []string{"payment-1.internal", "payment-2.internal"},
        Weights:     []int{1, 1},
        HealthCheck: true,
    },
    Metadata: map[string]interface{}{
        "team":        "payments",
        "criticality": "high",
        "sla":         "99.9%",
    },
}

cfg.SetServiceConfig("payment_service", serviceConfig)
```

### Configuration Validation

```go
// Validate configuration
func validateConfig(cfg *types.Config) error {
    // Validate server configuration
    if cfg.Server.Port == "" {
        return fmt.Errorf("server port is required")
    }
    
    if cfg.Server.Host == "" {
        return fmt.Errorf("server host is required")
    }
    
    // Validate database configuration
    if cfg.Database.PostgreSQL.Host == "" {
        return fmt.Errorf("database host is required")
    }
    
    if cfg.Database.PostgreSQL.Port == 0 {
        return fmt.Errorf("database port is required")
    }
    
    // Validate service configurations
    services := cfg.GetAllServices()
    for name, service := range services {
        if service.Host == "" {
            return fmt.Errorf("service %s host is required", name)
        }
        
        if service.Port == "" {
            return fmt.Errorf("service %s port is required", name)
        }
    }
    
    return nil
}

// Validate loaded configuration
err = validateConfig(cfg)
if err != nil {
    log.Fatalf("Configuration validation failed: %v", err)
}
```

### Error Handling

```go
// Load configuration with error handling
cfg, err := manager.Load()
if err != nil {
    // Handle different types of errors
    switch {
    case strings.Contains(err.Error(), "provider not found"):
        log.Printf("Configuration provider not found: %v", err)
    case strings.Contains(err.Error(), "failed to load config"):
        log.Printf("Configuration loading failed: %v", err)
    case strings.Contains(err.Error(), "invalid format"):
        log.Printf("Invalid configuration format: %v", err)
    default:
        log.Printf("Configuration error: %v", err)
    }
    return
}

// Watch configuration with error handling
err = manager.Watch(func(newConfig *types.Config) {
    // Handle configuration changes
    fmt.Println("Configuration updated")
})
if err != nil {
    log.Printf("Failed to watch configuration: %v", err)
}
```

### Configuration Cleanup

```go
// Close all providers when done
defer func() {
    err := manager.Close()
    if err != nil {
        log.Printf("Failed to close configuration manager: %v", err)
    }
}()
```

## Best Practices

1. **Environment Separation**: Use different configuration files for different environments
2. **Validation**: Always validate configuration after loading
3. **Watching**: Use configuration watching for dynamic updates
4. **Secrets Management**: Use Vault provider for sensitive configuration
5. **Service Discovery**: Configure services with proper health checks and circuit breakers
6. **Error Handling**: Implement comprehensive error handling for configuration operations
7. **Documentation**: Document all configuration options and their purposes
8. **Testing**: Test configuration loading in different scenarios
9. **Security**: Secure configuration files and sensitive data
10. **Performance**: Optimize configuration loading for production use

## Contributing

Contributions are welcome! Please read the contributing guidelines and submit pull requests for any improvements.

## License

This library is licensed under the MIT License. See the LICENSE file for details.
