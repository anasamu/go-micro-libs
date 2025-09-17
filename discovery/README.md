# Discovery Library

The Discovery library provides a unified interface for service discovery operations across multiple providers including Consul, etcd, Kubernetes, and static configurations. It offers comprehensive service discovery capabilities with support for service registration, deregistration, health checks, service watching, and advanced features like load balancing, failover, clustering, and real-time service monitoring.

## Features

- **Multi-Provider Support**: Consul, etcd, Kubernetes, static configurations
- **Service Registration**: Register and deregister services dynamically
- **Health Management**: Service health checks and status monitoring
- **Service Discovery**: Discover services by name, tags, and metadata
- **Real-Time Watching**: Watch for service changes and events
- **Load Balancing**: Built-in load balancing strategies
- **Failover Support**: Automatic failover between service instances
- **Clustering**: Distributed service discovery support
- **Metadata Support**: Rich metadata and tagging for services
- **Statistics**: Comprehensive discovery statistics and monitoring

## Supported Providers

- **Consul**: HashiCorp Consul service discovery
- **etcd**: etcd-based service discovery
- **Kubernetes**: Kubernetes native service discovery
- **Static**: Static service configuration

## Installation

```bash
go get github.com/anasamu/go-micro-libs/discovery
```

## Quick Start

```go
package main

import (
    "context"
    "fmt"
    "log"
    "time"

    "github.com/anasamu/go-micro-libs/discovery"
    "github.com/anasamu/go-micro-libs/discovery/types"
    "github.com/sirupsen/logrus"
)

func main() {
    // Create logger
    logger := logrus.New()

    // Create discovery manager
    config := &discovery.ManagerConfig{
        DefaultProvider: "consul",
        RetryAttempts:   3,
        RetryDelay:      1 * time.Second,
        Timeout:         30 * time.Second,
        FallbackEnabled: true,
    }
    manager := discovery.NewDiscoveryManager(config, logger)

    // Register Consul provider (example)
    // consulProvider := consul.NewConsulProvider("localhost:8500")
    // manager.RegisterProvider(consulProvider)

    // Register a service
    ctx := context.Background()
    registration := &types.ServiceRegistration{
        ID:       "user-service-1",
        Name:     "user-service",
        Address:  "localhost",
        Port:     8080,
        Protocol: "http",
        Tags:     []string{"api", "user", "v1"},
        Metadata: map[string]string{
            "version": "1.0.0",
            "team":    "backend",
        },
        Health: types.HealthPassing,
        TTL:     30 * time.Second,
        Weight:  100,
    }

    err := manager.RegisterService(ctx, registration)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Println("Service registered successfully")

    // Discover services
    query := &types.ServiceQuery{
        Name: "user-service",
        Tags: []string{"api"},
    }

    services, err := manager.DiscoverServices(ctx, query)
    if err != nil {
        log.Fatal(err)
    }

    for _, service := range services {
        fmt.Printf("Found service: %s with %d instances\n", service.Name, len(service.Instances))
    }
}
```

## API Reference

### DiscoveryManager

The main manager for handling service discovery operations across multiple providers.

#### Methods

##### `NewDiscoveryManager(config *ManagerConfig, logger *logrus.Logger) *DiscoveryManager`
Creates a new discovery manager with the given configuration and logger.

##### `RegisterProvider(provider DiscoveryProvider) error`
Registers a new discovery provider.

**Parameters:**
- `provider`: The discovery provider to register

**Returns:**
- `error`: Any error that occurred during registration

##### `GetProvider(name string) (DiscoveryProvider, error)`
Retrieves a specific provider by name.

##### `GetDefaultProvider() (DiscoveryProvider, error)`
Returns the default discovery provider.

##### `RegisterService(ctx context.Context, registration *types.ServiceRegistration) error`
Registers a service using the default provider.

**Parameters:**
- `ctx`: Context for cancellation and timeouts
- `registration`: Service registration details

**Returns:**
- `error`: Any error that occurred

##### `RegisterServiceWithProvider(ctx context.Context, providerName string, registration *types.ServiceRegistration) error`
Registers a service using a specific provider.

##### `DeregisterService(ctx context.Context, serviceID string) error`
Deregisters a service using the default provider.

##### `DeregisterServiceWithProvider(ctx context.Context, providerName string, serviceID string) error`
Deregisters a service using a specific provider.

##### `UpdateService(ctx context.Context, registration *types.ServiceRegistration) error`
Updates a service using the default provider.

##### `UpdateServiceWithProvider(ctx context.Context, providerName string, registration *types.ServiceRegistration) error`
Updates a service using a specific provider.

##### `DiscoverServices(ctx context.Context, query *types.ServiceQuery) ([]*types.Service, error)`
Discovers services using the default provider.

##### `DiscoverServicesWithProvider(ctx context.Context, providerName string, query *types.ServiceQuery) ([]*types.Service, error)`
Discovers services using a specific provider.

##### `GetService(ctx context.Context, serviceName string) (*types.Service, error)`
Gets a specific service using the default provider.

##### `GetServiceWithProvider(ctx context.Context, providerName string, serviceName string) (*types.Service, error)`
Gets a specific service using a specific provider.

##### `GetServiceInstance(ctx context.Context, serviceName, instanceID string) (*types.ServiceInstance, error)`
Gets a specific service instance using the default provider.

##### `GetServiceInstanceWithProvider(ctx context.Context, providerName string, serviceName, instanceID string) (*types.ServiceInstance, error)`
Gets a specific service instance using a specific provider.

##### `SetHealth(ctx context.Context, serviceID string, health types.HealthStatus) error`
Sets the health status of a service using the default provider.

##### `SetHealthWithProvider(ctx context.Context, providerName string, serviceID string, health types.HealthStatus) error`
Sets the health status of a service using a specific provider.

##### `GetHealth(ctx context.Context, serviceID string) (types.HealthStatus, error)`
Gets the health status of a service using the default provider.

##### `GetHealthWithProvider(ctx context.Context, providerName string, serviceID string) (types.HealthStatus, error)`
Gets the health status of a service using a specific provider.

##### `WatchServices(ctx context.Context, options *types.WatchOptions) (<-chan *types.ServiceEvent, error)`
Watches for service changes using the default provider.

##### `WatchServicesWithProvider(ctx context.Context, providerName string, options *types.WatchOptions) (<-chan *types.ServiceEvent, error)`
Watches for service changes using a specific provider.

##### `StopWatch(ctx context.Context, watchID string) error`
Stops watching for service changes using the default provider.

##### `StopWatchWithProvider(ctx context.Context, providerName string, watchID string) error`
Stops watching for service changes using a specific provider.

##### `GetStats(ctx context.Context) (map[string]*types.DiscoveryStats, error)`
Returns discovery statistics from all providers.

##### `ListServices(ctx context.Context) (map[string][]string, error)`
Returns a list of all services from all providers.

##### `Close() error`
Closes all discovery providers.

##### `ListProviders() []string`
Returns a list of registered provider names.

##### `GetProviderInfo() map[string]*types.ProviderInfo`
Returns information about all registered providers.

### Types

#### ManagerConfig
Configuration for the discovery manager.

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

#### ServiceRegistration
Represents a service registration request.

```go
type ServiceRegistration struct {
    ID       string            `json:"id"`
    Name     string            `json:"name"`
    Address  string            `json:"address"`
    Port     int               `json:"port"`
    Protocol string            `json:"protocol"`
    Tags     []string          `json:"tags"`
    Metadata map[string]string `json:"metadata"`
    Health   HealthStatus      `json:"health"`
    TTL      time.Duration     `json:"ttl"`
    Weight   int               `json:"weight"`
}
```

#### ServiceQuery
Represents a query for discovering services.

```go
type ServiceQuery struct {
    Name     string            `json:"name"`
    Tags     []string          `json:"tags"`
    Metadata map[string]string `json:"metadata"`
    Health   HealthStatus      `json:"health"`
    Limit    int               `json:"limit"`
}
```

#### Service
Represents a service with multiple instances.

```go
type Service struct {
    Name      string             `json:"name"`
    Instances []*ServiceInstance `json:"instances"`
    Tags      []string           `json:"tags"`
    Metadata  map[string]string  `json:"metadata"`
}
```

#### ServiceInstance
Represents a service instance.

```go
type ServiceInstance struct {
    ID          string            `json:"id"`
    Name        string            `json:"name"`
    Address     string            `json:"address"`
    Port        int               `json:"port"`
    Protocol    string            `json:"protocol"`
    Tags        []string          `json:"tags"`
    Metadata    map[string]string `json:"metadata"`
    Health      HealthStatus      `json:"health"`
    Weight      int               `json:"weight"`
    TTL         time.Duration     `json:"ttl"`
    LastUpdated time.Time         `json:"last_updated"`
}
```

#### HealthStatus
Represents the health status of a service.

```go
const (
    HealthPassing  HealthStatus = "passing"
    HealthWarning  HealthStatus = "warning"
    HealthCritical HealthStatus = "critical"
    HealthUnknown  HealthStatus = "unknown"
)
```

#### ServiceEvent
Represents a service discovery event.

```go
type ServiceEvent struct {
    Type      ServiceEventType `json:"type"`
    Service   *Service         `json:"service"`
    Instance  *ServiceInstance `json:"instance,omitempty"`
    Timestamp time.Time        `json:"timestamp"`
    Provider  string           `json:"provider"`
}
```

## Advanced Usage

### Service Registration

```go
// Register multiple service instances
services := []*types.ServiceRegistration{
    {
        ID:       "user-service-1",
        Name:     "user-service",
        Address:  "10.0.1.10",
        Port:     8080,
        Protocol: "http",
        Tags:     []string{"api", "user", "v1", "production"},
        Metadata: map[string]string{
            "version": "1.0.0",
            "team":    "backend",
            "region":  "us-east-1",
        },
        Health: types.HealthPassing,
        TTL:     30 * time.Second,
        Weight:  100,
    },
    {
        ID:       "user-service-2",
        Name:     "user-service",
        Address:  "10.0.1.11",
        Port:     8080,
        Protocol: "http",
        Tags:     []string{"api", "user", "v1", "production"},
        Metadata: map[string]string{
            "version": "1.0.0",
            "team":    "backend",
            "region":  "us-east-1",
        },
        Health: types.HealthPassing,
        TTL:     30 * time.Second,
        Weight:  100,
    },
    {
        ID:       "user-service-3",
        Name:     "user-service",
        Address:  "10.0.1.12",
        Port:     8080,
        Protocol: "http",
        Tags:     []string{"api", "user", "v2", "staging"},
        Metadata: map[string]string{
            "version": "2.0.0",
            "team":    "backend",
            "region":  "us-west-2",
        },
        Health: types.HealthWarning,
        TTL:     30 * time.Second,
        Weight:  50,
    },
}

for _, service := range services {
    err := manager.RegisterService(ctx, service)
    if err != nil {
        log.Printf("Failed to register service %s: %v", service.ID, err)
    } else {
        fmt.Printf("Registered service: %s\n", service.ID)
    }
}
```

### Service Discovery

```go
// Discover services by name
query := &types.ServiceQuery{
    Name: "user-service",
}

services, err := manager.DiscoverServices(ctx, query)
if err != nil {
    log.Printf("Failed to discover services: %v", err)
    return
}

for _, service := range services {
    fmt.Printf("Service: %s\n", service.Name)
    for _, instance := range service.Instances {
        fmt.Printf("  Instance: %s (%s:%d) - Health: %s\n", 
            instance.ID, instance.Address, instance.Port, instance.Health)
    }
}

// Discover services by tags
tagQuery := &types.ServiceQuery{
    Tags: []string{"api", "production"},
    Health: types.HealthPassing,
}

tagServices, err := manager.DiscoverServices(ctx, tagQuery)

// Discover services by metadata
metadataQuery := &types.ServiceQuery{
    Metadata: map[string]string{
        "team":    "backend",
        "version": "1.0.0",
    },
}

metadataServices, err := manager.DiscoverServices(ctx, metadataQuery)
```

### Health Management

```go
// Set health status for a service
err := manager.SetHealth(ctx, "user-service-1", types.HealthPassing)
if err != nil {
    log.Printf("Failed to set health: %v", err)
}

// Get health status
health, err := manager.GetHealth(ctx, "user-service-1")
if err != nil {
    log.Printf("Failed to get health: %v", err)
} else {
    fmt.Printf("Service health: %s\n", health)
}

// Health check loop
ticker := time.NewTicker(10 * time.Second)
defer ticker.Stop()

for {
    select {
    case <-ctx.Done():
        return
    case <-ticker.C:
        // Perform health check
        isHealthy := performHealthCheck()
        
        var healthStatus types.HealthStatus
        if isHealthy {
            healthStatus = types.HealthPassing
        } else {
            healthStatus = types.HealthCritical
        }
        
        err := manager.SetHealth(ctx, "user-service-1", healthStatus)
        if err != nil {
            log.Printf("Failed to update health: %v", err)
        }
    }
}
```

### Service Watching

```go
// Watch for service changes
watchOptions := &types.WatchOptions{
    ServiceName: "user-service",
    HealthOnly:  false,
    Timeout:     60 * time.Second,
}

eventChan, err := manager.WatchServices(ctx, watchOptions)
if err != nil {
    log.Printf("Failed to watch services: %v", err)
    return
}

// Process service events
go func() {
    for event := range eventChan {
        switch event.Type {
        case types.EventServiceRegistered:
            fmt.Printf("Service registered: %s\n", event.Service.Name)
        case types.EventServiceDeregistered:
            fmt.Printf("Service deregistered: %s\n", event.Service.Name)
        case types.EventInstanceAdded:
            fmt.Printf("Instance added: %s (%s:%d)\n", 
                event.Instance.ID, event.Instance.Address, event.Instance.Port)
        case types.EventInstanceRemoved:
            fmt.Printf("Instance removed: %s\n", event.Instance.ID)
        case types.EventHealthChanged:
            fmt.Printf("Health changed for %s: %s\n", 
                event.Instance.ID, event.Instance.Health)
        }
    }
}()
```

### Load Balancing

```go
// Get service instances for load balancing
service, err := manager.GetService(ctx, "user-service")
if err != nil {
    log.Printf("Failed to get service: %v", err)
    return
}

// Filter healthy instances
var healthyInstances []*types.ServiceInstance
for _, instance := range service.Instances {
    if instance.Health == types.HealthPassing {
        healthyInstances = append(healthyInstances, instance)
    }
}

if len(healthyInstances) == 0 {
    log.Println("No healthy instances available")
    return
}

// Simple round-robin load balancing
currentIndex := 0
selectedInstance := healthyInstances[currentIndex%len(healthyInstances)]
currentIndex++

fmt.Printf("Selected instance: %s (%s:%d)\n", 
    selectedInstance.ID, selectedInstance.Address, selectedInstance.Port)

// Weighted load balancing
var totalWeight int
for _, instance := range healthyInstances {
    totalWeight += instance.Weight
}

// Select instance based on weight
randomWeight := rand.Intn(totalWeight)
currentWeight := 0
for _, instance := range healthyInstances {
    currentWeight += instance.Weight
    if randomWeight < currentWeight {
        selectedInstance = instance
        break
    }
}
```

### Service Updates

```go
// Update service registration
updatedRegistration := &types.ServiceRegistration{
    ID:       "user-service-1",
    Name:     "user-service",
    Address:  "10.0.1.10",
    Port:     8080,
    Protocol: "http",
    Tags:     []string{"api", "user", "v1", "production", "updated"},
    Metadata: map[string]string{
        "version": "1.1.0",
        "team":    "backend",
        "region":  "us-east-1",
        "updated": "true",
    },
    Health: types.HealthPassing,
    TTL:     30 * time.Second,
    Weight:  120, // Increased weight
}

err := manager.UpdateService(ctx, updatedRegistration)
if err != nil {
    log.Printf("Failed to update service: %v", err)
} else {
    fmt.Println("Service updated successfully")
}
```

### Service Deregistration

```go
// Deregister a service instance
err := manager.DeregisterService(ctx, "user-service-1")
if err != nil {
    log.Printf("Failed to deregister service: %v", err)
} else {
    fmt.Println("Service deregistered successfully")
}

// Deregister all instances of a service
service, err := manager.GetService(ctx, "user-service")
if err != nil {
    log.Printf("Failed to get service: %v", err)
    return
}

for _, instance := range service.Instances {
    err := manager.DeregisterService(ctx, instance.ID)
    if err != nil {
        log.Printf("Failed to deregister instance %s: %v", instance.ID, err)
    } else {
        fmt.Printf("Deregistered instance: %s\n", instance.ID)
    }
}
```

### Statistics and Monitoring

```go
// Get discovery statistics
stats, err := manager.GetStats(ctx)
if err != nil {
    log.Printf("Failed to get stats: %v", err)
    return
}

for providerName, stat := range stats {
    fmt.Printf("Provider: %s\n", providerName)
    fmt.Printf("  Services Registered: %d\n", stat.ServicesRegistered)
    fmt.Printf("  Instances Active: %d\n", stat.InstancesActive)
    fmt.Printf("  Queries Processed: %d\n", stat.QueriesProcessed)
    fmt.Printf("  Uptime: %v\n", stat.Uptime)
    fmt.Printf("  Last Update: %v\n", stat.LastUpdate)
    fmt.Println()
}

// List all services
allServices, err := manager.ListServices(ctx)
if err != nil {
    log.Printf("Failed to list services: %v", err)
    return
}

for providerName, services := range allServices {
    fmt.Printf("Provider %s services:\n", providerName)
    for _, serviceName := range services {
        fmt.Printf("  - %s\n", serviceName)
    }
}
```

### Provider Management

```go
// Get provider information
providerInfo := manager.GetProviderInfo()
for name, info := range providerInfo {
    fmt.Printf("Provider: %s\n", name)
    fmt.Printf("  Connected: %t\n", info.IsConnected)
    fmt.Printf("  Features: %v\n", info.SupportedFeatures)
    if info.ConnectionInfo != nil {
        fmt.Printf("  Host: %s:%d\n", info.ConnectionInfo.Host, info.ConnectionInfo.Port)
        fmt.Printf("  Status: %s\n", info.ConnectionInfo.Status)
    }
    fmt.Println()
}

// List all providers
providers := manager.ListProviders()
fmt.Printf("Available providers: %v\n", providers)
```

### Error Handling

```go
services, err := manager.DiscoverServices(ctx, query)
if err != nil {
    // Handle different types of errors
    switch {
    case strings.Contains(err.Error(), "service not found"):
        log.Printf("Service not found: %v", err)
    case strings.Contains(err.Error(), "connection"):
        log.Printf("Discovery provider connection error: %v", err)
    case strings.Contains(err.Error(), "timeout"):
        log.Printf("Discovery operation timeout: %v", err)
    default:
        log.Printf("Service discovery failed: %v", err)
    }
    return
}

// Handle empty results
if len(services) == 0 {
    log.Println("No services found matching query")
    return
}
```

### Configuration Management

```go
// Custom configuration
config := &discovery.ManagerConfig{
    DefaultProvider: "consul",
    RetryAttempts:   5,
    RetryDelay:      2 * time.Second,
    Timeout:         60 * time.Second,
    FallbackEnabled: true,
    Metadata: map[string]string{
        "environment": "production",
        "version":     "1.0.0",
    },
}

manager := discovery.NewDiscoveryManager(config, logger)
```

## Best Practices

1. **Service Naming**: Use consistent, hierarchical service names
2. **Health Checks**: Implement proper health checks for all services
3. **TTL Management**: Set appropriate TTL values for service registrations
4. **Error Handling**: Implement comprehensive error handling for all operations
5. **Monitoring**: Monitor service discovery statistics and health
6. **Load Balancing**: Use appropriate load balancing strategies
7. **Graceful Shutdown**: Properly deregister services on shutdown
8. **Security**: Secure service discovery communications
9. **Testing**: Test service discovery in different scenarios
10. **Documentation**: Document service configurations and dependencies

## Contributing

Contributions are welcome! Please read the contributing guidelines and submit pull requests for any improvements.

## License

This library is licensed under the MIT License. See the LICENSE file for details.
