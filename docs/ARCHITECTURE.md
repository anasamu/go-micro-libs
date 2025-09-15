# Architecture

## Overview

Microservices Library Go dirancang dengan arsitektur modular yang memungkinkan pengembang untuk menggunakan berbagai layanan microservices dengan interface yang konsisten. Library ini mengikuti prinsip-prinsip berikut:

- **Modularity**: Setiap modul dapat digunakan secara independen
- **Provider Pattern**: Interface yang konsisten untuk berbagai implementasi
- **Configuration Management**: Konfigurasi yang fleksibel dan terpusat
- **Error Handling**: Penanganan error yang konsisten
- **Logging**: Logging terstruktur dengan logrus
- **Health Checks**: Monitoring kesehatan layanan
- **Retry Logic**: Mekanisme retry untuk operasi yang gagal

## Core Components

### 1. Manager Pattern

Setiap modul memiliki `Manager` yang bertindak sebagai facade untuk mengelola multiple provider:

```go
type Manager struct {
    providers map[string]Provider
    configs   map[string]*ProviderConfig
    stats     map[string]*ProviderStats
    mu        sync.RWMutex
}
```

**Responsibilities:**
- Mengelola multiple provider
- Menyediakan interface yang konsisten
- Menangani konfigurasi dan statistik
- Implementasi retry logic dan fallback

### 2. Provider Interface

Setiap provider mengimplementasikan interface yang spesifik untuk modulnya:

```go
type Provider interface {
    GetName() string
    Configure(config map[string]interface{}) error
    HealthCheck(ctx context.Context) error
    // ... methods spesifik untuk modul
}
```

**Benefits:**
- Konsistensi interface
- Kemudahan testing
- Fleksibilitas dalam memilih implementasi
- Kemudahan dalam menambah provider baru

### 3. Type System

Setiap modul memiliki package `types` yang mendefinisikan:

- **Interfaces**: Kontrak untuk provider
- **Request/Response**: Struktur data untuk operasi
- **Configuration**: Konfigurasi untuk provider
- **Statistics**: Metrik dan statistik
- **Errors**: Error types yang spesifik

## Module Architecture

### AI Module

```
ai/
├── manager.go          # AIManager implementation
├── types/
│   └── types.go        # AI interfaces and types
└── providers/
    ├── openai/
    ├── anthropic/
    ├── xai/
    ├── deepseek/
    └── google/
```

**Features:**
- Multiple AI provider support
- Fallback mechanism
- Model information retrieval
- Text generation and embedding
- Health monitoring

### Database Module

```
database/
├── manager.go          # DatabaseManager implementation
├── types/
│   └── types.go        # Database interfaces and types
├── providers/
│   ├── postgresql/
│   ├── mysql/
│   ├── mongodb/
│   └── ...
└── migrations/
    ├── migration.go    # Migration utilities
    └── cli.go          # CLI for migrations
```

**Features:**
- Multiple database support
- Transaction management
- Connection pooling
- Migration support
- Query optimization

### Cache Module

```
cache/
├── manager.go          # CacheManager implementation
├── types/
│   └── types.go        # Cache interfaces and types
└── providers/
    ├── redis/
    ├── memcache/
    └── memory/
```

**Features:**
- Multiple cache provider support
- Tag-based invalidation
- Batch operations
- TTL management
- Fallback mechanisms

### Storage Module

```
storage/
├── manager.go          # StorageManager implementation
├── types/
│   └── types.go        # Storage interfaces and types
└── providers/
    ├── s3/
    ├── gcs/
    ├── azure/
    └── minio/
```

**Features:**
- Multiple storage provider support
- Presigned URL generation
- Bucket management
- File validation
- Metadata handling

### Messaging Module

```
messaging/
├── manager.go          # MessagingManager implementation
├── types/
│   └── types.go        # Messaging interfaces and types
└── providers/
    ├── kafka/
    ├── nats/
    ├── rabbitmq/
    └── sqs/
```

**Features:**
- Multiple messaging provider support
- Topic/queue management
- Message serialization
- Batch publishing
- Consumer groups

## Configuration Architecture

### Configuration Hierarchy

1. **Default Configuration**: Konfigurasi default untuk setiap provider
2. **Environment Variables**: Override dengan environment variables
3. **Configuration Files**: Konfigurasi dari file (YAML, JSON, TOML)
4. **Runtime Configuration**: Konfigurasi yang dapat diubah saat runtime

### Configuration Providers

```go
type ConfigProvider interface {
    GetName() string
    LoadConfig(ctx context.Context) (map[string]interface{}, error)
    GetString(ctx context.Context, key string) (string, error)
    GetInt(ctx context.Context, key string) (int, error)
    GetBool(ctx context.Context, key string) (bool, error)
    WatchConfig(ctx context.Context, callback func(map[string]interface{})) error
}
```

**Supported Providers:**
- **Environment**: Environment variables
- **File**: YAML, JSON, TOML files
- **Consul**: Consul KV store
- **Vault**: HashiCorp Vault

## Error Handling

### Error Types

```go
type Error struct {
    Code    string `json:"code"`
    Message string `json:"message"`
    Details map[string]interface{} `json:"details,omitempty"`
}

type ProviderError struct {
    Provider string `json:"provider"`
    Error    error  `json:"error"`
}
```

### Error Handling Strategy

1. **Provider Errors**: Error yang berasal dari provider eksternal
2. **Configuration Errors**: Error dalam konfigurasi
3. **Validation Errors**: Error dalam validasi input
4. **Network Errors**: Error koneksi jaringan
5. **Timeout Errors**: Error timeout operasi

## Logging Architecture

### Structured Logging

```go
type LogEntry struct {
    Level     string                 `json:"level"`
    Message   string                 `json:"message"`
    Timestamp time.Time              `json:"timestamp"`
    Fields    map[string]interface{} `json:"fields"`
    Provider  string                 `json:"provider,omitempty"`
}
```

### Log Levels

- **DEBUG**: Informasi debugging
- **INFO**: Informasi umum
- **WARN**: Peringatan
- **ERROR**: Error yang dapat ditangani
- **FATAL**: Error yang tidak dapat ditangani

### Log Providers

- **Console**: Output ke console
- **File**: Output ke file
- **Elasticsearch**: Output ke Elasticsearch

## Health Check Architecture

### Health Check Interface

```go
type HealthChecker interface {
    HealthCheck(ctx context.Context) error
    GetHealthStatus() HealthStatus
}
```

### Health Status

```go
type HealthStatus struct {
    Status    string                 `json:"status"`
    Timestamp time.Time              `json:"timestamp"`
    Details   map[string]interface{} `json:"details,omitempty"`
}
```

**Status Values:**
- **healthy**: Layanan berfungsi normal
- **degraded**: Layanan berfungsi dengan keterbatasan
- **unhealthy**: Layanan tidak berfungsi

## Monitoring Architecture

### Metrics Collection

```go
type Metric struct {
    Name   string            `json:"name"`
    Value  float64           `json:"value"`
    Labels map[string]string `json:"labels"`
    Type   MetricType        `json:"type"`
}
```

### Metric Types

- **Counter**: Metrik yang hanya bertambah
- **Gauge**: Metrik yang dapat naik turun
- **Histogram**: Distribusi nilai
- **Summary**: Statistik ringkasan

### Monitoring Providers

- **Prometheus**: Metrics collection
- **Jaeger**: Distributed tracing
- **Elasticsearch**: Log aggregation

## Security Architecture

### Authentication

```go
type AuthProvider interface {
    Authenticate(ctx context.Context, request *AuthRequest) (*AuthResponse, error)
    ValidateToken(ctx context.Context, request *TokenValidationRequest) (*TokenValidationResponse, error)
    RefreshToken(ctx context.Context, request *TokenRefreshRequest) (*TokenRefreshResponse, error)
}
```

### Authorization

```go
type AuthzProvider interface {
    Authorize(ctx context.Context, request *AuthorizationRequest) (*AuthorizationResponse, error)
    CheckPermission(ctx context.Context, userID string, resource string, action string) (bool, error)
}
```

### Security Features

- **JWT**: JSON Web Token support
- **OAuth2**: OAuth2 authentication
- **2FA**: Two-factor authentication
- **RBAC**: Role-based access control
- **ABAC**: Attribute-based access control
- **ACL**: Access control lists

## Performance Considerations

### Connection Pooling

```go
type ConnectionPool struct {
    MaxConnections int
    MinConnections int
    MaxIdleTime    time.Duration
    MaxLifetime    time.Duration
}
```

### Caching Strategy

1. **L1 Cache**: In-memory cache
2. **L2 Cache**: Distributed cache (Redis)
3. **Cache Invalidation**: Tag-based invalidation
4. **Cache Warming**: Pre-loading frequently accessed data

### Retry Logic

```go
type RetryConfig struct {
    MaxAttempts int
    BaseDelay   time.Duration
    MaxDelay    time.Duration
    Multiplier  float64
}
```

## Scalability Patterns

### Horizontal Scaling

- **Load Balancing**: Distribusi beban antar instance
- **Service Discovery**: Penemuan layanan otomatis
- **Circuit Breaker**: Isolasi layanan yang gagal
- **Bulkhead**: Isolasi resource

### Vertical Scaling

- **Connection Pooling**: Optimasi koneksi database
- **Memory Management**: Optimasi penggunaan memory
- **CPU Optimization**: Optimasi penggunaan CPU

## Deployment Architecture

### Container Support

- **Docker**: Containerization
- **Kubernetes**: Orchestration
- **Helm**: Package management

### Configuration Management

- **ConfigMaps**: Kubernetes configuration
- **Secrets**: Sensitive data management
- **Environment Variables**: Runtime configuration

### Service Mesh

- **Istio**: Service mesh integration
- **Linkerd**: Alternative service mesh
- **Consul Connect**: Service mesh dengan Consul

## Testing Architecture

### Unit Testing

```go
func TestProvider(t *testing.T) {
    provider := NewProvider()
    config := map[string]interface{}{
        "host": "localhost",
        "port": 5432,
    }
    
    err := provider.Configure(config)
    assert.NoError(t, err)
    
    // Test provider functionality
}
```

### Integration Testing

```go
func TestIntegration(t *testing.T) {
    // Setup test environment
    // Test with real services
    // Cleanup
}
```

### Mock Providers

```go
type MockProvider struct {
    // Mock implementation
}

func (m *MockProvider) GetName() string {
    return "mock"
}
```

## Best Practices

### Code Organization

1. **Single Responsibility**: Setiap modul memiliki tanggung jawab yang jelas
2. **Interface Segregation**: Interface yang spesifik dan focused
3. **Dependency Injection**: Dependency injection untuk testability
4. **Configuration**: Konfigurasi yang fleksibel dan terpusat

### Error Handling

1. **Structured Errors**: Error yang terstruktur dan informatif
2. **Error Wrapping**: Wrapping error dengan context
3. **Retry Logic**: Implementasi retry untuk operasi yang dapat diulang
4. **Circuit Breaker**: Implementasi circuit breaker untuk resilience

### Performance

1. **Connection Pooling**: Pool koneksi untuk database dan cache
2. **Caching**: Implementasi caching yang efektif
3. **Batch Operations**: Operasi batch untuk efisiensi
4. **Async Operations**: Operasi asynchronous untuk non-blocking

### Security

1. **Input Validation**: Validasi input yang ketat
2. **Authentication**: Implementasi authentication yang kuat
3. **Authorization**: Implementasi authorization yang granular
4. **Encryption**: Enkripsi data sensitif

### Monitoring

1. **Health Checks**: Health check yang komprehensif
2. **Metrics**: Metrics yang relevan dan actionable
3. **Logging**: Logging yang terstruktur dan searchable
4. **Tracing**: Distributed tracing untuk debugging
