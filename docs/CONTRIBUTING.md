# Contributing Guide

## Overview

Terima kasih atas minat Anda untuk berkontribusi pada Microservices Library Go! Panduan ini akan membantu Anda memahami cara berkontribusi dengan efektif.

## Getting Started

### Prerequisites

- **Go**: Version 1.19 atau lebih baru
- **Git**: Version 2.0 atau lebih baru
- **Docker**: Version 20.10 atau lebih baru (opsional)
- **Make**: Untuk menjalankan task otomatis

### Development Setup

```bash
# Fork repository
git clone https://github.com/your-username/microservices-library-go.git
cd microservices-library-go

# Install dependencies
go mod download

# Run tests
make test

# Run linter
make lint

# Run all checks
make check
```

## Contribution Types

### 1. Bug Reports

Jika Anda menemukan bug, silakan buat issue dengan informasi berikut:

- **Description**: Deskripsi bug yang jelas
- **Steps to Reproduce**: Langkah-langkah untuk mereproduksi bug
- **Expected Behavior**: Perilaku yang diharapkan
- **Actual Behavior**: Perilaku yang terjadi
- **Environment**: Informasi environment (OS, Go version, dll)
- **Code Sample**: Contoh kode yang menyebabkan bug

### 2. Feature Requests

Untuk feature request, silakan buat issue dengan:

- **Description**: Deskripsi feature yang diinginkan
- **Use Case**: Kasus penggunaan yang spesifik
- **Proposed Solution**: Solusi yang diusulkan
- **Alternatives**: Alternatif lain yang dipertimbangkan

### 3. Code Contributions

#### Pull Request Process

1. **Fork Repository**: Fork repository ke akun GitHub Anda
2. **Create Branch**: Buat branch baru untuk feature/fix
3. **Make Changes**: Implementasikan perubahan
4. **Add Tests**: Tambahkan test untuk perubahan
5. **Update Documentation**: Update dokumentasi jika diperlukan
6. **Submit PR**: Submit pull request

#### Branch Naming Convention

- `feature/description`: Untuk feature baru
- `fix/description`: Untuk bug fix
- `docs/description`: Untuk dokumentasi
- `refactor/description`: Untuk refactoring
- `test/description`: Untuk test

#### Commit Message Format

```
type(scope): description

[optional body]

[optional footer]
```

**Types:**
- `feat`: Feature baru
- `fix`: Bug fix
- `docs`: Dokumentasi
- `style`: Formatting, semicolons, dll
- `refactor`: Refactoring code
- `test`: Menambah test
- `chore`: Maintenance tasks

**Examples:**
```
feat(ai): add support for Claude API
fix(cache): resolve Redis connection timeout
docs(api): update API documentation
test(database): add integration tests for PostgreSQL
```

## Code Standards

### 1. Go Code Style

#### Formatting
```bash
# Format code
go fmt ./...

# Run goimports
goimports -w .
```

#### Linting
```bash
# Run golangci-lint
golangci-lint run

# Run specific linters
golangci-lint run --enable=gofmt,govet,errcheck
```

#### Code Review Checklist

- [ ] Code follows Go conventions
- [ ] Functions have proper documentation
- [ ] Error handling is implemented
- [ ] Tests are included
- [ ] No hardcoded values
- [ ] Proper logging is implemented
- [ ] Security considerations are addressed

### 2. Documentation Standards

#### Code Documentation
```go
// Package ai provides AI service management
package ai

// Manager manages AI providers and handles requests
type Manager struct {
    // providers maps provider names to their implementations
    providers map[string]types.AIProvider
    // configs stores configuration for each provider
    configs   map[string]*types.ProviderConfig
    // stats tracks statistics for each provider
    stats     map[string]*types.ProviderStats
    // mu protects concurrent access to the manager
    mu        sync.RWMutex
}

// NewManager creates a new AI manager instance
func NewManager() *Manager {
    return &Manager{
        providers: make(map[string]types.AIProvider),
        configs:   make(map[string]*types.ProviderConfig),
        stats:     make(map[string]*types.ProviderStats),
    }
}

// AddProvider adds a new AI provider to the manager
// It returns an error if the provider configuration is invalid
func (m *Manager) AddProvider(config *types.ProviderConfig) error {
    // Implementation
}
```

#### README Documentation
- Clear description of the module
- Installation instructions
- Usage examples
- Configuration options
- API reference
- Troubleshooting guide

### 3. Test Standards

#### Unit Tests
```go
func TestManager_AddProvider(t *testing.T) {
    tests := []struct {
        name    string
        config  *types.ProviderConfig
        wantErr bool
    }{
        {
            name: "valid config",
            config: &types.ProviderConfig{
                Name:   "test",
                APIKey: "test-key",
            },
            wantErr: false,
        },
        {
            name: "invalid config",
            config: &types.ProviderConfig{
                Name: "",
            },
            wantErr: true,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            m := NewManager()
            err := m.AddProvider(tt.config)
            if (err != nil) != tt.wantErr {
                t.Errorf("AddProvider() error = %v, wantErr %v", err, tt.wantErr)
            }
        })
    }
}
```

#### Integration Tests
```go
func TestIntegration_Database(t *testing.T) {
    if testing.Short() {
        t.Skip("skipping integration test")
    }

    // Setup test database
    db := setupTestDB(t)
    defer cleanupTestDB(t, db)

    // Test database operations
    // ...
}
```

#### Test Coverage
```bash
# Run tests with coverage
go test -cover ./...

# Generate coverage report
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

## Adding New Providers

### 1. Provider Structure

```
providers/
└── newprovider/
    ├── provider.go
    ├── config.go
    └── README.md
```

### 2. Provider Implementation

```go
// provider.go
package newprovider

import (
    "context"
    "fmt"
    
    "github.com/anasamu/go-micro-libs/module/types"
    "github.com/sirupsen/logrus"
)

// Provider implements the module provider interface
type Provider struct {
    config *Config
    logger *logrus.Logger
    client *Client
}

// Config holds configuration for the provider
type Config struct {
    Host     string `json:"host"`
    Port     int    `json:"port"`
    APIKey   string `json:"api_key"`
    Timeout  int    `json:"timeout"`
}

// NewProvider creates a new provider instance
func NewProvider(logger *logrus.Logger) *Provider {
    return &Provider{
        logger: logger,
    }
}

// GetName returns the provider name
func (p *Provider) GetName() string {
    return "newprovider"
}

// Configure configures the provider with the given configuration
func (p *Provider) Configure(config map[string]interface{}) error {
    // Parse configuration
    // Validate configuration
    // Initialize client
    return nil
}

// HealthCheck checks the health of the provider
func (p *Provider) HealthCheck(ctx context.Context) error {
    // Implement health check
    return nil
}

// Implement other interface methods...
```

### 3. Provider Tests

```go
// provider_test.go
package newprovider

import (
    "context"
    "testing"
    
    "github.com/sirupsen/logrus"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

func TestProvider_GetName(t *testing.T) {
    provider := NewProvider(logrus.New())
    assert.Equal(t, "newprovider", provider.GetName())
}

func TestProvider_Configure(t *testing.T) {
    tests := []struct {
        name    string
        config  map[string]interface{}
        wantErr bool
    }{
        {
            name: "valid config",
            config: map[string]interface{}{
                "host":    "localhost",
                "port":    8080,
                "api_key": "test-key",
            },
            wantErr: false,
        },
        {
            name: "invalid config",
            config: map[string]interface{}{
                "host": "",
            },
            wantErr: true,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            provider := NewProvider(logrus.New())
            err := provider.Configure(tt.config)
            if tt.wantErr {
                require.Error(t, err)
            } else {
                require.NoError(t, err)
            }
        })
    }
}

func TestProvider_HealthCheck(t *testing.T) {
    provider := NewProvider(logrus.New())
    config := map[string]interface{}{
        "host":    "localhost",
        "port":    8080,
        "api_key": "test-key",
    }
    
    err := provider.Configure(config)
    require.NoError(t, err)
    
    ctx := context.Background()
    err = provider.HealthCheck(ctx)
    assert.NoError(t, err)
}
```

### 4. Provider Documentation

```markdown
# NewProvider

## Description

NewProvider is an implementation of the module provider interface for the NewService.

## Configuration

```yaml
newprovider:
  host: "localhost"
  port: 8080
  api_key: "your-api-key"
  timeout: 30
```

## Features

- Feature 1
- Feature 2
- Feature 3

## Usage

```go
provider := newprovider.NewProvider(logger)
config := map[string]interface{}{
    "host":    "localhost",
    "port":    8080,
    "api_key": "your-api-key",
}
err := provider.Configure(config)
```

## Examples

See the examples directory for complete usage examples.
```

## Adding New Modules

### 1. Module Structure

```
newmodule/
├── manager.go
├── types/
│   └── types.go
└── providers/
    └── example/
        └── provider.go
```

### 2. Module Implementation

```go
// manager.go
package newmodule

import (
    "context"
    "sync"
    
    "github.com/anasamu/go-micro-libs/newmodule/types"
    "github.com/sirupsen/logrus"
)

// Manager manages newmodule providers
type Manager struct {
    providers map[string]types.Provider
    configs   map[string]*types.ProviderConfig
    stats     map[string]*types.ProviderStats
    mu        sync.RWMutex
    logger    *logrus.Logger
}

// NewManager creates a new manager instance
func NewManager(logger *logrus.Logger) *Manager {
    return &Manager{
        providers: make(map[string]types.Provider),
        configs:   make(map[string]*types.ProviderConfig),
        stats:     make(map[string]*types.ProviderStats),
        logger:    logger,
    }
}

// RegisterProvider registers a new provider
func (m *Manager) RegisterProvider(provider types.Provider) error {
    m.mu.Lock()
    defer m.mu.Unlock()
    
    name := provider.GetName()
    if _, exists := m.providers[name]; exists {
        return fmt.Errorf("provider %s already registered", name)
    }
    
    m.providers[name] = provider
    m.stats[name] = &types.ProviderStats{
        Name:         name,
        RequestCount: 0,
        ErrorCount:   0,
        LastRequest:  time.Time{},
    }
    
    return nil
}

// Implement other manager methods...
```

### 3. Module Types

```go
// types/types.go
package types

import (
    "context"
    "time"
)

// Provider defines the interface for newmodule providers
type Provider interface {
    GetName() string
    Configure(config map[string]interface{}) error
    HealthCheck(ctx context.Context) error
    // Add other methods specific to the module
}

// ProviderConfig holds configuration for a provider
type ProviderConfig struct {
    Name        string                 `json:"name"`
    Type        string                 `json:"type"`
    Config      map[string]interface{} `json:"config"`
    RetryConfig *RetryConfig           `json:"retry_config,omitempty"`
}

// RetryConfig holds retry configuration
type RetryConfig struct {
    MaxAttempts int           `json:"max_attempts"`
    BaseDelay   time.Duration `json:"base_delay"`
    MaxDelay    time.Duration `json:"max_delay"`
    Multiplier  float64       `json:"multiplier"`
}

// ProviderStats holds statistics for a provider
type ProviderStats struct {
    Name         string    `json:"name"`
    RequestCount int64     `json:"request_count"`
    ErrorCount   int64     `json:"error_count"`
    LastRequest  time.Time `json:"last_request"`
    LastError    time.Time `json:"last_error"`
}

// Add other types specific to the module...
```

## Performance Guidelines

### 1. Memory Management

- Use object pooling for frequently created objects
- Avoid memory leaks in long-running processes
- Use appropriate data structures for the use case

### 2. Concurrency

- Use appropriate synchronization primitives
- Avoid race conditions
- Use context for cancellation and timeouts

### 3. I/O Operations

- Use connection pooling
- Implement proper timeouts
- Use async operations where appropriate

## Security Guidelines

### 1. Input Validation

- Validate all input parameters
- Sanitize user input
- Use appropriate data types

### 2. Authentication and Authorization

- Implement proper authentication
- Use secure token handling
- Implement proper authorization checks

### 3. Data Protection

- Encrypt sensitive data
- Use secure communication protocols
- Implement proper logging without exposing sensitive data

## Release Process

### 1. Versioning

We follow [Semantic Versioning](https://semver.org/):

- **MAJOR**: Breaking changes
- **MINOR**: New features (backward compatible)
- **PATCH**: Bug fixes (backward compatible)

### 2. Release Checklist

- [ ] All tests pass
- [ ] Documentation is updated
- [ ] CHANGELOG is updated
- [ ] Version is bumped
- [ ] Release notes are prepared
- [ ] Tag is created
- [ ] Release is published

### 3. Release Steps

```bash
# Update version
git tag v1.0.0
git push origin v1.0.0

# Create release
gh release create v1.0.0 --title "v1.0.0" --notes "Release notes"
```

## Community Guidelines

### 1. Code of Conduct

- Be respectful and inclusive
- Focus on constructive feedback
- Help others learn and grow
- Follow the project's coding standards

### 2. Communication

- Use clear and concise language
- Provide context for your questions
- Be patient with responses
- Use appropriate channels for different types of communication

### 3. Getting Help

- Check existing documentation first
- Search for similar issues
- Provide minimal reproducible examples
- Be specific about your problem

## Recognition

Contributors will be recognized in:

- CONTRIBUTORS.md file
- Release notes
- Project documentation
- GitHub contributors page

Thank you for contributing to Microservices Library Go!
