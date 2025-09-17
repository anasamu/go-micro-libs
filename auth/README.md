# Auth Library

The Auth library provides a unified interface for authentication and authorization across multiple providers. It supports various authentication methods including JWT, OAuth2, 2FA, and authorization models like RBAC, ABAC, and ACL with comprehensive security features.

## Features

- **Multi-Provider Support**: Seamlessly switch between different auth providers
- **Authentication Methods**: JWT, OAuth2, 2FA, LDAP, SAML, OpenID Connect
- **Authorization Models**: RBAC, ABAC, ACL with policy engines
- **Security Features**: Encryption, token blacklisting, rate limiting, brute force protection
- **Session Management**: Comprehensive session handling and device management
- **Audit Logging**: Built-in audit trails and compliance features
- **Health Monitoring**: Provider health checks and statistics
- **Context Awareness**: Multi-tenant and dynamic context support

## Supported Providers

### Authentication Providers
- **JWT**: JSON Web Token authentication
- **OAuth2**: OAuth 2.0 and OpenID Connect
- **2FA**: Two-factor authentication
- **Auth0**: Auth0 integration
- **Keycloak**: Keycloak identity management
- **Okta**: Okta identity provider

### Authorization Providers
- **RBAC**: Role-Based Access Control
- **ABAC**: Attribute-Based Access Control
- **ACL**: Access Control Lists

## Installation

```bash
go get github.com/anasamu/go-micro-libs/auth
```

## Quick Start

```go
package main

import (
    "context"
    "fmt"
    "log"
    "time"

    "github.com/anasamu/go-micro-libs/auth"
    "github.com/anasamu/go-micro-libs/auth/types"
    "github.com/sirupsen/logrus"
)

func main() {
    // Create logger
    logger := logrus.New()

    // Create auth manager with default config
    config := auth.DefaultManagerConfig()
    manager := auth.NewAuthManager(config, logger)

    // Register JWT provider (example)
    // jwtProvider := jwt.NewJWTProvider()
    // manager.RegisterProvider(jwtProvider)

    // Authenticate user
    ctx := context.Background()
    authReq := &types.AuthRequest{
        Username: "john.doe",
        Password: "securepassword",
        DeviceID: "device-123",
        IPAddress: "192.168.1.100",
    }

    response, err := manager.Authenticate(ctx, "jwt", authReq)
    if err != nil {
        log.Fatal(err)
    }

    if response.Success {
        fmt.Printf("User authenticated: %s\n", response.UserID)
        fmt.Printf("Access token: %s\n", response.AccessToken)
    }
}
```

## API Reference

### AuthManager

The main manager for handling authentication and authorization operations.

#### Methods

##### `NewAuthManager(config *ManagerConfig, logger *logrus.Logger) *AuthManager`
Creates a new auth manager with the given configuration and logger.

##### `RegisterProvider(provider AuthProvider) error`
Registers a new authentication or authorization provider.

**Parameters:**
- `provider`: The auth provider to register

**Returns:**
- `error`: Any error that occurred during registration

##### `GetProvider(name string) (AuthProvider, error)`
Retrieves a specific provider by name.

##### `GetDefaultProvider() (AuthProvider, error)`
Returns the default auth provider.

##### `Authenticate(ctx context.Context, providerName string, request *types.AuthRequest) (*types.AuthResponse, error)`
Authenticates a user using the specified provider.

**Parameters:**
- `ctx`: Context for cancellation and timeouts
- `providerName`: Name of the provider to use
- `request`: Authentication request with credentials

**Returns:**
- `*types.AuthResponse`: Authentication response with tokens and user info
- `error`: Any error that occurred

##### `ValidateToken(ctx context.Context, providerName string, request *types.TokenValidationRequest) (*types.TokenValidationResponse, error)`
Validates a token using the specified provider.

##### `RefreshToken(ctx context.Context, providerName string, request *types.TokenRefreshRequest) (*types.TokenRefreshResponse, error)`
Refreshes an access token using the refresh token.

##### `RevokeToken(ctx context.Context, providerName string, request *types.TokenRevocationRequest) error`
Revokes a token, making it invalid.

##### `Authorize(ctx context.Context, providerName string, request *types.AuthorizationRequest) (*types.AuthorizationResponse, error)`
Authorizes a user for a specific resource and action.

##### `CheckPermission(ctx context.Context, providerName string, request *types.PermissionRequest) (*types.PermissionResponse, error)`
Checks if a user has a specific permission.

##### `HealthCheck(ctx context.Context) map[string]error`
Performs health check on all providers.

##### `GetStats(ctx context.Context) map[string]interface{}`
Returns statistics for all providers.

##### `Close() error`
Closes all providers and cleans up resources.

### Types

#### ManagerConfig
Configuration for the auth manager.

```go
type ManagerConfig struct {
    DefaultProvider string            `json:"default_provider"`
    RetryAttempts   int               `json:"retry_attempts"`
    RetryDelay      time.Duration     `json:"retry_delay"`
    Timeout         time.Duration     `json:"timeout"`
    Metadata        map[string]string `json:"metadata"`
}
```

#### AuthRequest
Authentication request.

```go
type AuthRequest struct {
    Username      string                 `json:"username"`
    Password      string                 `json:"password"`
    Email         string                 `json:"email"`
    Token         string                 `json:"token,omitempty"`
    TwoFactorCode string                 `json:"two_factor_code,omitempty"`
    DeviceID      string                 `json:"device_id,omitempty"`
    IPAddress     string                 `json:"ip_address,omitempty"`
    UserAgent     string                 `json:"user_agent,omitempty"`
    ServiceID     string                 `json:"service_id,omitempty"`
    Context       map[string]interface{} `json:"context,omitempty"`
    Metadata      map[string]interface{} `json:"metadata,omitempty"`
}
```

#### AuthResponse
Authentication response.

```go
type AuthResponse struct {
    Success      bool                   `json:"success"`
    UserID       string                 `json:"user_id"`
    AccessToken  string                 `json:"access_token,omitempty"`
    RefreshToken string                 `json:"refresh_token,omitempty"`
    ExpiresAt    time.Time              `json:"expires_at,omitempty"`
    TokenType    string                 `json:"token_type,omitempty"`
    Roles        []string               `json:"roles,omitempty"`
    Permissions  []string               `json:"permissions,omitempty"`
    Requires2FA  bool                   `json:"requires_2fa,omitempty"`
    ServiceID    string                 `json:"service_id,omitempty"`
    Context      map[string]interface{} `json:"context,omitempty"`
    Message      string                 `json:"message,omitempty"`
    Metadata     map[string]interface{} `json:"metadata,omitempty"`
}
```

#### TokenValidationRequest
Token validation request.

```go
type TokenValidationRequest struct {
    Token     string                 `json:"token"`
    TokenType string                 `json:"token_type,omitempty"`
    Metadata  map[string]interface{} `json:"metadata,omitempty"`
}
```

#### TokenValidationResponse
Token validation response.

```go
type TokenValidationResponse struct {
    Valid     bool                   `json:"valid"`
    UserID    string                 `json:"user_id,omitempty"`
    Claims    map[string]interface{} `json:"claims,omitempty"`
    ExpiresAt time.Time              `json:"expires_at,omitempty"`
    Message   string                 `json:"message,omitempty"`
    Metadata  map[string]interface{} `json:"metadata,omitempty"`
}
```

#### AuthorizationRequest
Authorization request.

```go
type AuthorizationRequest struct {
    UserID      string                 `json:"user_id"`
    Resource    string                 `json:"resource"`
    Action      string                 `json:"action"`
    Context     map[string]interface{} `json:"context,omitempty"`
    Environment map[string]interface{} `json:"environment,omitempty"`
    Metadata    map[string]interface{} `json:"metadata,omitempty"`
}
```

#### AuthorizationResponse
Authorization response.

```go
type AuthorizationResponse struct {
    Allowed  bool                   `json:"allowed"`
    Reason   string                 `json:"reason,omitempty"`
    Policies []string               `json:"policies,omitempty"`
    Metadata map[string]interface{} `json:"metadata,omitempty"`
}
```

#### PermissionRequest
Permission check request.

```go
type PermissionRequest struct {
    UserID     string                 `json:"user_id"`
    Permission string                 `json:"permission"`
    Resource   string                 `json:"resource,omitempty"`
    Context    map[string]interface{} `json:"context,omitempty"`
    Metadata   map[string]interface{} `json:"metadata,omitempty"`
}
```

#### PermissionResponse
Permission check response.

```go
type PermissionResponse struct {
    Granted  bool                   `json:"granted"`
    Reason   string                 `json:"reason,omitempty"`
    Metadata map[string]interface{} `json:"metadata,omitempty"`
}
```

## Advanced Usage

### JWT Authentication

```go
// Authenticate with JWT
authReq := &types.AuthRequest{
    Username: "john.doe",
    Password: "securepassword",
    DeviceID: "device-123",
}

response, err := manager.Authenticate(ctx, "jwt", authReq)
if err != nil {
    log.Fatal(err)
}

// Validate token
tokenReq := &types.TokenValidationRequest{
    Token: response.AccessToken,
}

validation, err := manager.ValidateToken(ctx, "jwt", tokenReq)
if err != nil {
    log.Fatal(err)
}

if validation.Valid {
    fmt.Printf("Token is valid for user: %s\n", validation.UserID)
}
```

### OAuth2 Authentication

```go
// Authenticate with OAuth2
authReq := &types.AuthRequest{
    Token: "oauth2-access-token",
    ServiceID: "oauth2-provider",
}

response, err := manager.Authenticate(ctx, "oauth2", authReq)
```

### Two-Factor Authentication

```go
// First step - username/password
authReq := &types.AuthRequest{
    Username: "john.doe",
    Password: "securepassword",
}

response, err := manager.Authenticate(ctx, "jwt", authReq)
if response.Requires2FA {
    // Second step - 2FA code
    authReq.TwoFactorCode = "123456"
    response, err = manager.Authenticate(ctx, "jwt", authReq)
}
```

### Token Management

```go
// Refresh token
refreshReq := &types.TokenRefreshRequest{
    RefreshToken: response.RefreshToken,
}

newTokens, err := manager.RefreshToken(ctx, "jwt", refreshReq)
if err != nil {
    log.Fatal(err)
}

// Revoke token
revokeReq := &types.TokenRevocationRequest{
    Token:  response.AccessToken,
    UserID: response.UserID,
    Reason: "user_logout",
}

err = manager.RevokeToken(ctx, "jwt", revokeReq)
```

### Authorization

```go
// Check authorization
authzReq := &types.AuthorizationRequest{
    UserID:   "user-123",
    Resource: "/api/users",
    Action:   "read",
    Context: map[string]interface{}{
        "ip_address": "192.168.1.100",
        "user_agent": "Mozilla/5.0...",
    },
}

authzResp, err := manager.Authorize(ctx, "rbac", authzReq)
if err != nil {
    log.Fatal(err)
}

if authzResp.Allowed {
    fmt.Println("User is authorized to perform this action")
} else {
    fmt.Printf("Access denied: %s\n", authzResp.Reason)
}
```

### Permission Checks

```go
// Check specific permission
permReq := &types.PermissionRequest{
    UserID:     "user-123",
    Permission: "users:read",
    Resource:   "/api/users",
    Context: map[string]interface{}{
        "department": "engineering",
    },
}

permResp, err := manager.CheckPermission(ctx, "rbac", permReq)
if err != nil {
    log.Fatal(err)
}

if permResp.Granted {
    fmt.Println("User has the required permission")
}
```

### Multi-Tenant Context

```go
// Authentication with tenant context
authReq := &types.AuthRequest{
    Username: "john.doe",
    Password: "securepassword",
    Context: map[string]interface{}{
        "tenant_id": "tenant-123",
        "organization": "acme-corp",
    },
}

response, err := manager.Authenticate(ctx, "jwt", authReq)
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
stats := manager.GetStats(ctx)
for provider, stat := range stats {
    fmt.Printf("Provider %s stats: %+v\n", provider, stat)
}
```

## Security Features

### Token Blacklisting
```go
// Revoke token to blacklist it
revokeReq := &types.TokenRevocationRequest{
    Token:  "compromised-token",
    UserID: "user-123",
    Reason: "security_breach",
}

err := manager.RevokeToken(ctx, "jwt", revokeReq)
```

### Rate Limiting
The library includes built-in rate limiting to prevent brute force attacks:

```go
// Configure rate limiting in provider
config := map[string]interface{}{
    "rate_limit": map[string]interface{}{
        "max_attempts": 5,
        "window":       "5m",
        "block_duration": "15m",
    },
}

provider.Configure(config)
```

### Audit Logging
All authentication and authorization events are automatically logged for compliance:

```go
// Audit logs are automatically generated for:
// - Login attempts (successful and failed)
// - Token validations
// - Authorization checks
// - Permission checks
// - Token revocations
```

## Best Practices

1. **Secure Token Storage**: Store tokens securely and use HTTPS
2. **Token Expiration**: Set appropriate token expiration times
3. **Refresh Tokens**: Implement proper refresh token rotation
4. **Rate Limiting**: Configure rate limiting to prevent abuse
5. **Audit Logging**: Enable comprehensive audit logging
6. **Error Handling**: Don't expose sensitive information in errors
7. **Context Validation**: Validate user context for authorization
8. **Multi-Factor Authentication**: Enable 2FA for sensitive operations
9. **Token Blacklisting**: Implement token revocation mechanisms
10. **Health Monitoring**: Monitor auth provider health regularly

## Contributing

Contributions are welcome! Please read the contributing guidelines and submit pull requests for any improvements.

## License

This library is licensed under the MIT License. See the LICENSE file for details.
