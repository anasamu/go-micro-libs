# ZeroTrust Library

ZeroTrust library implements Zero Trust principles for microservices, providing mutual TLS (mTLS) and identity-based access without implicit trust.

## Features

### Core Features
- **Service Identity Management**: Secure service identification and authentication
- **Mutual TLS (mTLS)**: Certificate-based authentication between services
- **Policy Engine**: Flexible policy evaluation and enforcement
- **Network Segmentation**: Micro-segmentation and zero-trust networking
- **Certificate Management**: Automated certificate generation, validation, and renewal

### Supported Providers

#### 1. SPIFFE/SPIRE Provider
- **Identity Management**: Secure Production Identity Framework for Everyone (SPIFFE)
- **Attestation**: SPIRE (SPIFFE Runtime Environment) integration
- **Certificate Generation**: Automatic SPIFFE certificate generation
- **Trust Domain Management**: Multi-tenant trust domain support

#### 2. Istio Service Mesh Provider
- **Service Mesh Security**: Istio-based service mesh security
- **Traffic Management**: Envoy proxy-based traffic management
- **Policy Enforcement**: Istio authorization policies
- **Network Segmentation**: Service mesh-based micro-segmentation

#### 3. mTLS via cert-manager Provider
- **Certificate Management**: Kubernetes cert-manager integration
- **Automated Renewal**: Automatic certificate renewal
- **CA Management**: Certificate Authority management
- **Key Rotation**: Automated key rotation

## Installation

```go
go get github.com/anasamu/go-micro-libs/zerotrust
```

## Quick Start

### Basic Usage

```go
package main

import (
    "context"
    "log"
    
    "github.com/anasamu/go-micro-libs/zerotrust"
    "github.com/anasamu/go-micro-libs/zerotrust/providers/spiffe"
    "github.com/anasamu/go-micro-libs/zerotrust/providers/istio"
    "github.com/anasamu/go-micro-libs/zerotrust/providers/mtls"
    "github.com/sirupsen/logrus"
)

func main() {
    // Create logger
    logger := logrus.New()
    
    // Create ZeroTrust manager
    manager := zerotrust.NewZeroTrustManager(nil, logger)
    
    // Register SPIFFE provider
    spiffeProvider := spiffe.NewSPIFFEProvider("spiffe", logger)
    spiffeConfig := map[string]interface{}{
        "server_url":   "spire-server:8081",
        "trust_domain": "example.org",
    }
    spiffeProvider.Configure(spiffeConfig)
    manager.RegisterProvider(spiffeProvider)
    
    // Register Istio provider
    istioProvider := istio.NewIstioProvider("istio", logger)
    istioConfig := map[string]interface{}{
        "namespace":  "default",
        "mesh_name":  "default",
    }
    istioProvider.Configure(istioConfig)
    manager.RegisterProvider(istioProvider)
    
    // Register mTLS provider
    mtlsProvider := mtls.NewMTLSProvider("mtls", logger)
    mtlsConfig := map[string]interface{}{
        "cluster_name": "production",
        "namespace":    "default",
    }
    mtlsProvider.Configure(mtlsConfig)
    manager.RegisterProvider(mtlsProvider)
    
    // Use the manager...
}
```

### Service Authentication

```go
// Authenticate a service using SPIFFE
authRequest := &types.ServiceAuthRequest{
    ServiceID:  "user-service",
    SPIFFEID:   "spiffe://example.org/service/user-service",
    TrustDomain: "example.org",
    Context: map[string]interface{}{
        "environment": "production",
    },
}

response, err := manager.AuthenticateService(ctx, "spiffe", authRequest)
if err != nil {
    log.Fatal(err)
}

if response.Success {
    log.Printf("Service authenticated: %s", response.IdentityID)
}
```

### Certificate Management

```go
// Generate mTLS certificate
certRequest := &types.MTLSCertRequest{
    ServiceID:      "user-service",
    Subject:        "CN=user-service",
    SubjectAltNames: []string{"user-service.default.svc.cluster.local"},
    ValidityPeriod: 24 * time.Hour,
    KeySize:        2048,
    KeyType:        "RSA",
}

certResponse, err := manager.GenerateMTLSCertificate(ctx, "mtls", certRequest)
if err != nil {
    log.Fatal(err)
}

log.Printf("Certificate generated: %s", certResponse.Certificate.SerialNumber)
```

### Policy Evaluation

```go
// Evaluate access policy
policyRequest := &types.PolicyEvaluationRequest{
    PolicyID: "user-service-access",
    Subject:  "user-service",
    Resource: "user-database",
    Action:   "read",
    Context: map[string]interface{}{
        "time": "business-hours",
        "location": "datacenter-1",
    },
}

policyResponse, err := manager.EvaluatePolicy(ctx, "istio", policyRequest)
if err != nil {
    log.Fatal(err)
}

if policyResponse.Allowed {
    log.Printf("Access allowed: %s", policyResponse.Reason)
} else {
    log.Printf("Access denied: %s", policyResponse.Reason)
}
```

## Configuration

### SPIFFE/SPIRE Configuration

```yaml
spiffe:
  server_url: "spire-server:8081"
  trust_domain: "example.org"
  retry_attempts: 3
  timeout: "30s"
```

### Istio Configuration

```yaml
istio:
  namespace: "default"
  mesh_name: "default"
  host: "istiod.istio-system.svc.cluster.local"
  port: 15012
  secure: true
```

### mTLS Configuration

```yaml
mtls:
  cluster_name: "production"
  namespace: "default"
  cert_manager:
    issuer: "letsencrypt-prod"
    secret_name: "mtls-certs"
```

## Advanced Features

### Network Segmentation

```go
// Create network segment
segmentRequest := &types.NetworkSegmentRequest{
    SegmentID:   "frontend-segment",
    Name:        "Frontend Network Segment",
    Description: "Network segment for frontend services",
    NetworkCIDR: "10.0.1.0/24",
    Policies: []types.ServiceMeshPolicy{
        {
            ID:       "frontend-policy",
            Name:     "Frontend Access Policy",
            Type:     "authorization",
            Enabled:  true,
            Priority: 100,
            Rules: []types.PolicyRule{
                {
                    ID:          "allow-frontend",
                    Name:        "Allow Frontend Access",
                    Description: "Allow frontend services to access backend",
                    Enabled:     true,
                    Priority:    1,
                    Conditions: []types.PolicyCondition{
                        {
                            ID:       "frontend-service",
                            Type:     "service",
                            Field:    "service.name",
                            Operator: "equals",
                            Value:    "frontend-*",
                        },
                    },
                    Actions: []types.PolicyAction{
                        {
                            ID:   "allow",
                            Type: "allow",
                        },
                    },
                },
            },
        },
    },
}

segmentResponse, err := manager.CreateNetworkSegment(ctx, "istio", segmentRequest)
if err != nil {
    log.Fatal(err)
}

log.Printf("Network segment created: %s", segmentResponse.SegmentID)
```

### Service Mesh Configuration

```go
// Configure service mesh security
meshConfigRequest := &types.ServiceMeshConfigRequest{
    ServiceID: "user-service",
    MeshType:  "istio",
    Namespace: "default",
    Configuration: map[string]interface{}{
        "mtls": map[string]interface{}{
            "mode": "STRICT",
        },
        "authorization": map[string]interface{}{
            "enabled": true,
            "policies": []string{"user-service-policy"},
        },
    },
    Policies: []types.ServiceMeshPolicy{
        {
            ID:       "user-service-policy",
            Name:     "User Service Policy",
            Type:     "authorization",
            Enabled:  true,
            Priority: 100,
        },
    },
}

meshResponse, err := manager.ConfigureServiceMesh(ctx, "istio", meshConfigRequest)
if err != nil {
    log.Fatal(err)
}

log.Printf("Service mesh configured: %s", meshResponse.Status)
```

## Monitoring and Observability

### Health Checks

```go
// Check provider health
healthResults := manager.HealthCheck(ctx)
for provider, err := range healthResults {
    if err != nil {
        log.Printf("Provider %s is unhealthy: %v", provider, err)
    } else {
        log.Printf("Provider %s is healthy", provider)
    }
}
```

### Statistics

```go
// Get provider statistics
stats := manager.GetStats(ctx)
for provider, statsData := range stats {
    log.Printf("Provider %s stats: %+v", provider, statsData)
}
```

## Best Practices

### 1. Certificate Management
- Use short-lived certificates (24 hours or less)
- Implement automated certificate renewal
- Rotate private keys regularly
- Monitor certificate expiration

### 2. Policy Design
- Follow principle of least privilege
- Use context-aware policies
- Implement defense in depth
- Regular policy audits

### 3. Network Segmentation
- Segment services by function
- Use micro-segmentation
- Implement zero-trust networking
- Monitor network traffic

### 4. Service Identity
- Use strong service identities
- Implement service attestation
- Validate service certificates
- Monitor identity changes

## Integration Examples

### With Go Micro Framework

```go
// In your microservice bootstrap
func bootstrapService(ctx context.Context, config *Config) error {
    // Initialize ZeroTrust manager
    ztManager := zerotrust.NewZeroTrustManager(config.ZeroTrust, logger)
    
    // Register providers
    spiffeProvider := spiffe.NewSPIFFEProvider("spiffe", logger)
    spiffeProvider.Configure(config.SPIFFE)
    ztManager.RegisterProvider(spiffeProvider)
    
    // Authenticate service
    authRequest := &types.ServiceAuthRequest{
        ServiceID: config.Service.Name,
        Context:   config.Service.Context,
    }
    
    authResponse, err := ztManager.AuthenticateService(ctx, "spiffe", authRequest)
    if err != nil {
        return err
    }
    
    // Store service identity
    config.Service.IdentityID = authResponse.IdentityID
    config.Service.SPIFFEID = authResponse.SPIFFEID
    
    return nil
}
```

### With Kubernetes

```yaml
# Service account with SPIFFE annotation
apiVersion: v1
kind: ServiceAccount
metadata:
  name: user-service
  namespace: default
  annotations:
    spire.io/spiffe-id: "spiffe://example.org/service/user-service"

---
# Pod with SPIFFE sidecar
apiVersion: v1
kind: Pod
metadata:
  name: user-service
spec:
  serviceAccountName: user-service
  containers:
  - name: user-service
    image: user-service:latest
  - name: spire-agent
    image: gcr.io/spiffe-io/spire-agent:latest
```

## Troubleshooting

### Common Issues

1. **Certificate Validation Failures**
   - Check certificate expiration
   - Verify trust chain
   - Validate SPIFFE ID format

2. **Policy Evaluation Errors**
   - Check policy syntax
   - Verify context data
   - Validate subject permissions

3. **Network Access Denied**
   - Check network policies
   - Verify service identity
   - Validate mTLS configuration

### Debug Logging

```go
// Enable debug logging
logger.SetLevel(logrus.DebugLevel)

// Add structured logging
logger.WithFields(logrus.Fields{
    "service_id": "user-service",
    "provider":   "spiffe",
    "operation":  "authenticate",
}).Debug("Service authentication started")
```

## Contributing

Please see [CONTRIBUTING.md](../../CONTRIBUTING.md) for contribution guidelines.

## License

This library is licensed under the MIT License. See [LICENSE](../../LICENSE) for details.
