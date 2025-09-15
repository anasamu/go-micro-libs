package zerotrust

import (
	"context"
	"fmt"
	"time"

	"github.com/anasamu/go-micro-libs/zerotrust/types"
	"github.com/sirupsen/logrus"
)

// ZeroTrustManager manages multiple zero trust security providers
type ZeroTrustManager struct {
	providers map[string]ZeroTrustProvider
	logger    *logrus.Logger
	config    *ManagerConfig
}

// ManagerConfig holds zero trust manager configuration
type ManagerConfig struct {
	DefaultProvider string            `json:"default_provider"`
	RetryAttempts   int               `json:"retry_attempts"`
	RetryDelay      time.Duration     `json:"retry_delay"`
	Timeout         time.Duration     `json:"timeout"`
	Metadata        map[string]string `json:"metadata"`
}

// ZeroTrustProvider interface for zero trust security backends
type ZeroTrustProvider interface {
	// Provider information
	GetName() string
	GetSupportedFeatures() []types.ZeroTrustFeature
	GetConnectionInfo() *types.ConnectionInfo

	// Identity and authentication
	AuthenticateService(ctx context.Context, request *types.ServiceAuthRequest) (*types.ServiceAuthResponse, error)
	ValidateServiceIdentity(ctx context.Context, request *types.ServiceIdentityRequest) (*types.ServiceIdentityResponse, error)
	IssueServiceCredential(ctx context.Context, request *types.CredentialRequest) (*types.CredentialResponse, error)

	// mTLS operations
	GenerateMTLSCertificate(ctx context.Context, request *types.MTLSCertRequest) (*types.MTLSCertResponse, error)
	ValidateMTLSCertificate(ctx context.Context, request *types.MTLSCertValidationRequest) (*types.MTLSCertValidationResponse, error)
	RenewMTLSCertificate(ctx context.Context, request *types.MTLSCertRenewalRequest) (*types.MTLSCertRenewalResponse, error)

	// SPIFFE/SPIRE operations
	CreateSPIFFEIdentity(ctx context.Context, request *types.SPIFFEIdentityRequest) (*types.SPIFFEIdentityResponse, error)
	ValidateSPIFFEIdentity(ctx context.Context, request *types.SPIFFEValidationRequest) (*types.SPIFFEValidationResponse, error)
	AttestSPIFFEIdentity(ctx context.Context, request *types.SPIFFEAttestRequest) (*types.SPIFFEAttestResponse, error)

	// Service mesh operations
	ConfigureServiceMesh(ctx context.Context, request *types.ServiceMeshConfigRequest) (*types.ServiceMeshConfigResponse, error)
	ValidateServiceMeshPolicy(ctx context.Context, request *types.ServiceMeshPolicyRequest) (*types.ServiceMeshPolicyResponse, error)
	ApplyServiceMeshSecurity(ctx context.Context, request *types.ServiceMeshSecurityRequest) (*types.ServiceMeshSecurityResponse, error)

	// Policy enforcement
	EvaluatePolicy(ctx context.Context, request *types.PolicyEvaluationRequest) (*types.PolicyEvaluationResponse, error)
	EnforcePolicy(ctx context.Context, request *types.PolicyEnforcementRequest) (*types.PolicyEnforcementResponse, error)

	// Network segmentation
	CreateNetworkSegment(ctx context.Context, request *types.NetworkSegmentRequest) (*types.NetworkSegmentResponse, error)
	ValidateNetworkAccess(ctx context.Context, request *types.NetworkAccessRequest) (*types.NetworkAccessResponse, error)

	// Health and monitoring
	HealthCheck(ctx context.Context) error
	GetStats(ctx context.Context) (*types.ZeroTrustStats, error)

	// Configuration
	Configure(config map[string]interface{}) error
	IsConfigured() bool
	Close() error
}

// DefaultManagerConfig returns default zero trust manager configuration
func DefaultManagerConfig() *ManagerConfig {
	return &ManagerConfig{
		DefaultProvider: "spiffe",
		RetryAttempts:   3,
		RetryDelay:      5 * time.Second,
		Timeout:         30 * time.Second,
		Metadata:        make(map[string]string),
	}
}

// NewZeroTrustManager creates a new zero trust manager
func NewZeroTrustManager(config *ManagerConfig, logger *logrus.Logger) *ZeroTrustManager {
	if config == nil {
		config = DefaultManagerConfig()
	}

	if logger == nil {
		logger = logrus.New()
	}

	return &ZeroTrustManager{
		providers: make(map[string]ZeroTrustProvider),
		logger:    logger,
		config:    config,
	}
}

// RegisterProvider registers a zero trust provider
func (ztm *ZeroTrustManager) RegisterProvider(provider ZeroTrustProvider) error {
	if provider == nil {
		return fmt.Errorf("provider cannot be nil")
	}

	name := provider.GetName()
	if name == "" {
		return fmt.Errorf("provider name cannot be empty")
	}

	ztm.providers[name] = provider
	ztm.logger.WithField("provider", name).Info("Zero trust provider registered")

	return nil
}

// GetProvider returns a zero trust provider by name
func (ztm *ZeroTrustManager) GetProvider(name string) (ZeroTrustProvider, error) {
	provider, exists := ztm.providers[name]
	if !exists {
		return nil, fmt.Errorf("zero trust provider not found: %s", name)
	}
	return provider, nil
}

// GetDefaultProvider returns the default zero trust provider
func (ztm *ZeroTrustManager) GetDefaultProvider() (ZeroTrustProvider, error) {
	return ztm.GetProvider(ztm.config.DefaultProvider)
}

// AuthenticateService authenticates a service using the specified provider
func (ztm *ZeroTrustManager) AuthenticateService(ctx context.Context, providerName string, request *types.ServiceAuthRequest) (*types.ServiceAuthResponse, error) {
	provider, err := ztm.GetProvider(providerName)
	if err != nil {
		return nil, err
	}

	// Validate request
	if err := ztm.validateServiceAuthRequest(request); err != nil {
		return nil, fmt.Errorf("invalid service auth request: %w", err)
	}

	response, err := provider.AuthenticateService(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("failed to authenticate service: %w", err)
	}

	ztm.logger.WithFields(logrus.Fields{
		"provider":    providerName,
		"service_id":  response.ServiceID,
		"success":     response.Success,
		"identity_id": response.IdentityID,
	}).Debug("Service authentication completed")

	return response, nil
}

// ValidateServiceIdentity validates a service identity using the specified provider
func (ztm *ZeroTrustManager) ValidateServiceIdentity(ctx context.Context, providerName string, request *types.ServiceIdentityRequest) (*types.ServiceIdentityResponse, error) {
	provider, err := ztm.GetProvider(providerName)
	if err != nil {
		return nil, err
	}

	response, err := provider.ValidateServiceIdentity(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("failed to validate service identity: %w", err)
	}

	ztm.logger.WithFields(logrus.Fields{
		"provider":    providerName,
		"service_id":  request.ServiceID,
		"valid":       response.Valid,
		"identity_id": response.IdentityID,
	}).Debug("Service identity validation completed")

	return response, nil
}

// IssueServiceCredential issues a credential for a service using the specified provider
func (ztm *ZeroTrustManager) IssueServiceCredential(ctx context.Context, providerName string, request *types.CredentialRequest) (*types.CredentialResponse, error) {
	provider, err := ztm.GetProvider(providerName)
	if err != nil {
		return nil, err
	}

	response, err := provider.IssueServiceCredential(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("failed to issue service credential: %w", err)
	}

	ztm.logger.WithFields(logrus.Fields{
		"provider":        providerName,
		"service_id":      request.ServiceID,
		"credential_type": response.CredentialType,
		"expires_at":      response.ExpiresAt,
	}).Debug("Service credential issuance completed")

	return response, nil
}

// GenerateMTLSCertificate generates an mTLS certificate using the specified provider
func (ztm *ZeroTrustManager) GenerateMTLSCertificate(ctx context.Context, providerName string, request *types.MTLSCertRequest) (*types.MTLSCertResponse, error) {
	provider, err := ztm.GetProvider(providerName)
	if err != nil {
		return nil, err
	}

	response, err := provider.GenerateMTLSCertificate(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("failed to generate mTLS certificate: %w", err)
	}

	ztm.logger.WithFields(logrus.Fields{
		"provider":    providerName,
		"service_id":  request.ServiceID,
		"cert_serial": response.Certificate.SerialNumber,
		"expires_at":  response.Certificate.ExpiresAt,
	}).Debug("mTLS certificate generation completed")

	return response, nil
}

// ValidateMTLSCertificate validates an mTLS certificate using the specified provider
func (ztm *ZeroTrustManager) ValidateMTLSCertificate(ctx context.Context, providerName string, request *types.MTLSCertValidationRequest) (*types.MTLSCertValidationResponse, error) {
	provider, err := ztm.GetProvider(providerName)
	if err != nil {
		return nil, err
	}

	response, err := provider.ValidateMTLSCertificate(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("failed to validate mTLS certificate: %w", err)
	}

	ztm.logger.WithFields(logrus.Fields{
		"provider":    providerName,
		"cert_serial": request.Certificate.SerialNumber,
		"valid":       response.Valid,
		"trust_chain": response.TrustChainValid,
	}).Debug("mTLS certificate validation completed")

	return response, nil
}

// CreateSPIFFEIdentity creates a SPIFFE identity using the specified provider
func (ztm *ZeroTrustManager) CreateSPIFFEIdentity(ctx context.Context, providerName string, request *types.SPIFFEIdentityRequest) (*types.SPIFFEIdentityResponse, error) {
	provider, err := ztm.GetProvider(providerName)
	if err != nil {
		return nil, err
	}

	response, err := provider.CreateSPIFFEIdentity(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("failed to create SPIFFE identity: %w", err)
	}

	ztm.logger.WithFields(logrus.Fields{
		"provider":     providerName,
		"service_id":   request.ServiceID,
		"spiffe_id":    response.SPIFFEID,
		"trust_domain": response.TrustDomain,
	}).Debug("SPIFFE identity creation completed")

	return response, nil
}

// ValidateSPIFFEIdentity validates a SPIFFE identity using the specified provider
func (ztm *ZeroTrustManager) ValidateSPIFFEIdentity(ctx context.Context, providerName string, request *types.SPIFFEValidationRequest) (*types.SPIFFEValidationResponse, error) {
	provider, err := ztm.GetProvider(providerName)
	if err != nil {
		return nil, err
	}

	response, err := provider.ValidateSPIFFEIdentity(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("failed to validate SPIFFE identity: %w", err)
	}

	ztm.logger.WithFields(logrus.Fields{
		"provider":     providerName,
		"spiffe_id":    request.SPIFFEID,
		"valid":        response.Valid,
		"trust_domain": response.TrustDomain,
	}).Debug("SPIFFE identity validation completed")

	return response, nil
}

// ConfigureServiceMesh configures service mesh security using the specified provider
func (ztm *ZeroTrustManager) ConfigureServiceMesh(ctx context.Context, providerName string, request *types.ServiceMeshConfigRequest) (*types.ServiceMeshConfigResponse, error) {
	provider, err := ztm.GetProvider(providerName)
	if err != nil {
		return nil, err
	}

	response, err := provider.ConfigureServiceMesh(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("failed to configure service mesh: %w", err)
	}

	ztm.logger.WithFields(logrus.Fields{
		"provider":      providerName,
		"service_id":    request.ServiceID,
		"mesh_type":     request.MeshType,
		"configuration": response.Configuration,
	}).Debug("Service mesh configuration completed")

	return response, nil
}

// EvaluatePolicy evaluates a zero trust policy using the specified provider
func (ztm *ZeroTrustManager) EvaluatePolicy(ctx context.Context, providerName string, request *types.PolicyEvaluationRequest) (*types.PolicyEvaluationResponse, error) {
	provider, err := ztm.GetProvider(providerName)
	if err != nil {
		return nil, err
	}

	response, err := provider.EvaluatePolicy(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("failed to evaluate policy: %w", err)
	}

	ztm.logger.WithFields(logrus.Fields{
		"provider":  providerName,
		"policy_id": request.PolicyID,
		"allowed":   response.Allowed,
		"reason":    response.Reason,
	}).Debug("Policy evaluation completed")

	return response, nil
}

// validateServiceAuthRequest validates a service authentication request
func (ztm *ZeroTrustManager) validateServiceAuthRequest(request *types.ServiceAuthRequest) error {
	if request == nil {
		return fmt.Errorf("service auth request cannot be nil")
	}

	if request.ServiceID == "" {
		return fmt.Errorf("service ID is required")
	}

	if request.Credential == "" && request.Certificate == nil {
		return fmt.Errorf("credential or certificate is required")
	}

	return nil
}

// HealthCheck performs health check on all providers
func (ztm *ZeroTrustManager) HealthCheck(ctx context.Context) map[string]error {
	results := make(map[string]error)

	for name, provider := range ztm.providers {
		results[name] = provider.HealthCheck(ctx)
	}

	return results
}

// GetStats returns statistics for all providers
func (ztm *ZeroTrustManager) GetStats(ctx context.Context) map[string]interface{} {
	stats := make(map[string]interface{})

	for name, provider := range ztm.providers {
		if providerStats, err := provider.GetStats(ctx); err == nil {
			stats[name] = providerStats
		}
	}

	return stats
}

// Close closes all providers
func (ztm *ZeroTrustManager) Close() error {
	var errors []error

	for name, provider := range ztm.providers {
		if err := provider.Close(); err != nil {
			errors = append(errors, fmt.Errorf("failed to close provider %s: %w", name, err))
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("errors closing providers: %v", errors)
	}

	ztm.logger.Info("All zero trust providers closed")
	return nil
}
