package types

import (
	"crypto/x509"
	"time"
)

// ZeroTrustFeature represents a zero trust security feature
type ZeroTrustFeature string

const (
	// Identity and authentication features
	FeatureServiceIdentity       ZeroTrustFeature = "service_identity"
	FeatureMutualTLS             ZeroTrustFeature = "mutual_tls"
	FeatureSPIFFE                ZeroTrustFeature = "spiffe"
	FeatureSPIRE                 ZeroTrustFeature = "spire"
	FeatureServiceAuthentication ZeroTrustFeature = "service_authentication"
	FeatureCredentialManagement  ZeroTrustFeature = "credential_management"

	// Certificate management features
	FeatureCertificateGeneration ZeroTrustFeature = "certificate_generation"
	FeatureCertificateValidation ZeroTrustFeature = "certificate_validation"
	FeatureCertificateRenewal    ZeroTrustFeature = "certificate_renewal"
	FeatureCertificateRevocation ZeroTrustFeature = "certificate_revocation"
	FeatureCertificateRotation   ZeroTrustFeature = "certificate_rotation"

	// Service mesh features
	FeatureServiceMesh       ZeroTrustFeature = "service_mesh"
	FeatureIstio             ZeroTrustFeature = "istio"
	FeatureEnvoy             ZeroTrustFeature = "envoy"
	FeatureLinkerd           ZeroTrustFeature = "linkerd"
	FeatureConsulConnect     ZeroTrustFeature = "consul_connect"
	FeatureTrafficManagement ZeroTrustFeature = "traffic_management"
	FeatureServiceDiscovery  ZeroTrustFeature = "service_discovery"
	FeatureLoadBalancing     ZeroTrustFeature = "load_balancing"

	// Network security features
	FeatureNetworkSegmentation ZeroTrustFeature = "network_segmentation"
	FeatureMicroSegmentation   ZeroTrustFeature = "micro_segmentation"
	FeatureZeroTrustNetwork    ZeroTrustFeature = "zero_trust_network"
	FeatureNetworkPolicy       ZeroTrustFeature = "network_policy"
	FeatureFirewallManagement  ZeroTrustFeature = "firewall_management"

	// Policy enforcement features
	FeaturePolicyEngine       ZeroTrustFeature = "policy_engine"
	FeaturePolicyEvaluation   ZeroTrustFeature = "policy_evaluation"
	FeaturePolicyEnforcement  ZeroTrustFeature = "policy_enforcement"
	FeatureDynamicPolicies    ZeroTrustFeature = "dynamic_policies"
	FeatureContextualPolicies ZeroTrustFeature = "contextual_policies"

	// Monitoring and observability features
	FeatureSecurityMonitoring  ZeroTrustFeature = "security_monitoring"
	FeatureThreatDetection     ZeroTrustFeature = "threat_detection"
	FeatureAnomalyDetection    ZeroTrustFeature = "anomaly_detection"
	FeatureAuditLogging        ZeroTrustFeature = "audit_logging"
	FeatureSecurityAnalytics   ZeroTrustFeature = "security_analytics"
	FeatureComplianceReporting ZeroTrustFeature = "compliance_reporting"

	// Encryption and key management features
	FeatureEncryptionAtRest       ZeroTrustFeature = "encryption_at_rest"
	FeatureEncryptionInTransit    ZeroTrustFeature = "encryption_in_transit"
	FeatureKeyManagement          ZeroTrustFeature = "key_management"
	FeatureHardwareSecurityModule ZeroTrustFeature = "hsm"
	FeatureKeyRotation            ZeroTrustFeature = "key_rotation"

	// Access control features
	FeatureLeastPrivilegeAccess ZeroTrustFeature = "least_privilege_access"
	FeatureJustInTimeAccess     ZeroTrustFeature = "jit_access"
	FeatureConditionalAccess    ZeroTrustFeature = "conditional_access"
	FeatureRiskBasedAccess      ZeroTrustFeature = "risk_based_access"
	FeatureAdaptiveAccess       ZeroTrustFeature = "adaptive_access"
)

// ConnectionInfo represents zero trust provider connection information
type ConnectionInfo struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Version  string `json:"version"`
	Secure   bool   `json:"secure"`
}

// ServiceAuthRequest represents a service authentication request
type ServiceAuthRequest struct {
	ServiceID   string                 `json:"service_id"`
	Credential  string                 `json:"credential,omitempty"`
	Certificate *x509.Certificate      `json:"certificate,omitempty"`
	SPIFFEID    string                 `json:"spiffe_id,omitempty"`
	TrustDomain string                 `json:"trust_domain,omitempty"`
	Context     map[string]interface{} `json:"context,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	Timestamp   time.Time              `json:"timestamp"`
}

// ServiceAuthResponse represents a service authentication response
type ServiceAuthResponse struct {
	Success     bool                   `json:"success"`
	ServiceID   string                 `json:"service_id"`
	IdentityID  string                 `json:"identity_id,omitempty"`
	SPIFFEID    string                 `json:"spiffe_id,omitempty"`
	TrustDomain string                 `json:"trust_domain,omitempty"`
	Credential  *ServiceCredential     `json:"credential,omitempty"`
	Certificate *Certificate           `json:"certificate,omitempty"`
	ExpiresAt   time.Time              `json:"expires_at,omitempty"`
	Message     string                 `json:"message,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// ServiceIdentityRequest represents a service identity validation request
type ServiceIdentityRequest struct {
	ServiceID   string                 `json:"service_id"`
	IdentityID  string                 `json:"identity_id,omitempty"`
	SPIFFEID    string                 `json:"spiffe_id,omitempty"`
	TrustDomain string                 `json:"trust_domain,omitempty"`
	Certificate *x509.Certificate      `json:"certificate,omitempty"`
	Context     map[string]interface{} `json:"context,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// ServiceIdentityResponse represents a service identity validation response
type ServiceIdentityResponse struct {
	Valid       bool                   `json:"valid"`
	ServiceID   string                 `json:"service_id"`
	IdentityID  string                 `json:"identity_id,omitempty"`
	SPIFFEID    string                 `json:"spiffe_id,omitempty"`
	TrustDomain string                 `json:"trust_domain,omitempty"`
	Claims      map[string]interface{} `json:"claims,omitempty"`
	ExpiresAt   time.Time              `json:"expires_at,omitempty"`
	Message     string                 `json:"message,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// CredentialRequest represents a credential issuance request
type CredentialRequest struct {
	ServiceID       string                 `json:"service_id"`
	CredentialType  string                 `json:"credential_type"`
	ValidityPeriod  time.Duration          `json:"validity_period"`
	Subject         string                 `json:"subject,omitempty"`
	SubjectAltNames []string               `json:"subject_alt_names,omitempty"`
	KeyUsage        []x509.KeyUsage        `json:"key_usage,omitempty"`
	ExtKeyUsage     []x509.ExtKeyUsage     `json:"ext_key_usage,omitempty"`
	Context         map[string]interface{} `json:"context,omitempty"`
	Metadata        map[string]interface{} `json:"metadata,omitempty"`
}

// CredentialResponse represents a credential issuance response
type CredentialResponse struct {
	ServiceID      string                 `json:"service_id"`
	CredentialType string                 `json:"credential_type"`
	Credential     *ServiceCredential     `json:"credential,omitempty"`
	Certificate    *Certificate           `json:"certificate,omitempty"`
	PrivateKey     []byte                 `json:"private_key,omitempty"`
	ExpiresAt      time.Time              `json:"expires_at"`
	Message        string                 `json:"message,omitempty"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
}

// ServiceCredential represents a service credential
type ServiceCredential struct {
	ID           string                 `json:"id"`
	Type         string                 `json:"type"`
	ServiceID    string                 `json:"service_id"`
	Subject      string                 `json:"subject"`
	Issuer       string                 `json:"issuer"`
	IssuedAt     time.Time              `json:"issued_at"`
	ExpiresAt    time.Time              `json:"expires_at"`
	NotBefore    time.Time              `json:"not_before"`
	SerialNumber string                 `json:"serial_number"`
	Fingerprint  string                 `json:"fingerprint"`
	KeyID        string                 `json:"key_id,omitempty"`
	PublicKey    []byte                 `json:"public_key,omitempty"`
	Claims       map[string]interface{} `json:"claims,omitempty"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

// Certificate represents a certificate
type Certificate struct {
	SerialNumber   string                 `json:"serial_number"`
	Subject        string                 `json:"subject"`
	Issuer         string                 `json:"issuer"`
	NotBefore      time.Time              `json:"not_before"`
	NotAfter       time.Time              `json:"not_after"`
	ExpiresAt      time.Time              `json:"expires_at"`
	Fingerprint    string                 `json:"fingerprint"`
	PublicKey      []byte                 `json:"public_key,omitempty"`
	KeyUsage       []x509.KeyUsage        `json:"key_usage,omitempty"`
	ExtKeyUsage    []x509.ExtKeyUsage     `json:"ext_key_usage,omitempty"`
	DNSNames       []string               `json:"dns_names,omitempty"`
	IPAddresses    []string               `json:"ip_addresses,omitempty"`
	URIs           []string               `json:"uris,omitempty"`
	EmailAddresses []string               `json:"email_addresses,omitempty"`
	Extensions     map[string]interface{} `json:"extensions,omitempty"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
}

// MTLSCertRequest represents an mTLS certificate generation request
type MTLSCertRequest struct {
	ServiceID       string                 `json:"service_id"`
	Subject         string                 `json:"subject"`
	SubjectAltNames []string               `json:"subject_alt_names,omitempty"`
	ValidityPeriod  time.Duration          `json:"validity_period"`
	KeySize         int                    `json:"key_size,omitempty"`
	KeyType         string                 `json:"key_type,omitempty"`
	KeyUsage        []x509.KeyUsage        `json:"key_usage,omitempty"`
	ExtKeyUsage     []x509.ExtKeyUsage     `json:"ext_key_usage,omitempty"`
	Context         map[string]interface{} `json:"context,omitempty"`
	Metadata        map[string]interface{} `json:"metadata,omitempty"`
}

// MTLSCertResponse represents an mTLS certificate generation response
type MTLSCertResponse struct {
	ServiceID   string                 `json:"service_id"`
	Certificate *Certificate           `json:"certificate"`
	PrivateKey  []byte                 `json:"private_key"`
	CAChain     []*Certificate         `json:"ca_chain,omitempty"`
	ExpiresAt   time.Time              `json:"expires_at"`
	Message     string                 `json:"message,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// MTLSCertValidationRequest represents an mTLS certificate validation request
type MTLSCertValidationRequest struct {
	Certificate *x509.Certificate      `json:"certificate"`
	CAChain     []*x509.Certificate    `json:"ca_chain,omitempty"`
	ServiceID   string                 `json:"service_id,omitempty"`
	Context     map[string]interface{} `json:"context,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// MTLSCertValidationResponse represents an mTLS certificate validation response
type MTLSCertValidationResponse struct {
	Valid           bool                   `json:"valid"`
	TrustChainValid bool                   `json:"trust_chain_valid"`
	ServiceID       string                 `json:"service_id,omitempty"`
	ExpiresAt       time.Time              `json:"expires_at,omitempty"`
	Issuer          string                 `json:"issuer,omitempty"`
	Subject         string                 `json:"subject,omitempty"`
	SerialNumber    string                 `json:"serial_number,omitempty"`
	Message         string                 `json:"message,omitempty"`
	Metadata        map[string]interface{} `json:"metadata,omitempty"`
}

// MTLSCertRenewalRequest represents an mTLS certificate renewal request
type MTLSCertRenewalRequest struct {
	ServiceID      string                 `json:"service_id"`
	CertificateID  string                 `json:"certificate_id"`
	ValidityPeriod time.Duration          `json:"validity_period"`
	Context        map[string]interface{} `json:"context,omitempty"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
}

// MTLSCertRenewalResponse represents an mTLS certificate renewal response
type MTLSCertRenewalResponse struct {
	ServiceID   string                 `json:"service_id"`
	Certificate *Certificate           `json:"certificate"`
	PrivateKey  []byte                 `json:"private_key"`
	CAChain     []*Certificate         `json:"ca_chain,omitempty"`
	ExpiresAt   time.Time              `json:"expires_at"`
	Message     string                 `json:"message,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// SPIFFEIdentityRequest represents a SPIFFE identity creation request
type SPIFFEIdentityRequest struct {
	ServiceID   string                 `json:"service_id"`
	TrustDomain string                 `json:"trust_domain"`
	SPIFFEPath  string                 `json:"spiffe_path,omitempty"`
	ParentID    string                 `json:"parent_id,omitempty"`
	Selector    map[string]interface{} `json:"selector,omitempty"`
	TTL         time.Duration          `json:"ttl,omitempty"`
	DNSNames    []string               `json:"dns_names,omitempty"`
	Context     map[string]interface{} `json:"context,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// SPIFFEIdentityResponse represents a SPIFFE identity creation response
type SPIFFEIdentityResponse struct {
	ServiceID   string                 `json:"service_id"`
	SPIFFEID    string                 `json:"spiffe_id"`
	TrustDomain string                 `json:"trust_domain"`
	Certificate *Certificate           `json:"certificate"`
	PrivateKey  []byte                 `json:"private_key"`
	Bundle      []*Certificate         `json:"bundle,omitempty"`
	ExpiresAt   time.Time              `json:"expires_at"`
	Message     string                 `json:"message,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// SPIFFEValidationRequest represents a SPIFFE identity validation request
type SPIFFEValidationRequest struct {
	SPIFFEID    string                 `json:"spiffe_id"`
	TrustDomain string                 `json:"trust_domain"`
	Certificate *x509.Certificate      `json:"certificate,omitempty"`
	Bundle      []*x509.Certificate    `json:"bundle,omitempty"`
	Context     map[string]interface{} `json:"context,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// SPIFFEValidationResponse represents a SPIFFE identity validation response
type SPIFFEValidationResponse struct {
	Valid       bool                   `json:"valid"`
	SPIFFEID    string                 `json:"spiffe_id"`
	TrustDomain string                 `json:"trust_domain"`
	ServiceID   string                 `json:"service_id,omitempty"`
	Claims      map[string]interface{} `json:"claims,omitempty"`
	ExpiresAt   time.Time              `json:"expires_at,omitempty"`
	Message     string                 `json:"message,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// SPIFFEAttestRequest represents a SPIFFE attestation request
type SPIFFEAttestRequest struct {
	ServiceID       string                 `json:"service_id"`
	TrustDomain     string                 `json:"trust_domain"`
	AttestationData map[string]interface{} `json:"attestation_data"`
	Context         map[string]interface{} `json:"context,omitempty"`
	Metadata        map[string]interface{} `json:"metadata,omitempty"`
}

// SPIFFEAttestResponse represents a SPIFFE attestation response
type SPIFFEAttestResponse struct {
	Success     bool                   `json:"success"`
	ServiceID   string                 `json:"service_id"`
	SPIFFEID    string                 `json:"spiffe_id"`
	TrustDomain string                 `json:"trust_domain"`
	Certificate *Certificate           `json:"certificate,omitempty"`
	PrivateKey  []byte                 `json:"private_key,omitempty"`
	ExpiresAt   time.Time              `json:"expires_at,omitempty"`
	Message     string                 `json:"message,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// ServiceMeshConfigRequest represents a service mesh configuration request
type ServiceMeshConfigRequest struct {
	ServiceID     string                 `json:"service_id"`
	MeshType      string                 `json:"mesh_type"`
	Namespace     string                 `json:"namespace,omitempty"`
	Configuration map[string]interface{} `json:"configuration"`
	Policies      []ServiceMeshPolicy    `json:"policies,omitempty"`
	Context       map[string]interface{} `json:"context,omitempty"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
}

// ServiceMeshConfigResponse represents a service mesh configuration response
type ServiceMeshConfigResponse struct {
	ServiceID       string                 `json:"service_id"`
	MeshType        string                 `json:"mesh_type"`
	Configuration   map[string]interface{} `json:"configuration"`
	AppliedPolicies []ServiceMeshPolicy    `json:"applied_policies,omitempty"`
	Status          string                 `json:"status"`
	Message         string                 `json:"message,omitempty"`
	Metadata        map[string]interface{} `json:"metadata,omitempty"`
}

// ServiceMeshPolicy represents a service mesh policy
type ServiceMeshPolicy struct {
	ID         string                 `json:"id"`
	Name       string                 `json:"name"`
	Type       string                 `json:"type"`
	Enabled    bool                   `json:"enabled"`
	Priority   int                    `json:"priority"`
	Rules      []PolicyRule           `json:"rules,omitempty"`
	Conditions []PolicyCondition      `json:"conditions,omitempty"`
	Actions    []PolicyAction         `json:"actions,omitempty"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
}

// PolicyRule represents a policy rule
type PolicyRule struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Enabled     bool                   `json:"enabled"`
	Priority    int                    `json:"priority"`
	Conditions  []PolicyCondition      `json:"conditions"`
	Actions     []PolicyAction         `json:"actions"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// PolicyCondition represents a policy condition
type PolicyCondition struct {
	ID       string                 `json:"id"`
	Type     string                 `json:"type"`
	Field    string                 `json:"field"`
	Operator string                 `json:"operator"`
	Value    interface{}            `json:"value"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// PolicyAction represents a policy action
type PolicyAction struct {
	ID         string                 `json:"id"`
	Type       string                 `json:"type"`
	Parameters map[string]interface{} `json:"parameters"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
}

// ServiceMeshPolicyRequest represents a service mesh policy validation request
type ServiceMeshPolicyRequest struct {
	ServiceID string                 `json:"service_id"`
	PolicyID  string                 `json:"policy_id"`
	Policy    *ServiceMeshPolicy     `json:"policy"`
	Context   map[string]interface{} `json:"context,omitempty"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// ServiceMeshPolicyResponse represents a service mesh policy validation response
type ServiceMeshPolicyResponse struct {
	Valid        bool                   `json:"valid"`
	ServiceID    string                 `json:"service_id"`
	PolicyID     string                 `json:"policy_id"`
	AppliedRules []PolicyRule           `json:"applied_rules,omitempty"`
	Violations   []PolicyViolation      `json:"violations,omitempty"`
	Message      string                 `json:"message,omitempty"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

// PolicyViolation represents a policy violation
type PolicyViolation struct {
	ID          string                 `json:"id"`
	RuleID      string                 `json:"rule_id"`
	Type        string                 `json:"type"`
	Severity    string                 `json:"severity"`
	Description string                 `json:"description"`
	Context     map[string]interface{} `json:"context,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// ServiceMeshSecurityRequest represents a service mesh security application request
type ServiceMeshSecurityRequest struct {
	ServiceID      string                 `json:"service_id"`
	SecurityConfig map[string]interface{} `json:"security_config"`
	Policies       []ServiceMeshPolicy    `json:"policies,omitempty"`
	Context        map[string]interface{} `json:"context,omitempty"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
}

// ServiceMeshSecurityResponse represents a service mesh security application response
type ServiceMeshSecurityResponse struct {
	ServiceID       string                 `json:"service_id"`
	AppliedSecurity map[string]interface{} `json:"applied_security"`
	AppliedPolicies []ServiceMeshPolicy    `json:"applied_policies,omitempty"`
	Status          string                 `json:"status"`
	Message         string                 `json:"message,omitempty"`
	Metadata        map[string]interface{} `json:"metadata,omitempty"`
}

// PolicyEvaluationRequest represents a policy evaluation request
type PolicyEvaluationRequest struct {
	PolicyID    string                 `json:"policy_id"`
	Subject     string                 `json:"subject"`
	Resource    string                 `json:"resource"`
	Action      string                 `json:"action"`
	Context     map[string]interface{} `json:"context,omitempty"`
	Environment map[string]interface{} `json:"environment,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// PolicyEvaluationResponse represents a policy evaluation response
type PolicyEvaluationResponse struct {
	Allowed      bool                   `json:"allowed"`
	PolicyID     string                 `json:"policy_id"`
	Subject      string                 `json:"subject"`
	Resource     string                 `json:"resource"`
	Action       string                 `json:"action"`
	Reason       string                 `json:"reason,omitempty"`
	AppliedRules []PolicyRule           `json:"applied_rules,omitempty"`
	Obligations  []PolicyObligation     `json:"obligations,omitempty"`
	Message      string                 `json:"message,omitempty"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

// PolicyObligation represents a policy obligation
type PolicyObligation struct {
	ID         string                 `json:"id"`
	Type       string                 `json:"type"`
	Parameters map[string]interface{} `json:"parameters"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
}

// PolicyEnforcementRequest represents a policy enforcement request
type PolicyEnforcementRequest struct {
	PolicyID    string                 `json:"policy_id"`
	Subject     string                 `json:"subject"`
	Resource    string                 `json:"resource"`
	Action      string                 `json:"action"`
	Context     map[string]interface{} `json:"context,omitempty"`
	Environment map[string]interface{} `json:"environment,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// PolicyEnforcementResponse represents a policy enforcement response
type PolicyEnforcementResponse struct {
	Enforced       bool                   `json:"enforced"`
	PolicyID       string                 `json:"policy_id"`
	Subject        string                 `json:"subject"`
	Resource       string                 `json:"resource"`
	Action         string                 `json:"action"`
	Result         string                 `json:"result,omitempty"`
	AppliedActions []PolicyAction         `json:"applied_actions,omitempty"`
	Message        string                 `json:"message,omitempty"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
}

// NetworkSegmentRequest represents a network segment creation request
type NetworkSegmentRequest struct {
	SegmentID   string                 `json:"segment_id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	NetworkCIDR string                 `json:"network_cidr"`
	Policies    []ServiceMeshPolicy    `json:"policies,omitempty"`
	Context     map[string]interface{} `json:"context,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// NetworkSegmentResponse represents a network segment creation response
type NetworkSegmentResponse struct {
	SegmentID       string                 `json:"segment_id"`
	Name            string                 `json:"name"`
	Description     string                 `json:"description"`
	NetworkCIDR     string                 `json:"network_cidr"`
	AppliedPolicies []ServiceMeshPolicy    `json:"applied_policies,omitempty"`
	Status          string                 `json:"status"`
	Message         string                 `json:"message,omitempty"`
	Metadata        map[string]interface{} `json:"metadata,omitempty"`
}

// NetworkAccessRequest represents a network access validation request
type NetworkAccessRequest struct {
	SourceSegment string                 `json:"source_segment"`
	TargetSegment string                 `json:"target_segment"`
	ServiceID     string                 `json:"service_id"`
	Port          int                    `json:"port,omitempty"`
	Protocol      string                 `json:"protocol,omitempty"`
	Context       map[string]interface{} `json:"context,omitempty"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
}

// NetworkAccessResponse represents a network access validation response
type NetworkAccessResponse struct {
	Allowed         bool                   `json:"allowed"`
	SourceSegment   string                 `json:"source_segment"`
	TargetSegment   string                 `json:"target_segment"`
	ServiceID       string                 `json:"service_id"`
	Port            int                    `json:"port,omitempty"`
	Protocol        string                 `json:"protocol,omitempty"`
	Reason          string                 `json:"reason,omitempty"`
	AppliedPolicies []ServiceMeshPolicy    `json:"applied_policies,omitempty"`
	Message         string                 `json:"message,omitempty"`
	Metadata        map[string]interface{} `json:"metadata,omitempty"`
}

// ZeroTrustStats represents zero trust statistics
type ZeroTrustStats struct {
	TotalAuthentications      int64                  `json:"total_authentications"`
	SuccessfulAuthentications int64                  `json:"successful_authentications"`
	FailedAuthentications     int64                  `json:"failed_authentications"`
	ActiveIdentities          int64                  `json:"active_identities"`
	ActiveCertificates        int64                  `json:"active_certificates"`
	PolicyEvaluations         int64                  `json:"policy_evaluations"`
	PolicyViolations          int64                  `json:"policy_violations"`
	NetworkAccessRequests     int64                  `json:"network_access_requests"`
	NetworkAccessDenied       int64                  `json:"network_access_denied"`
	ProviderData              map[string]interface{} `json:"provider_data"`
}
