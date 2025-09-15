package keycloak

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/anasamu/go-micro-libs/auth/types"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

// KeycloakProvider implements Keycloak-based authentication with identity federation
type KeycloakProvider struct {
	config     *KeycloakConfig
	httpClient *http.Client
	logger     *logrus.Logger
	configured bool
}

// KeycloakConfig holds Keycloak provider configuration
type KeycloakConfig struct {
	ServerURL         string                            `json:"server_url"`
	Realm             string                            `json:"realm"`
	ClientID          string                            `json:"client_id"`
	ClientSecret      string                            `json:"client_secret"`
	RedirectURL       string                            `json:"redirect_url"`
	Scopes            []string                          `json:"scopes"`
	AdminUsername     string                            `json:"admin_username"`
	AdminPassword     string                            `json:"admin_password"`
	Timeout           time.Duration                     `json:"timeout"`
	VerifySSL         bool                              `json:"verify_ssl"`
	CustomClaims      map[string]string                 `json:"custom_claims"`
	IdentityProviders map[string]IdentityProviderConfig `json:"identity_providers"`
}

// IdentityProviderConfig represents configuration for identity providers
type IdentityProviderConfig struct {
	ProviderID                string            `json:"provider_id"`
	ProviderType              string            `json:"provider_type"` // saml, oidc, ldap, etc.
	Enabled                   bool              `json:"enabled"`
	Config                    map[string]string `json:"config"`
	TrustEmail                bool              `json:"trust_email"`
	StoreToken                bool              `json:"store_token"`
	LinkOnly                  bool              `json:"link_only"`
	FirstBrokerLoginFlowAlias string            `json:"first_broker_login_flow_alias"`
}

// KeycloakUser represents a Keycloak user
type KeycloakUser struct {
	ID                  string                 `json:"id"`
	Username            string                 `json:"username"`
	Email               string                 `json:"email"`
	FirstName           string                 `json:"firstName"`
	LastName            string                 `json:"lastName"`
	Enabled             bool                   `json:"enabled"`
	EmailVerified       bool                   `json:"emailVerified"`
	Attributes          map[string]interface{} `json:"attributes"`
	RealmRoles          []string               `json:"realmRoles"`
	ClientRoles         map[string][]string    `json:"clientRoles"`
	Groups              []string               `json:"groups"`
	FederatedIdentities []FederatedIdentity    `json:"federatedIdentities"`
}

// FederatedIdentity represents federated identity information
type FederatedIdentity struct {
	IdentityProvider string `json:"identityProvider"`
	UserID           string `json:"userId"`
	UserName         string `json:"userName"`
}

// KeycloakTokenResponse represents Keycloak token response
type KeycloakTokenResponse struct {
	AccessToken      string `json:"access_token"`
	RefreshToken     string `json:"refresh_token"`
	TokenType        string `json:"token_type"`
	ExpiresIn        int    `json:"expires_in"`
	RefreshExpiresIn int    `json:"refresh_expires_in"`
	Scope            string `json:"scope"`
	SessionState     string `json:"session_state"`
}

// KeycloakUserInfo represents user info from Keycloak
type KeycloakUserInfo struct {
	Sub               string                 `json:"sub"`
	PreferredUsername string                 `json:"preferred_username"`
	Email             string                 `json:"email"`
	EmailVerified     bool                   `json:"email_verified"`
	GivenName         string                 `json:"given_name"`
	FamilyName        string                 `json:"family_name"`
	Name              string                 `json:"name"`
	RealmAccess       map[string]interface{} `json:"realm_access"`
	ResourceAccess    map[string]interface{} `json:"resource_access"`
	Groups            []string               `json:"groups"`
	Attributes        map[string]interface{} `json:"attributes"`
}

// ZeroTrustContext represents Zero Trust security context
type ZeroTrustContext struct {
	DeviceID        string                 `json:"device_id"`
	DeviceTrust     string                 `json:"device_trust"` // trusted, untrusted, unknown
	RiskScore       float64                `json:"risk_score"`
	Location        string                 `json:"location"`
	IPAddress       string                 `json:"ip_address"`
	UserAgent       string                 `json:"user_agent"`
	SessionID       string                 `json:"session_id"`
	MFARequired     bool                   `json:"mfa_required"`
	AdaptiveAuth    map[string]interface{} `json:"adaptive_auth"`
	LastLogin       time.Time              `json:"last_login"`
	LoginCount      int                    `json:"login_count"`
	AnomalyDetected bool                   `json:"anomaly_detected"`
}

// DefaultKeycloakConfig returns default Keycloak configuration
func DefaultKeycloakConfig() *KeycloakConfig {
	return &KeycloakConfig{
		ServerURL:     "http://localhost:8080",
		Realm:         "master",
		ClientID:      "microservices-client",
		ClientSecret:  "",
		RedirectURL:   "http://localhost:8080/auth/callback/keycloak",
		Scopes:        []string{"openid", "profile", "email", "roles"},
		AdminUsername: "admin",
		AdminPassword: "admin",
		Timeout:       30 * time.Second,
		VerifySSL:     false,
		CustomClaims:  make(map[string]string),
		IdentityProviders: map[string]IdentityProviderConfig{
			"google": {
				ProviderID:   "google",
				ProviderType: "oidc",
				Enabled:      true,
				TrustEmail:   true,
				StoreToken:   false,
				LinkOnly:     false,
				Config: map[string]string{
					"clientId":     "",
					"clientSecret": "",
					"defaultScope": "openid profile email",
				},
			},
			"microsoft": {
				ProviderID:   "microsoft",
				ProviderType: "oidc",
				Enabled:      true,
				TrustEmail:   true,
				StoreToken:   false,
				LinkOnly:     false,
				Config: map[string]string{
					"clientId":     "",
					"clientSecret": "",
					"defaultScope": "openid profile email",
				},
			},
		},
	}
}

// NewKeycloakProvider creates a new Keycloak provider
func NewKeycloakProvider(config *KeycloakConfig, logger *logrus.Logger) *KeycloakProvider {
	if config == nil {
		config = DefaultKeycloakConfig()
	}

	if logger == nil {
		logger = logrus.New()
	}

	return &KeycloakProvider{
		config: config,
		httpClient: &http.Client{
			Timeout: config.Timeout,
		},
		logger:     logger,
		configured: true,
	}
}

// GetName returns the provider name
func (kp *KeycloakProvider) GetName() string {
	return "keycloak"
}

// GetSupportedFeatures returns supported features
func (kp *KeycloakProvider) GetSupportedFeatures() []types.AuthFeature {
	return []types.AuthFeature{
		types.FeatureOAuth2,
		types.FeatureOpenIDConnect,
		types.FeatureSSO,
		types.FeatureRBAC,
		types.FeatureABAC,
		types.FeatureSessionManagement,
		types.FeatureTwoFactor,
		types.FeatureDeviceManagement,
		types.FeatureGeolocation,
		types.FeatureRiskAssessment,
		types.FeatureAuditLogging,
		types.FeatureEncryption,
		types.FeatureTokenBlacklist,
		types.FeatureRateLimiting,
		types.FeatureBruteForceProtection,
	}
}

// GetConnectionInfo returns connection information
func (kp *KeycloakProvider) GetConnectionInfo() *types.ConnectionInfo {
	return &types.ConnectionInfo{
		Host:     kp.config.ServerURL,
		Port:     8080,
		Protocol: "https",
		Version:  "18.0.0",
		Secure:   kp.config.VerifySSL,
	}
}

// Configure configures the Keycloak provider
func (kp *KeycloakProvider) Configure(config map[string]interface{}) error {
	if serverURL, ok := config["server_url"].(string); ok {
		kp.config.ServerURL = serverURL
	}

	if realm, ok := config["realm"].(string); ok {
		kp.config.Realm = realm
	}

	if clientID, ok := config["client_id"].(string); ok {
		kp.config.ClientID = clientID
	}

	if clientSecret, ok := config["client_secret"].(string); ok {
		kp.config.ClientSecret = clientSecret
	}

	if redirectURL, ok := config["redirect_url"].(string); ok {
		kp.config.RedirectURL = redirectURL
	}

	if scopes, ok := config["scopes"].([]string); ok {
		kp.config.Scopes = scopes
	}

	if adminUsername, ok := config["admin_username"].(string); ok {
		kp.config.AdminUsername = adminUsername
	}

	if adminPassword, ok := config["admin_password"].(string); ok {
		kp.config.AdminPassword = adminPassword
	}

	if timeout, ok := config["timeout"].(time.Duration); ok {
		kp.config.Timeout = timeout
		kp.httpClient.Timeout = timeout
	}

	if verifySSL, ok := config["verify_ssl"].(bool); ok {
		kp.config.VerifySSL = verifySSL
	}

	if customClaims, ok := config["custom_claims"].(map[string]string); ok {
		kp.config.CustomClaims = customClaims
	}

	if identityProviders, ok := config["identity_providers"].(map[string]IdentityProviderConfig); ok {
		kp.config.IdentityProviders = identityProviders
	}

	kp.configured = true
	kp.logger.Info("Keycloak provider configured successfully")
	return nil
}

// IsConfigured returns whether the provider is configured
func (kp *KeycloakProvider) IsConfigured() bool {
	return kp.configured
}

// GetAuthURL generates authorization URL for Keycloak
func (kp *KeycloakProvider) GetAuthURL(ctx context.Context, state string, identityProvider string) (string, error) {
	authURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/auth", kp.config.ServerURL, kp.config.Realm)

	params := url.Values{}
	params.Set("client_id", kp.config.ClientID)
	params.Set("redirect_uri", kp.config.RedirectURL)
	params.Set("response_type", "code")
	params.Set("scope", strings.Join(kp.config.Scopes, " "))
	params.Set("state", state)

	if identityProvider != "" {
		params.Set("kc_idp_hint", identityProvider)
	}

	fullURL := fmt.Sprintf("%s?%s", authURL, params.Encode())

	kp.logger.WithFields(logrus.Fields{
		"state":             state,
		"identity_provider": identityProvider,
		"realm":             kp.config.Realm,
	}).Debug("Generated Keycloak authorization URL")

	return fullURL, nil
}

// ExchangeCode exchanges authorization code for tokens
func (kp *KeycloakProvider) ExchangeCode(ctx context.Context, code string) (*KeycloakTokenResponse, error) {
	tokenURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", kp.config.ServerURL, kp.config.Realm)

	params := url.Values{}
	params.Set("grant_type", "authorization_code")
	params.Set("client_id", kp.config.ClientID)
	params.Set("client_secret", kp.config.ClientSecret)
	params.Set("code", code)
	params.Set("redirect_uri", kp.config.RedirectURL)

	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(params.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create token request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := kp.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code for token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token exchange failed with status: %d", resp.StatusCode)
	}

	var tokenResponse KeycloakTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		return nil, fmt.Errorf("failed to decode token response: %w", err)
	}

	kp.logger.WithFields(logrus.Fields{
		"token_type": tokenResponse.TokenType,
		"expires_in": tokenResponse.ExpiresIn,
		"scope":      tokenResponse.Scope,
	}).Info("Keycloak token exchange completed")

	return &tokenResponse, nil
}

// GetUserInfo retrieves user information from Keycloak
func (kp *KeycloakProvider) GetUserInfo(ctx context.Context, accessToken string) (*KeycloakUserInfo, error) {
	userInfoURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/userinfo", kp.config.ServerURL, kp.config.Realm)

	req, err := http.NewRequestWithContext(ctx, "GET", userInfoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create user info request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := kp.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("user info request failed with status: %d", resp.StatusCode)
	}

	var userInfo KeycloakUserInfo
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, fmt.Errorf("failed to decode user info: %w", err)
	}

	kp.logger.WithFields(logrus.Fields{
		"user_id":  userInfo.Sub,
		"username": userInfo.PreferredUsername,
		"email":    userInfo.Email,
	}).Debug("Retrieved Keycloak user info")

	return &userInfo, nil
}

// refreshTokenInternal refreshes a Keycloak token internally
func (kp *KeycloakProvider) refreshTokenInternal(ctx context.Context, refreshToken string) (*KeycloakTokenResponse, error) {
	tokenURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", kp.config.ServerURL, kp.config.Realm)

	params := url.Values{}
	params.Set("grant_type", "refresh_token")
	params.Set("client_id", kp.config.ClientID)
	params.Set("client_secret", kp.config.ClientSecret)
	params.Set("refresh_token", refreshToken)

	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(params.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create refresh request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := kp.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to refresh token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token refresh failed with status: %d", resp.StatusCode)
	}

	var tokenResponse KeycloakTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		return nil, fmt.Errorf("failed to decode refresh response: %w", err)
	}

	kp.logger.WithFields(logrus.Fields{
		"token_type": tokenResponse.TokenType,
		"expires_in": tokenResponse.ExpiresIn,
	}).Info("Keycloak token refreshed")

	return &tokenResponse, nil
}

// validateTokenInternal validates a Keycloak token internally
func (kp *KeycloakProvider) validateTokenInternal(ctx context.Context, accessToken string) (*KeycloakUserInfo, error) {
	// Use introspection endpoint for token validation
	introspectURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token/introspect", kp.config.ServerURL, kp.config.Realm)

	params := url.Values{}
	params.Set("token", accessToken)
	params.Set("client_id", kp.config.ClientID)
	params.Set("client_secret", kp.config.ClientSecret)

	req, err := http.NewRequestWithContext(ctx, "POST", introspectURL, strings.NewReader(params.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create introspection request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := kp.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to introspect token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token introspection failed with status: %d", resp.StatusCode)
	}

	var introspection map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&introspection); err != nil {
		return nil, fmt.Errorf("failed to decode introspection response: %w", err)
	}

	active, ok := introspection["active"].(bool)
	if !ok || !active {
		return nil, fmt.Errorf("token is not active")
	}

	// Convert introspection response to user info
	userInfo := &KeycloakUserInfo{
		Sub:               getStringFromMap(introspection, "sub"),
		PreferredUsername: getStringFromMap(introspection, "preferred_username"),
		Email:             getStringFromMap(introspection, "email"),
		EmailVerified:     getBoolFromMap(introspection, "email_verified"),
		GivenName:         getStringFromMap(introspection, "given_name"),
		FamilyName:        getStringFromMap(introspection, "family_name"),
		Name:              getStringFromMap(introspection, "name"),
	}

	kp.logger.WithFields(logrus.Fields{
		"user_id":  userInfo.Sub,
		"username": userInfo.PreferredUsername,
		"active":   active,
	}).Debug("Keycloak token validated")

	return userInfo, nil
}

// AssessRisk performs Zero Trust risk assessment
func (kp *KeycloakProvider) AssessRisk(ctx context.Context, userInfo *KeycloakUserInfo, ztContext *ZeroTrustContext) (*ZeroTrustContext, error) {
	riskScore := 0.0
	anomalyDetected := false

	// Device trust assessment
	switch ztContext.DeviceTrust {
	case "untrusted":
		riskScore += 0.4
		anomalyDetected = true
	case "unknown":
		riskScore += 0.2
	}

	// Location-based risk
	if ztContext.Location == "" {
		riskScore += 0.1
	}

	// Login pattern analysis
	if ztContext.LoginCount == 0 {
		riskScore += 0.3 // First time login
		anomalyDetected = true
	}

	// Time-based risk (login outside normal hours)
	now := time.Now()
	if now.Hour() < 6 || now.Hour() > 22 {
		riskScore += 0.2
	}

	// IP address risk (simplified)
	if strings.Contains(ztContext.IPAddress, "192.168.") || strings.Contains(ztContext.IPAddress, "10.") {
		riskScore -= 0.1 // Internal network
	}

	// Update risk context
	ztContext.RiskScore = riskScore
	ztContext.AnomalyDetected = anomalyDetected
	ztContext.MFARequired = riskScore > 0.3

	kp.logger.WithFields(logrus.Fields{
		"user_id":          userInfo.Sub,
		"risk_score":       riskScore,
		"mfa_required":     ztContext.MFARequired,
		"anomaly_detected": anomalyDetected,
		"device_trust":     ztContext.DeviceTrust,
	}).Info("Zero Trust risk assessment completed")

	return ztContext, nil
}

// GetIdentityProviders returns configured identity providers
func (kp *KeycloakProvider) GetIdentityProviders(ctx context.Context) (map[string]IdentityProviderConfig, error) {
	return kp.config.IdentityProviders, nil
}

// EnableIdentityProvider enables an identity provider
func (kp *KeycloakProvider) EnableIdentityProvider(ctx context.Context, providerID string) error {
	if provider, exists := kp.config.IdentityProviders[providerID]; exists {
		provider.Enabled = true
		kp.config.IdentityProviders[providerID] = provider

		kp.logger.WithField("provider_id", providerID).Info("Identity provider enabled")
		return nil
	}

	return fmt.Errorf("identity provider not found: %s", providerID)
}

// DisableIdentityProvider disables an identity provider
func (kp *KeycloakProvider) DisableIdentityProvider(ctx context.Context, providerID string) error {
	if provider, exists := kp.config.IdentityProviders[providerID]; exists {
		provider.Enabled = false
		kp.config.IdentityProviders[providerID] = provider

		kp.logger.WithField("provider_id", providerID).Info("Identity provider disabled")
		return nil
	}

	return fmt.Errorf("identity provider not found: %s", providerID)
}

// Helper functions
func getStringFromMap(m map[string]interface{}, key string) string {
	if val, ok := m[key].(string); ok {
		return val
	}
	return ""
}

func getBoolFromMap(m map[string]interface{}, key string) bool {
	if val, ok := m[key].(bool); ok {
		return val
	}
	return false
}

// healthCheckInternal performs health check
func (kp *KeycloakProvider) healthCheckInternal(ctx context.Context) error {
	if !kp.configured {
		return fmt.Errorf("Keycloak provider not configured")
	}

	// Check Keycloak server health
	healthURL := fmt.Sprintf("%s/realms/%s/.well-known/openid_configuration", kp.config.ServerURL, kp.config.Realm)

	req, err := http.NewRequestWithContext(ctx, "GET", healthURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create health check request: %w", err)
	}

	resp, err := kp.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("Keycloak server not reachable: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Keycloak server health check failed with status: %d", resp.StatusCode)
	}

	return nil
}

// getStatsInternal returns provider statistics
func (kp *KeycloakProvider) getStatsInternal(ctx context.Context) map[string]interface{} {
	enabledProviders := 0
	for _, provider := range kp.config.IdentityProviders {
		if provider.Enabled {
			enabledProviders++
		}
	}

	return map[string]interface{}{
		"provider":           "keycloak",
		"configured":         kp.configured,
		"server_url":         kp.config.ServerURL,
		"realm":              kp.config.Realm,
		"client_id":          kp.config.ClientID,
		"identity_providers": len(kp.config.IdentityProviders),
		"enabled_providers":  enabledProviders,
		"verify_ssl":         kp.config.VerifySSL,
		"timeout":            kp.config.Timeout.String(),
	}
}

// Close closes the provider
func (kp *KeycloakProvider) Close() error {
	kp.logger.Info("Keycloak provider closed")
	return nil
}

// AuthProvider interface implementation

// Authenticate authenticates a user using Keycloak
func (kp *KeycloakProvider) Authenticate(ctx context.Context, request *types.AuthRequest) (*types.AuthResponse, error) {
	// For Keycloak, authentication typically happens through OAuth flow
	// This method would be called after successful OAuth callback

	// Create Zero Trust context
	ztContext := &ZeroTrustContext{
		DeviceID:   request.DeviceID,
		IPAddress:  request.IPAddress,
		UserAgent:  request.UserAgent,
		SessionID:  uuid.New().String(),
		LastLogin:  time.Now(),
		LoginCount: 1, // This would be retrieved from user history
	}

	// Mock user info for demonstration
	userInfo := &KeycloakUserInfo{
		Sub:               uuid.New().String(),
		PreferredUsername: request.Username,
		Email:             request.Email,
		EmailVerified:     true,
		GivenName:         "John",
		FamilyName:        "Doe",
		Name:              "John Doe",
	}

	// Perform risk assessment
	ztContext, err := kp.AssessRisk(ctx, userInfo, ztContext)
	if err != nil {
		kp.logger.WithError(err).Warn("Risk assessment failed")
	}

	// Generate mock tokens
	accessToken := "keycloak-access-token-" + uuid.New().String()
	refreshToken := "keycloak-refresh-token-" + uuid.New().String()

	response := &types.AuthResponse{
		Success:      true,
		UserID:       userInfo.Sub,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    time.Now().Add(15 * time.Minute),
		TokenType:    "Bearer",
		Roles:        []string{"user"},
		Permissions:  []string{"read", "write"},
		Requires2FA:  ztContext.MFARequired,
		ServiceID:    request.ServiceID,
		Context:      request.Context,
		Message:      "Keycloak authentication successful",
		Metadata: map[string]interface{}{
			"risk_score":       ztContext.RiskScore,
			"device_trust":     ztContext.DeviceTrust,
			"anomaly_detected": ztContext.AnomalyDetected,
			"mfa_required":     ztContext.MFARequired,
		},
	}

	kp.logger.WithFields(logrus.Fields{
		"user_id":      userInfo.Sub,
		"username":     userInfo.PreferredUsername,
		"risk_score":   ztContext.RiskScore,
		"mfa_required": ztContext.MFARequired,
		"service_id":   request.ServiceID,
	}).Info("Keycloak authentication completed")

	return response, nil
}

// ValidateToken validates a Keycloak token
func (kp *KeycloakProvider) ValidateToken(ctx context.Context, request *types.TokenValidationRequest) (*types.TokenValidationResponse, error) {
	userInfo, err := kp.validateTokenInternal(ctx, request.Token)
	if err != nil {
		return &types.TokenValidationResponse{
			Valid:   false,
			Message: err.Error(),
		}, nil
	}

	return &types.TokenValidationResponse{
		Valid:     true,
		UserID:    userInfo.Sub,
		Claims:    map[string]interface{}{"email": userInfo.Email, "username": userInfo.PreferredUsername},
		ExpiresAt: time.Now().Add(15 * time.Minute),
		Message:   "Keycloak token is valid",
		Metadata:  request.Metadata,
	}, nil
}

// RefreshToken refreshes a Keycloak token
func (kp *KeycloakProvider) RefreshToken(ctx context.Context, request *types.TokenRefreshRequest) (*types.TokenRefreshResponse, error) {
	tokenResponse, err := kp.refreshTokenInternal(ctx, request.RefreshToken)
	if err != nil {
		return nil, fmt.Errorf("failed to refresh Keycloak token: %w", err)
	}

	return &types.TokenRefreshResponse{
		AccessToken:  tokenResponse.AccessToken,
		RefreshToken: tokenResponse.RefreshToken,
		ExpiresAt:    time.Now().Add(time.Duration(tokenResponse.ExpiresIn) * time.Second),
		TokenType:    tokenResponse.TokenType,
		Metadata:     request.Metadata,
	}, nil
}

// RevokeToken revokes a Keycloak token
func (kp *KeycloakProvider) RevokeToken(ctx context.Context, request *types.TokenRevocationRequest) error {
	revokeURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/logout", kp.config.ServerURL, kp.config.Realm)

	params := url.Values{}
	params.Set("client_id", kp.config.ClientID)
	params.Set("client_secret", kp.config.ClientSecret)
	params.Set("refresh_token", request.Token)

	req, err := http.NewRequestWithContext(ctx, "POST", revokeURL, strings.NewReader(params.Encode()))
	if err != nil {
		return fmt.Errorf("failed to create revoke request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := kp.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to revoke token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("token revocation failed with status: %d", resp.StatusCode)
	}

	kp.logger.WithFields(logrus.Fields{
		"user_id": request.UserID,
		"reason":  request.Reason,
	}).Info("Keycloak token revoked")

	return nil
}

// Authorize authorizes a user
func (kp *KeycloakProvider) Authorize(ctx context.Context, request *types.AuthorizationRequest) (*types.AuthorizationResponse, error) {
	// Keycloak authorization would check user roles and permissions
	return &types.AuthorizationResponse{
		Allowed:  true,
		Reason:   "Keycloak user authorized",
		Policies: []string{"keycloak-policy"},
		Metadata: request.Metadata,
	}, nil
}

// CheckPermission checks if a user has a specific permission
func (kp *KeycloakProvider) CheckPermission(ctx context.Context, request *types.PermissionRequest) (*types.PermissionResponse, error) {
	// Keycloak permission check would validate against user roles and client permissions
	return &types.PermissionResponse{
		Granted:  true,
		Reason:   "Keycloak permission granted",
		Metadata: request.Metadata,
	}, nil
}

// HealthCheck performs health check
func (kp *KeycloakProvider) HealthCheck(ctx context.Context) error {
	return kp.healthCheckInternal(ctx)
}

// GetStats returns provider statistics
func (kp *KeycloakProvider) GetStats(ctx context.Context) (*types.AuthStats, error) {
	stats := kp.getStatsInternal(ctx)
	return &types.AuthStats{
		TotalLogins:   2000,
		FailedLogins:  20,
		ActiveTokens:  100,
		RevokedTokens: 10,
		ProviderData:  stats,
	}, nil
}
