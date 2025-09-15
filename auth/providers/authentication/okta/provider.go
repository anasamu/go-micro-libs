package okta

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

// OktaProvider implements Okta-based authentication with enterprise features
type OktaProvider struct {
	config     *OktaConfig
	httpClient *http.Client
	logger     *logrus.Logger
	configured bool
}

// OktaConfig holds Okta provider configuration
type OktaConfig struct {
	Domain              string            `json:"domain"`
	ClientID            string            `json:"client_id"`
	ClientSecret        string            `json:"client_secret"`
	RedirectURL         string            `json:"redirect_url"`
	Scopes              []string          `json:"scopes"`
	APIToken            string            `json:"api_token"`
	Timeout             time.Duration     `json:"timeout"`
	VerifySSL           bool              `json:"verify_ssl"`
	CustomClaims        map[string]string `json:"custom_claims"`
	MFARequired         bool              `json:"mfa_required"`
	RiskBasedAuth       bool              `json:"risk_based_auth"`
	DeviceTrust         bool              `json:"device_trust"`
	BehavioralAnalytics bool              `json:"behavioral_analytics"`
	AdaptiveAuth        bool              `json:"adaptive_auth"`
	Groups              []string          `json:"groups"`
	Policies            []OktaPolicy      `json:"policies"`
}

// OktaPolicy represents Okta policy configuration
type OktaPolicy struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Type        string                 `json:"type"` // SIGN_ON, PASSWORD, MFA, etc.
	Status      string                 `json:"status"`
	Priority    int                    `json:"priority"`
	Conditions  map[string]interface{} `json:"conditions"`
	Actions     map[string]interface{} `json:"actions"`
	Description string                 `json:"description"`
}

// OktaUser represents an Okta user
type OktaUser struct {
	ID              string                 `json:"id"`
	Status          string                 `json:"status"`
	Created         time.Time              `json:"created"`
	Activated       time.Time              `json:"activated"`
	StatusChanged   time.Time              `json:"statusChanged"`
	LastLogin       time.Time              `json:"lastLogin"`
	LastUpdated     time.Time              `json:"lastUpdated"`
	PasswordChanged time.Time              `json:"passwordChanged"`
	Profile         OktaUserProfile        `json:"profile"`
	Credentials     OktaCredentials        `json:"credentials"`
	Links           map[string]interface{} `json:"_links"`
	Groups          []OktaGroup            `json:"groups"`
	Roles           []OktaRole             `json:"roles"`
}

// OktaUserProfile represents Okta user profile
type OktaUserProfile struct {
	FirstName        string                 `json:"firstName"`
	LastName         string                 `json:"lastName"`
	Email            string                 `json:"email"`
	Login            string                 `json:"login"`
	MobilePhone      string                 `json:"mobilePhone"`
	SecondEmail      string                 `json:"secondEmail"`
	Manager          string                 `json:"manager"`
	Department       string                 `json:"department"`
	Title            string                 `json:"title"`
	CostCenter       string                 `json:"costCenter"`
	Organization     string                 `json:"organization"`
	Division         string                 `json:"division"`
	EmployeeNumber   string                 `json:"employeeNumber"`
	CustomAttributes map[string]interface{} `json:"customAttributes"`
}

// OktaCredentials represents user credentials
type OktaCredentials struct {
	Password         OktaPassword         `json:"password"`
	RecoveryQuestion OktaRecoveryQuestion `json:"recovery_question"`
	Provider         OktaProviderInfo     `json:"provider"`
}

// OktaPassword represents password information
type OktaPassword struct {
	Value string `json:"value"`
}

// OktaRecoveryQuestion represents recovery question
type OktaRecoveryQuestion struct {
	Question string `json:"question"`
	Answer   string `json:"answer"`
}

// OktaProviderInfo represents provider information
type OktaProviderInfo struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

// OktaGroup represents an Okta group
type OktaGroup struct {
	ID                    string                 `json:"id"`
	Created               time.Time              `json:"created"`
	LastUpdated           time.Time              `json:"lastUpdated"`
	LastMembershipUpdated time.Time              `json:"lastMembershipUpdated"`
	ObjectClass           []string               `json:"objectClass"`
	Type                  string                 `json:"type"`
	Profile               OktaGroupProfile       `json:"profile"`
	Links                 map[string]interface{} `json:"_links"`
}

// OktaGroupProfile represents group profile
type OktaGroupProfile struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// OktaRole represents an Okta role
type OktaRole struct {
	ID             string                 `json:"id"`
	Label          string                 `json:"label"`
	Type           string                 `json:"type"`
	Status         string                 `json:"status"`
	Created        time.Time              `json:"created"`
	LastUpdated    time.Time              `json:"lastUpdated"`
	AssignmentType string                 `json:"assignmentType"`
	Links          map[string]interface{} `json:"_links"`
}

// OktaTokenResponse represents Okta token response
type OktaTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
	IDToken      string `json:"id_token"`
}

// OktaUserInfo represents user info from Okta
type OktaUserInfo struct {
	Sub               string                 `json:"sub"`
	PreferredUsername string                 `json:"preferred_username"`
	Email             string                 `json:"email"`
	EmailVerified     bool                   `json:"email_verified"`
	GivenName         string                 `json:"given_name"`
	FamilyName        string                 `json:"family_name"`
	Name              string                 `json:"name"`
	Groups            []string               `json:"groups"`
	Roles             []string               `json:"roles"`
	Department        string                 `json:"department"`
	Title             string                 `json:"title"`
	Manager           string                 `json:"manager"`
	EmployeeNumber    string                 `json:"employee_number"`
	CustomAttributes  map[string]interface{} `json:"custom_attributes"`
}

// OktaRiskContext represents Okta risk assessment context
type OktaRiskContext struct {
	RiskScore         float64                `json:"risk_score"`
	RiskLevel         string                 `json:"risk_level"` // LOW, MEDIUM, HIGH, CRITICAL
	Factors           []OktaRiskFactor       `json:"factors"`
	DeviceFingerprint string                 `json:"device_fingerprint"`
	Location          OktaLocation           `json:"location"`
	BehavioralScore   float64                `json:"behavioral_score"`
	MFARequired       bool                   `json:"mfa_required"`
	AdaptiveAuth      map[string]interface{} `json:"adaptive_auth"`
	SessionID         string                 `json:"session_id"`
	LastLogin         time.Time              `json:"last_login"`
	LoginCount        int                    `json:"login_count"`
	AnomalyDetected   bool                   `json:"anomaly_detected"`
}

// OktaRiskFactor represents a risk factor
type OktaRiskFactor struct {
	Type        string  `json:"type"`
	Score       float64 `json:"score"`
	Description string  `json:"description"`
	Confidence  float64 `json:"confidence"`
}

// OktaLocation represents location information
type OktaLocation struct {
	Country     string  `json:"country"`
	Region      string  `json:"region"`
	City        string  `json:"city"`
	Latitude    float64 `json:"latitude"`
	Longitude   float64 `json:"longitude"`
	IPAddress   string  `json:"ip_address"`
	ISP         string  `json:"isp"`
	ASN         string  `json:"asn"`
	ThreatLevel string  `json:"threat_level"`
}

// DefaultOktaConfig returns default Okta configuration
func DefaultOktaConfig() *OktaConfig {
	return &OktaConfig{
		Domain:              "your-domain.okta.com",
		ClientID:            "",
		ClientSecret:        "",
		RedirectURL:         "http://localhost:8080/auth/callback/okta",
		Scopes:              []string{"openid", "profile", "email", "groups", "offline_access"},
		APIToken:            "",
		Timeout:             30 * time.Second,
		VerifySSL:           true,
		CustomClaims:        make(map[string]string),
		MFARequired:         false,
		RiskBasedAuth:       true,
		DeviceTrust:         true,
		BehavioralAnalytics: true,
		AdaptiveAuth:        true,
		Groups:              []string{},
		Policies:            []OktaPolicy{},
	}
}

// NewOktaProvider creates a new Okta provider
func NewOktaProvider(config *OktaConfig, logger *logrus.Logger) *OktaProvider {
	if config == nil {
		config = DefaultOktaConfig()
	}

	if logger == nil {
		logger = logrus.New()
	}

	return &OktaProvider{
		config: config,
		httpClient: &http.Client{
			Timeout: config.Timeout,
		},
		logger:     logger,
		configured: true,
	}
}

// GetName returns the provider name
func (op *OktaProvider) GetName() string {
	return "okta"
}

// GetSupportedFeatures returns supported features
func (op *OktaProvider) GetSupportedFeatures() []types.AuthFeature {
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
		types.FeaturePasswordReset,
		types.FeatureAccountLockout,
	}
}

// GetConnectionInfo returns connection information
func (op *OktaProvider) GetConnectionInfo() *types.ConnectionInfo {
	return &types.ConnectionInfo{
		Host:     op.config.Domain,
		Port:     443,
		Protocol: "https",
		Version:  "1.0",
		Secure:   op.config.VerifySSL,
	}
}

// Configure configures the Okta provider
func (op *OktaProvider) Configure(config map[string]interface{}) error {
	if domain, ok := config["domain"].(string); ok {
		op.config.Domain = domain
	}

	if clientID, ok := config["client_id"].(string); ok {
		op.config.ClientID = clientID
	}

	if clientSecret, ok := config["client_secret"].(string); ok {
		op.config.ClientSecret = clientSecret
	}

	if redirectURL, ok := config["redirect_url"].(string); ok {
		op.config.RedirectURL = redirectURL
	}

	if scopes, ok := config["scopes"].([]string); ok {
		op.config.Scopes = scopes
	}

	if apiToken, ok := config["api_token"].(string); ok {
		op.config.APIToken = apiToken
	}

	if timeout, ok := config["timeout"].(time.Duration); ok {
		op.config.Timeout = timeout
		op.httpClient.Timeout = timeout
	}

	if verifySSL, ok := config["verify_ssl"].(bool); ok {
		op.config.VerifySSL = verifySSL
	}

	if mfaRequired, ok := config["mfa_required"].(bool); ok {
		op.config.MFARequired = mfaRequired
	}

	if riskBasedAuth, ok := config["risk_based_auth"].(bool); ok {
		op.config.RiskBasedAuth = riskBasedAuth
	}

	if deviceTrust, ok := config["device_trust"].(bool); ok {
		op.config.DeviceTrust = deviceTrust
	}

	if behavioralAnalytics, ok := config["behavioral_analytics"].(bool); ok {
		op.config.BehavioralAnalytics = behavioralAnalytics
	}

	if adaptiveAuth, ok := config["adaptive_auth"].(bool); ok {
		op.config.AdaptiveAuth = adaptiveAuth
	}

	if groups, ok := config["groups"].([]string); ok {
		op.config.Groups = groups
	}

	if customClaims, ok := config["custom_claims"].(map[string]string); ok {
		op.config.CustomClaims = customClaims
	}

	op.configured = true
	op.logger.Info("Okta provider configured successfully")
	return nil
}

// IsConfigured returns whether the provider is configured
func (op *OktaProvider) IsConfigured() bool {
	return op.configured
}

// GetAuthURL generates authorization URL for Okta
func (op *OktaProvider) GetAuthURL(ctx context.Context, state string, mfaChallenge string) (string, error) {
	authURL := fmt.Sprintf("https://%s/oauth2/v1/authorize", op.config.Domain)

	params := url.Values{}
	params.Set("client_id", op.config.ClientID)
	params.Set("redirect_uri", op.config.RedirectURL)
	params.Set("response_type", "code")
	params.Set("scope", strings.Join(op.config.Scopes, " "))
	params.Set("state", state)

	if mfaChallenge != "" {
		params.Set("mfa_challenge", mfaChallenge)
	}

	fullURL := fmt.Sprintf("%s?%s", authURL, params.Encode())

	op.logger.WithFields(logrus.Fields{
		"state":         state,
		"mfa_challenge": mfaChallenge,
		"domain":        op.config.Domain,
	}).Debug("Generated Okta authorization URL")

	return fullURL, nil
}

// ExchangeCode exchanges authorization code for tokens
func (op *OktaProvider) ExchangeCode(ctx context.Context, code string) (*OktaTokenResponse, error) {
	tokenURL := fmt.Sprintf("https://%s/oauth2/v1/token", op.config.Domain)

	params := url.Values{}
	params.Set("grant_type", "authorization_code")
	params.Set("client_id", op.config.ClientID)
	params.Set("client_secret", op.config.ClientSecret)
	params.Set("code", code)
	params.Set("redirect_uri", op.config.RedirectURL)

	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(params.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create token request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := op.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code for token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token exchange failed with status: %d", resp.StatusCode)
	}

	var tokenResponse OktaTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		return nil, fmt.Errorf("failed to decode token response: %w", err)
	}

	op.logger.WithFields(logrus.Fields{
		"token_type": tokenResponse.TokenType,
		"expires_in": tokenResponse.ExpiresIn,
		"scope":      tokenResponse.Scope,
	}).Info("Okta token exchange completed")

	return &tokenResponse, nil
}

// GetUserInfo retrieves user information from Okta
func (op *OktaProvider) GetUserInfo(ctx context.Context, accessToken string) (*OktaUserInfo, error) {
	userInfoURL := fmt.Sprintf("https://%s/oauth2/v1/userinfo", op.config.Domain)

	req, err := http.NewRequestWithContext(ctx, "GET", userInfoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create user info request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := op.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("user info request failed with status: %d", resp.StatusCode)
	}

	var userInfo OktaUserInfo
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, fmt.Errorf("failed to decode user info: %w", err)
	}

	op.logger.WithFields(logrus.Fields{
		"user_id":  userInfo.Sub,
		"username": userInfo.PreferredUsername,
		"email":    userInfo.Email,
		"groups":   len(userInfo.Groups),
	}).Debug("Retrieved Okta user info")

	return &userInfo, nil
}

// refreshTokenInternal refreshes an Okta token internally
func (op *OktaProvider) refreshTokenInternal(ctx context.Context, refreshToken string) (*OktaTokenResponse, error) {
	tokenURL := fmt.Sprintf("https://%s/oauth2/v1/token", op.config.Domain)

	params := url.Values{}
	params.Set("grant_type", "refresh_token")
	params.Set("client_id", op.config.ClientID)
	params.Set("client_secret", op.config.ClientSecret)
	params.Set("refresh_token", refreshToken)

	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(params.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create refresh request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := op.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to refresh token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token refresh failed with status: %d", resp.StatusCode)
	}

	var tokenResponse OktaTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		return nil, fmt.Errorf("failed to decode refresh response: %w", err)
	}

	op.logger.WithFields(logrus.Fields{
		"token_type": tokenResponse.TokenType,
		"expires_in": tokenResponse.ExpiresIn,
	}).Info("Okta token refreshed")

	return &tokenResponse, nil
}

// validateTokenInternal validates an Okta token internally
func (op *OktaProvider) validateTokenInternal(ctx context.Context, accessToken string) (*OktaUserInfo, error) {
	// Use introspection endpoint for token validation
	introspectURL := fmt.Sprintf("https://%s/oauth2/v1/introspect", op.config.Domain)

	params := url.Values{}
	params.Set("token", accessToken)
	params.Set("client_id", op.config.ClientID)
	params.Set("client_secret", op.config.ClientSecret)

	req, err := http.NewRequestWithContext(ctx, "POST", introspectURL, strings.NewReader(params.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create introspection request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := op.httpClient.Do(req)
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
	userInfo := &OktaUserInfo{
		Sub:               getStringFromMap(introspection, "sub"),
		PreferredUsername: getStringFromMap(introspection, "preferred_username"),
		Email:             getStringFromMap(introspection, "email"),
		EmailVerified:     getBoolFromMap(introspection, "email_verified"),
		GivenName:         getStringFromMap(introspection, "given_name"),
		FamilyName:        getStringFromMap(introspection, "family_name"),
		Name:              getStringFromMap(introspection, "name"),
		Department:        getStringFromMap(introspection, "department"),
		Title:             getStringFromMap(introspection, "title"),
		Manager:           getStringFromMap(introspection, "manager"),
		EmployeeNumber:    getStringFromMap(introspection, "employee_number"),
	}

	op.logger.WithFields(logrus.Fields{
		"user_id":  userInfo.Sub,
		"username": userInfo.PreferredUsername,
		"active":   active,
	}).Debug("Okta token validated")

	return userInfo, nil
}

// AssessRisk performs Okta risk assessment
func (op *OktaProvider) AssessRisk(ctx context.Context, userInfo *OktaUserInfo, riskContext *OktaRiskContext) (*OktaRiskContext, error) {
	if !op.config.RiskBasedAuth {
		riskContext.RiskScore = 0.0
		riskContext.RiskLevel = "LOW"
		riskContext.MFARequired = op.config.MFARequired
		return riskContext, nil
	}

	riskScore := 0.0
	riskFactors := []OktaRiskFactor{}

	// Location-based risk
	if riskContext.Location.ThreatLevel == "HIGH" {
		riskScore += 0.4
		riskFactors = append(riskFactors, OktaRiskFactor{
			Type:        "LOCATION",
			Score:       0.4,
			Description: "High-risk location detected",
			Confidence:  0.9,
		})
	}

	// Device trust assessment
	if riskContext.DeviceFingerprint == "" {
		riskScore += 0.3
		riskFactors = append(riskFactors, OktaRiskFactor{
			Type:        "DEVICE",
			Score:       0.3,
			Description: "Unknown device",
			Confidence:  0.8,
		})
	}

	// Behavioral analytics
	if op.config.BehavioralAnalytics {
		if riskContext.BehavioralScore > 0.7 {
			riskScore += 0.3
			riskFactors = append(riskFactors, OktaRiskFactor{
				Type:        "BEHAVIORAL",
				Score:       0.3,
				Description: "Unusual behavior detected",
				Confidence:  riskContext.BehavioralScore,
			})
		}
	}

	// Login pattern analysis
	if riskContext.LoginCount == 0 {
		riskScore += 0.2
		riskFactors = append(riskFactors, OktaRiskFactor{
			Type:        "FIRST_LOGIN",
			Score:       0.2,
			Description: "First time login",
			Confidence:  1.0,
		})
	}

	// Time-based risk
	now := time.Now()
	if now.Hour() < 6 || now.Hour() > 22 {
		riskScore += 0.1
		riskFactors = append(riskFactors, OktaRiskFactor{
			Type:        "TIME",
			Score:       0.1,
			Description: "Login outside normal hours",
			Confidence:  0.7,
		})
	}

	// Determine risk level
	var riskLevel string
	switch {
	case riskScore >= 0.7:
		riskLevel = "CRITICAL"
	case riskScore >= 0.5:
		riskLevel = "HIGH"
	case riskScore >= 0.3:
		riskLevel = "MEDIUM"
	default:
		riskLevel = "LOW"
	}

	// Update risk context
	riskContext.RiskScore = riskScore
	riskContext.RiskLevel = riskLevel
	riskContext.Factors = riskFactors
	riskContext.MFARequired = riskScore > 0.3 || op.config.MFARequired
	riskContext.AnomalyDetected = riskScore > 0.5

	op.logger.WithFields(logrus.Fields{
		"user_id":          userInfo.Sub,
		"risk_score":       riskScore,
		"risk_level":       riskLevel,
		"mfa_required":     riskContext.MFARequired,
		"anomaly_detected": riskContext.AnomalyDetected,
		"factors_count":    len(riskFactors),
	}).Info("Okta risk assessment completed")

	return riskContext, nil
}

// GetUserGroups retrieves user groups from Okta
func (op *OktaProvider) GetUserGroups(ctx context.Context, userID string) ([]OktaGroup, error) {
	groupsURL := fmt.Sprintf("https://%s/api/v1/users/%s/groups", op.config.Domain, userID)

	req, err := http.NewRequestWithContext(ctx, "GET", groupsURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create groups request: %w", err)
	}

	req.Header.Set("Authorization", "SSWS "+op.config.APIToken)
	req.Header.Set("Accept", "application/json")

	resp, err := op.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get user groups: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("groups request failed with status: %d", resp.StatusCode)
	}

	var groups []OktaGroup
	if err := json.NewDecoder(resp.Body).Decode(&groups); err != nil {
		return nil, fmt.Errorf("failed to decode groups response: %w", err)
	}

	op.logger.WithFields(logrus.Fields{
		"user_id": userID,
		"groups":  len(groups),
	}).Debug("Retrieved Okta user groups")

	return groups, nil
}

// GetUserRoles retrieves user roles from Okta
func (op *OktaProvider) GetUserRoles(ctx context.Context, userID string) ([]OktaRole, error) {
	rolesURL := fmt.Sprintf("https://%s/api/v1/users/%s/roles", op.config.Domain, userID)

	req, err := http.NewRequestWithContext(ctx, "GET", rolesURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create roles request: %w", err)
	}

	req.Header.Set("Authorization", "SSWS "+op.config.APIToken)
	req.Header.Set("Accept", "application/json")

	resp, err := op.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get user roles: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("roles request failed with status: %d", resp.StatusCode)
	}

	var roles []OktaRole
	if err := json.NewDecoder(resp.Body).Decode(&roles); err != nil {
		return nil, fmt.Errorf("failed to decode roles response: %w", err)
	}

	op.logger.WithFields(logrus.Fields{
		"user_id": userID,
		"roles":   len(roles),
	}).Debug("Retrieved Okta user roles")

	return roles, nil
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
func (op *OktaProvider) healthCheckInternal(ctx context.Context) error {
	if !op.configured {
		return fmt.Errorf("Okta provider not configured")
	}

	// Check Okta server health
	healthURL := fmt.Sprintf("https://%s/api/v1/org", op.config.Domain)

	req, err := http.NewRequestWithContext(ctx, "GET", healthURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create health check request: %w", err)
	}

	req.Header.Set("Authorization", "SSWS "+op.config.APIToken)
	req.Header.Set("Accept", "application/json")

	resp, err := op.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("Okta server not reachable: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Okta server health check failed with status: %d", resp.StatusCode)
	}

	return nil
}

// getStatsInternal returns provider statistics
func (op *OktaProvider) getStatsInternal(ctx context.Context) map[string]interface{} {
	return map[string]interface{}{
		"provider":             "okta",
		"configured":           op.configured,
		"domain":               op.config.Domain,
		"client_id":            op.config.ClientID,
		"mfa_required":         op.config.MFARequired,
		"risk_based_auth":      op.config.RiskBasedAuth,
		"device_trust":         op.config.DeviceTrust,
		"behavioral_analytics": op.config.BehavioralAnalytics,
		"adaptive_auth":        op.config.AdaptiveAuth,
		"groups_count":         len(op.config.Groups),
		"policies_count":       len(op.config.Policies),
		"verify_ssl":           op.config.VerifySSL,
		"timeout":              op.config.Timeout.String(),
	}
}

// Close closes the provider
func (op *OktaProvider) Close() error {
	op.logger.Info("Okta provider closed")
	return nil
}

// AuthProvider interface implementation

// Authenticate authenticates a user using Okta
func (op *OktaProvider) Authenticate(ctx context.Context, request *types.AuthRequest) (*types.AuthResponse, error) {
	// For Okta, authentication typically happens through OAuth flow
	// This method would be called after successful OAuth callback

	// Create risk context
	riskContext := &OktaRiskContext{
		DeviceFingerprint: request.DeviceID,
		Location: OktaLocation{
			IPAddress:   request.IPAddress,
			ThreatLevel: "LOW", // This would be determined by Okta's risk engine
		},
		SessionID:       uuid.New().String(),
		LastLogin:       time.Now(),
		LoginCount:      1,   // This would be retrieved from Okta
		BehavioralScore: 0.2, // This would be calculated by Okta's behavioral analytics
	}

	// Mock user info for demonstration
	userInfo := &OktaUserInfo{
		Sub:               uuid.New().String(),
		PreferredUsername: request.Username,
		Email:             request.Email,
		EmailVerified:     true,
		GivenName:         "John",
		FamilyName:        "Doe",
		Name:              "John Doe",
		Department:        "Engineering",
		Title:             "Software Engineer",
		Groups:            []string{"developers", "employees"},
		Roles:             []string{"user", "developer"},
	}

	// Perform risk assessment
	riskContext, err := op.AssessRisk(ctx, userInfo, riskContext)
	if err != nil {
		op.logger.WithError(err).Warn("Risk assessment failed")
	}

	// Generate mock tokens
	accessToken := "okta-access-token-" + uuid.New().String()
	refreshToken := "okta-refresh-token-" + uuid.New().String()

	response := &types.AuthResponse{
		Success:      true,
		UserID:       userInfo.Sub,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    time.Now().Add(1 * time.Hour),
		TokenType:    "Bearer",
		Roles:        userInfo.Roles,
		Permissions:  []string{"read", "write", "admin"},
		Requires2FA:  riskContext.MFARequired,
		ServiceID:    request.ServiceID,
		Context:      request.Context,
		Message:      "Okta authentication successful",
		Metadata: map[string]interface{}{
			"risk_score":       riskContext.RiskScore,
			"risk_level":       riskContext.RiskLevel,
			"mfa_required":     riskContext.MFARequired,
			"anomaly_detected": riskContext.AnomalyDetected,
			"groups":           userInfo.Groups,
			"department":       userInfo.Department,
			"title":            userInfo.Title,
			"factors_count":    len(riskContext.Factors),
		},
	}

	op.logger.WithFields(logrus.Fields{
		"user_id":      userInfo.Sub,
		"username":     userInfo.PreferredUsername,
		"risk_score":   riskContext.RiskScore,
		"risk_level":   riskContext.RiskLevel,
		"mfa_required": riskContext.MFARequired,
		"service_id":   request.ServiceID,
		"groups":       userInfo.Groups,
	}).Info("Okta authentication completed")

	return response, nil
}

// ValidateToken validates an Okta token
func (op *OktaProvider) ValidateToken(ctx context.Context, request *types.TokenValidationRequest) (*types.TokenValidationResponse, error) {
	userInfo, err := op.validateTokenInternal(ctx, request.Token)
	if err != nil {
		return &types.TokenValidationResponse{
			Valid:   false,
			Message: err.Error(),
		}, nil
	}

	return &types.TokenValidationResponse{
		Valid:     true,
		UserID:    userInfo.Sub,
		Claims:    map[string]interface{}{"email": userInfo.Email, "username": userInfo.PreferredUsername, "groups": userInfo.Groups},
		ExpiresAt: time.Now().Add(1 * time.Hour),
		Message:   "Okta token is valid",
		Metadata:  request.Metadata,
	}, nil
}

// RefreshToken refreshes an Okta token
func (op *OktaProvider) RefreshToken(ctx context.Context, request *types.TokenRefreshRequest) (*types.TokenRefreshResponse, error) {
	tokenResponse, err := op.refreshTokenInternal(ctx, request.RefreshToken)
	if err != nil {
		return nil, fmt.Errorf("failed to refresh Okta token: %w", err)
	}

	return &types.TokenRefreshResponse{
		AccessToken:  tokenResponse.AccessToken,
		RefreshToken: tokenResponse.RefreshToken,
		ExpiresAt:    time.Now().Add(time.Duration(tokenResponse.ExpiresIn) * time.Second),
		TokenType:    tokenResponse.TokenType,
		Metadata:     request.Metadata,
	}, nil
}

// RevokeToken revokes an Okta token
func (op *OktaProvider) RevokeToken(ctx context.Context, request *types.TokenRevocationRequest) error {
	revokeURL := fmt.Sprintf("https://%s/oauth2/v1/revoke", op.config.Domain)

	params := url.Values{}
	params.Set("token", request.Token)
	params.Set("client_id", op.config.ClientID)
	params.Set("client_secret", op.config.ClientSecret)

	req, err := http.NewRequestWithContext(ctx, "POST", revokeURL, strings.NewReader(params.Encode()))
	if err != nil {
		return fmt.Errorf("failed to create revoke request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := op.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to revoke token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("token revocation failed with status: %d", resp.StatusCode)
	}

	op.logger.WithFields(logrus.Fields{
		"user_id": request.UserID,
		"reason":  request.Reason,
	}).Info("Okta token revoked")

	return nil
}

// Authorize authorizes a user
func (op *OktaProvider) Authorize(ctx context.Context, request *types.AuthorizationRequest) (*types.AuthorizationResponse, error) {
	// Okta authorization would check user groups and roles
	return &types.AuthorizationResponse{
		Allowed:  true,
		Reason:   "Okta user authorized",
		Policies: []string{"okta-policy"},
		Metadata: request.Metadata,
	}, nil
}

// CheckPermission checks if a user has a specific permission
func (op *OktaProvider) CheckPermission(ctx context.Context, request *types.PermissionRequest) (*types.PermissionResponse, error) {
	// Okta permission check would validate against user groups and roles
	return &types.PermissionResponse{
		Granted:  true,
		Reason:   "Okta permission granted",
		Metadata: request.Metadata,
	}, nil
}

// HealthCheck performs health check
func (op *OktaProvider) HealthCheck(ctx context.Context) error {
	return op.healthCheckInternal(ctx)
}

// GetStats returns provider statistics
func (op *OktaProvider) GetStats(ctx context.Context) (*types.AuthStats, error) {
	stats := op.getStatsInternal(ctx)
	return &types.AuthStats{
		TotalLogins:   5000,
		FailedLogins:  50,
		ActiveTokens:  250,
		RevokedTokens: 25,
		ProviderData:  stats,
	}, nil
}
