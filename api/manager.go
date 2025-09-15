package api

import (
	"context"
	"fmt"
	"time"

	"github.com/anasamu/go-micro-libs/api/types"
	"github.com/sirupsen/logrus"
)

// APIManager manages multiple API providers
type APIManager struct {
	providers map[string]APIProvider
	logger    *logrus.Logger
	config    *ManagerConfig
}

// ManagerConfig holds API manager configuration
type ManagerConfig struct {
	DefaultProvider string            `json:"default_provider"`
	RetryAttempts   int               `json:"retry_attempts"`
	RetryDelay      time.Duration     `json:"retry_delay"`
	Timeout         time.Duration     `json:"timeout"`
	MaxRequestSize  int64             `json:"max_request_size"`
	Metadata        map[string]string `json:"metadata"`
}

// APIProvider interface for API backends
type APIProvider interface {
	// Provider information
	GetName() string
	GetSupportedFeatures() []types.APIFeature
	GetConnectionInfo() *types.ConnectionInfo

	// Connection management
	Connect(ctx context.Context) error
	Disconnect(ctx context.Context) error
	Ping(ctx context.Context) error
	IsConnected() bool

	// HTTP operations
	SendRequest(ctx context.Context, request *types.APIRequest) (*types.APIResponse, error)
	SendBatch(ctx context.Context, request *types.BatchRequest) (*types.BatchResponse, error)

	// GraphQL operations
	SendGraphQLRequest(ctx context.Context, request *types.GraphQLRequest) (*types.GraphQLResponse, error)

	// gRPC operations
	SendgRPCRequest(ctx context.Context, request *types.GRPCRequest) (*types.GRPCResponse, error)

	// WebSocket operations
	ConnectWebSocket(ctx context.Context, request *types.WebSocketRequest) (*types.WebSocketResponse, error)
	SendWebSocketMessage(ctx context.Context, request *types.WebSocketRequest, message interface{}) (*types.WebSocketResponse, error)
	CloseWebSocket(ctx context.Context, request *types.WebSocketRequest) error

	// Advanced operations
	StreamRequest(ctx context.Context, request *types.APIRequest, handler types.APIHandler) error
	WebSocketStream(ctx context.Context, request *types.WebSocketRequest, handler types.WebSocketHandler) error

	// Health and monitoring
	HealthCheck(ctx context.Context) error
	GetStats(ctx context.Context) (*types.APIStats, error)

	// Configuration
	Configure(config map[string]interface{}) error
	IsConfigured() bool
	Close() error
}

// DefaultManagerConfig returns default API manager configuration
func DefaultManagerConfig() *ManagerConfig {
	return &ManagerConfig{
		DefaultProvider: "http",
		RetryAttempts:   3,
		RetryDelay:      5 * time.Second,
		Timeout:         30 * time.Second,
		MaxRequestSize:  10 * 1024 * 1024, // 10MB
		Metadata:        make(map[string]string),
	}
}

// NewAPIManager creates a new API manager
func NewAPIManager(config *ManagerConfig, logger *logrus.Logger) *APIManager {
	if config == nil {
		config = DefaultManagerConfig()
	}

	if logger == nil {
		logger = logrus.New()
	}

	return &APIManager{
		providers: make(map[string]APIProvider),
		logger:    logger,
		config:    config,
	}
}

// RegisterProvider registers an API provider
func (am *APIManager) RegisterProvider(provider APIProvider) error {
	if provider == nil {
		return fmt.Errorf("provider cannot be nil")
	}

	name := provider.GetName()
	if name == "" {
		return fmt.Errorf("provider name cannot be empty")
	}

	am.providers[name] = provider
	am.logger.WithField("provider", name).Info("API provider registered")

	return nil
}

// GetProvider returns an API provider by name
func (am *APIManager) GetProvider(name string) (APIProvider, error) {
	provider, exists := am.providers[name]
	if !exists {
		return nil, fmt.Errorf("API provider not found: %s", name)
	}
	return provider, nil
}

// GetDefaultProvider returns the default API provider
func (am *APIManager) GetDefaultProvider() (APIProvider, error) {
	return am.GetProvider(am.config.DefaultProvider)
}

// Connect connects to an API system using the specified provider
func (am *APIManager) Connect(ctx context.Context, providerName string) error {
	provider, err := am.GetProvider(providerName)
	if err != nil {
		return err
	}

	// Connect with retry logic
	for attempt := 1; attempt <= am.config.RetryAttempts; attempt++ {
		err = provider.Connect(ctx)
		if err == nil {
			break
		}

		am.logger.WithError(err).WithFields(logrus.Fields{
			"provider": providerName,
			"attempt":  attempt,
		}).Warn("API connection failed, retrying")

		if attempt < am.config.RetryAttempts {
			time.Sleep(am.config.RetryDelay)
		}
	}

	if err != nil {
		return fmt.Errorf("failed to connect to API system after %d attempts: %w", am.config.RetryAttempts, err)
	}

	am.logger.WithField("provider", providerName).Info("API system connected successfully")
	return nil
}

// Disconnect disconnects from an API system using the specified provider
func (am *APIManager) Disconnect(ctx context.Context, providerName string) error {
	provider, err := am.GetProvider(providerName)
	if err != nil {
		return err
	}

	err = provider.Disconnect(ctx)
	if err != nil {
		return fmt.Errorf("failed to disconnect from API system: %w", err)
	}

	am.logger.WithField("provider", providerName).Info("API system disconnected successfully")
	return nil
}

// Ping pings an API system using the specified provider
func (am *APIManager) Ping(ctx context.Context, providerName string) error {
	provider, err := am.GetProvider(providerName)
	if err != nil {
		return err
	}

	err = provider.Ping(ctx)
	if err != nil {
		return fmt.Errorf("failed to ping API system: %w", err)
	}

	return nil
}

// SendRequest sends an HTTP request using the specified provider
func (am *APIManager) SendRequest(ctx context.Context, providerName string, request *types.APIRequest) (*types.APIResponse, error) {
	provider, err := am.GetProvider(providerName)
	if err != nil {
		return nil, err
	}

	// Validate request
	if err := am.validateAPIRequest(request); err != nil {
		return nil, fmt.Errorf("invalid API request: %w", err)
	}

	// Check request size limit
	if am.getRequestSize(request) > am.config.MaxRequestSize {
		return nil, fmt.Errorf("request size %d exceeds maximum allowed size %d", am.getRequestSize(request), am.config.MaxRequestSize)
	}

	// Set default values
	if request.CreatedAt.IsZero() {
		request.CreatedAt = time.Now()
	}
	if request.Timeout == 0 {
		request.Timeout = am.config.Timeout
	}
	if request.Retries == 0 {
		request.Retries = am.config.RetryAttempts
	}

	// Send with retry logic
	var response *types.APIResponse
	for attempt := 1; attempt <= request.Retries; attempt++ {
		response, err = provider.SendRequest(ctx, request)
		if err == nil {
			break
		}

		am.logger.WithError(err).WithFields(logrus.Fields{
			"provider":   providerName,
			"attempt":    attempt,
			"request_id": request.ID,
			"method":     request.Method,
			"url":        request.URL,
		}).Warn("API request failed, retrying")

		if attempt < request.Retries {
			time.Sleep(am.config.RetryDelay)
		}
	}

	if err != nil {
		return nil, fmt.Errorf("failed to send API request after %d attempts: %w", request.Retries, err)
	}

	am.logger.WithFields(logrus.Fields{
		"provider":   providerName,
		"request_id": request.ID,
		"method":     request.Method,
		"url":        request.URL,
		"status":     response.StatusCode,
		"duration":   response.Duration,
	}).Info("API request sent successfully")

	return response, nil
}

// SendBatch sends multiple HTTP requests using the specified provider
func (am *APIManager) SendBatch(ctx context.Context, providerName string, request *types.BatchRequest) (*types.BatchResponse, error) {
	provider, err := am.GetProvider(providerName)
	if err != nil {
		return nil, err
	}

	// Validate request
	if err := am.validateBatchRequest(request); err != nil {
		return nil, fmt.Errorf("invalid batch request: %w", err)
	}

	response, err := provider.SendBatch(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("failed to send batch: %w", err)
	}

	am.logger.WithFields(logrus.Fields{
		"provider":      providerName,
		"request_count": len(request.Requests),
		"success_count": len(response.Responses),
	}).Info("Batch API request sent successfully")

	return response, nil
}

// SendGraphQLRequest sends a GraphQL request using the specified provider
func (am *APIManager) SendGraphQLRequest(ctx context.Context, providerName string, request *types.GraphQLRequest) (*types.GraphQLResponse, error) {
	provider, err := am.GetProvider(providerName)
	if err != nil {
		return nil, err
	}

	// Validate request
	if err := am.validateGraphQLRequest(request); err != nil {
		return nil, fmt.Errorf("invalid GraphQL request: %w", err)
	}

	// Set default values
	if request.CreatedAt.IsZero() {
		request.CreatedAt = time.Now()
	}
	if request.Timeout == 0 {
		request.Timeout = am.config.Timeout
	}

	response, err := provider.SendGraphQLRequest(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("failed to send GraphQL request: %w", err)
	}

	am.logger.WithFields(logrus.Fields{
		"provider":   providerName,
		"request_id": request.ID,
		"operation":  request.Operation,
		"duration":   response.Duration,
		"success":    response.Success,
	}).Info("GraphQL request sent successfully")

	return response, nil
}

// SendgRPCRequest sends a gRPC request using the specified provider
func (am *APIManager) SendgRPCRequest(ctx context.Context, providerName string, request *types.GRPCRequest) (*types.GRPCResponse, error) {
	provider, err := am.GetProvider(providerName)
	if err != nil {
		return nil, err
	}

	// Validate request
	if err := am.validategRPCRequest(request); err != nil {
		return nil, fmt.Errorf("invalid gRPC request: %w", err)
	}

	// Set default values
	if request.CreatedAt.IsZero() {
		request.CreatedAt = time.Now()
	}
	if request.Timeout == 0 {
		request.Timeout = am.config.Timeout
	}

	response, err := provider.SendgRPCRequest(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("failed to send gRPC request: %w", err)
	}

	am.logger.WithFields(logrus.Fields{
		"provider":   providerName,
		"request_id": request.ID,
		"service":    request.Service,
		"method":     request.Method,
		"duration":   response.Duration,
		"success":    response.Success,
	}).Info("gRPC request sent successfully")

	return response, nil
}

// ConnectWebSocket connects to a WebSocket using the specified provider
func (am *APIManager) ConnectWebSocket(ctx context.Context, providerName string, request *types.WebSocketRequest) (*types.WebSocketResponse, error) {
	provider, err := am.GetProvider(providerName)
	if err != nil {
		return nil, err
	}

	// Validate request
	if err := am.validateWebSocketRequest(request); err != nil {
		return nil, fmt.Errorf("invalid WebSocket request: %w", err)
	}

	// Set default values
	if request.CreatedAt.IsZero() {
		request.CreatedAt = time.Now()
	}
	if request.Timeout == 0 {
		request.Timeout = am.config.Timeout
	}

	response, err := provider.ConnectWebSocket(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("failed to connect WebSocket: %w", err)
	}

	am.logger.WithFields(logrus.Fields{
		"provider":   providerName,
		"request_id": request.ID,
		"url":        request.URL,
		"duration":   response.Duration,
		"success":    response.Success,
	}).Info("WebSocket connected successfully")

	return response, nil
}

// SendWebSocketMessage sends a message through WebSocket using the specified provider
func (am *APIManager) SendWebSocketMessage(ctx context.Context, providerName string, request *types.WebSocketRequest, message interface{}) (*types.WebSocketResponse, error) {
	provider, err := am.GetProvider(providerName)
	if err != nil {
		return nil, err
	}

	response, err := provider.SendWebSocketMessage(ctx, request, message)
	if err != nil {
		return nil, fmt.Errorf("failed to send WebSocket message: %w", err)
	}

	am.logger.WithFields(logrus.Fields{
		"provider":   providerName,
		"request_id": request.ID,
		"duration":   response.Duration,
		"success":    response.Success,
	}).Info("WebSocket message sent successfully")

	return response, nil
}

// CloseWebSocket closes a WebSocket connection using the specified provider
func (am *APIManager) CloseWebSocket(ctx context.Context, providerName string, request *types.WebSocketRequest) error {
	provider, err := am.GetProvider(providerName)
	if err != nil {
		return err
	}

	err = provider.CloseWebSocket(ctx, request)
	if err != nil {
		return fmt.Errorf("failed to close WebSocket: %w", err)
	}

	am.logger.WithFields(logrus.Fields{
		"provider":   providerName,
		"request_id": request.ID,
	}).Info("WebSocket closed successfully")

	return nil
}

// StreamRequest streams an API request using the specified provider
func (am *APIManager) StreamRequest(ctx context.Context, providerName string, request *types.APIRequest, handler types.APIHandler) error {
	provider, err := am.GetProvider(providerName)
	if err != nil {
		return err
	}

	err = provider.StreamRequest(ctx, request, handler)
	if err != nil {
		return fmt.Errorf("failed to stream request: %w", err)
	}

	am.logger.WithFields(logrus.Fields{
		"provider":   providerName,
		"request_id": request.ID,
		"method":     request.Method,
		"url":        request.URL,
	}).Info("Request streaming started successfully")

	return nil
}

// WebSocketStream streams WebSocket messages using the specified provider
func (am *APIManager) WebSocketStream(ctx context.Context, providerName string, request *types.WebSocketRequest, handler types.WebSocketHandler) error {
	provider, err := am.GetProvider(providerName)
	if err != nil {
		return err
	}

	err = provider.WebSocketStream(ctx, request, handler)
	if err != nil {
		return fmt.Errorf("failed to stream WebSocket: %w", err)
	}

	am.logger.WithFields(logrus.Fields{
		"provider":   providerName,
		"request_id": request.ID,
		"url":        request.URL,
	}).Info("WebSocket streaming started successfully")

	return nil
}

// HealthCheck performs health check on all providers
func (am *APIManager) HealthCheck(ctx context.Context) map[string]error {
	results := make(map[string]error)

	for name, provider := range am.providers {
		err := provider.HealthCheck(ctx)
		results[name] = err
	}

	return results
}

// GetStats gets statistics from a provider
func (am *APIManager) GetStats(ctx context.Context, providerName string) (*types.APIStats, error) {
	provider, err := am.GetProvider(providerName)
	if err != nil {
		return nil, err
	}

	stats, err := provider.GetStats(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get API stats: %w", err)
	}

	return stats, nil
}

// GetSupportedProviders returns a list of registered providers
func (am *APIManager) GetSupportedProviders() []string {
	providers := make([]string, 0, len(am.providers))
	for name := range am.providers {
		providers = append(providers, name)
	}
	return providers
}

// GetProviderCapabilities returns capabilities of a provider
func (am *APIManager) GetProviderCapabilities(providerName string) ([]types.APIFeature, *types.ConnectionInfo, error) {
	provider, err := am.GetProvider(providerName)
	if err != nil {
		return nil, nil, err
	}

	return provider.GetSupportedFeatures(), provider.GetConnectionInfo(), nil
}

// Close closes all API connections
func (am *APIManager) Close() error {
	var lastErr error

	for name, provider := range am.providers {
		if err := provider.Close(); err != nil {
			am.logger.WithError(err).WithField("provider", name).Error("Failed to close API provider")
			lastErr = err
		}
	}

	return lastErr
}

// IsProviderConnected checks if a provider is connected
func (am *APIManager) IsProviderConnected(providerName string) bool {
	provider, err := am.GetProvider(providerName)
	if err != nil {
		return false
	}
	return provider.IsConnected()
}

// GetConnectedProviders returns a list of connected providers
func (am *APIManager) GetConnectedProviders() []string {
	connected := make([]string, 0)
	for name, provider := range am.providers {
		if provider.IsConnected() {
			connected = append(connected, name)
		}
	}
	return connected
}

// validateAPIRequest validates an API request
func (am *APIManager) validateAPIRequest(request *types.APIRequest) error {
	if request == nil {
		return fmt.Errorf("request cannot be nil")
	}

	if request.Method == "" {
		return fmt.Errorf("method is required")
	}

	if request.URL == "" {
		return fmt.Errorf("URL is required")
	}

	return nil
}

// validateBatchRequest validates a batch request
func (am *APIManager) validateBatchRequest(request *types.BatchRequest) error {
	if request == nil {
		return fmt.Errorf("request cannot be nil")
	}

	if len(request.Requests) == 0 {
		return fmt.Errorf("requests are required")
	}

	for i, req := range request.Requests {
		if err := am.validateAPIRequest(&req); err != nil {
			return fmt.Errorf("request %d is invalid: %w", i, err)
		}
	}

	return nil
}

// validateGraphQLRequest validates a GraphQL request
func (am *APIManager) validateGraphQLRequest(request *types.GraphQLRequest) error {
	if request == nil {
		return fmt.Errorf("request cannot be nil")
	}

	if request.Query == "" {
		return fmt.Errorf("query is required")
	}

	return nil
}

// validategRPCRequest validates a gRPC request
func (am *APIManager) validategRPCRequest(request *types.GRPCRequest) error {
	if request == nil {
		return fmt.Errorf("request cannot be nil")
	}

	if request.Service == "" {
		return fmt.Errorf("service is required")
	}

	if request.Method == "" {
		return fmt.Errorf("method is required")
	}

	return nil
}

// validateWebSocketRequest validates a WebSocket request
func (am *APIManager) validateWebSocketRequest(request *types.WebSocketRequest) error {
	if request == nil {
		return fmt.Errorf("request cannot be nil")
	}

	if request.URL == "" {
		return fmt.Errorf("URL is required")
	}

	return nil
}

// getRequestSize calculates the approximate size of a request
func (am *APIManager) getRequestSize(request *types.APIRequest) int64 {
	size := int64(len(request.URL))

	// Add body size if it's a string or byte slice
	if request.Body != nil {
		switch body := request.Body.(type) {
		case string:
			size += int64(len(body))
		case []byte:
			size += int64(len(body))
		}
	}

	// Add form data size
	for _, formData := range request.FormData {
		size += int64(len(formData.Name) + len(formData.Value))
	}

	// Add file sizes
	for _, file := range request.Files {
		size += int64(len(file.Data))
	}

	return size
}
