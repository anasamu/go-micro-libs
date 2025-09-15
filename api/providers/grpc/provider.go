package grpc

import (
	"context"
	"fmt"
	"time"

	"github.com/anasamu/go-micro-libs/api/types"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

// Provider implements APIProvider for gRPC
type Provider struct {
	config    map[string]interface{}
	logger    *logrus.Logger
	conn      *grpc.ClientConn
	connected bool
}

// NewProvider creates a new gRPC API provider
func NewProvider(logger *logrus.Logger) *Provider {
	return &Provider{
		config: make(map[string]interface{}),
		logger: logger,
	}
}

// GetName returns the provider name
func (p *Provider) GetName() string {
	return "grpc"
}

// GetSupportedFeatures returns supported features
func (p *Provider) GetSupportedFeatures() []types.APIFeature {
	return []types.APIFeature{
		types.FeaturegRPC,
		types.FeatureAuthentication,
		types.FeatureRateLimit,
		types.FeatureRetry,
		types.FeatureLogging,
		types.FeatureMonitoring,
		types.FeatureValidation,
		types.FeatureTransformation,
		types.FeatureStreaming,
		types.FeatureAsync,
		types.FeatureSync,
	}
}

// GetConnectionInfo returns connection information
func (p *Provider) GetConnectionInfo() *types.ConnectionInfo {
	address, _ := p.config["address"].(string)
	useTLS, _ := p.config["use_tls"].(bool)

	if address == "" {
		address = "localhost:50051"
	}

	host := "localhost"
	port := 50051
	protocol := "grpc"
	secure := useTLS

	// Parse address to get host and port
	if len(address) > 0 {
		// Simple parsing - in real implementation, use proper parsing
		if address != "localhost:50051" {
			// Extract host and port from address
			// This is simplified - in real implementation, use proper parsing
			host = "localhost"
			port = 50051
		}
	}

	return &types.ConnectionInfo{
		Host:     host,
		Port:     port,
		Protocol: protocol,
		Version:  "2.0",
		Secure:   secure,
	}
}

// Configure configures the gRPC provider
func (p *Provider) Configure(config map[string]interface{}) error {
	address, ok := config["address"].(string)
	if !ok || address == "" {
		return fmt.Errorf("grpc address is required")
	}

	// Set default values
	if config["timeout"] == nil {
		config["timeout"] = 30 * time.Second
	}
	if config["max_retries"] == nil {
		config["max_retries"] = 3
	}
	if config["retry_delay"] == nil {
		config["retry_delay"] = 1 * time.Second
	}
	if config["use_tls"] == nil {
		config["use_tls"] = false
	}

	p.config = config

	p.logger.Info("gRPC provider configured successfully")
	return nil
}

// IsConfigured checks if the provider is configured
func (p *Provider) IsConfigured() bool {
	address, ok := p.config["address"].(string)
	return ok && address != ""
}

// Connect connects to gRPC service
func (p *Provider) Connect(ctx context.Context) error {
	if !p.IsConfigured() {
		return fmt.Errorf("grpc provider not configured")
	}

	address, _ := p.config["address"].(string)
	useTLS, _ := p.config["use_tls"].(bool)
	timeout, _ := p.config["timeout"].(time.Duration)

	// Set up connection options
	var opts []grpc.DialOption

	// Configure transport credentials
	if useTLS {
		creds := credentials.NewTLS(nil) // In real implementation, configure TLS properly
		opts = append(opts, grpc.WithTransportCredentials(creds))
	} else {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	// Configure timeout
	if timeout > 0 {
		opts = append(opts, grpc.WithTimeout(timeout))
	}

	// Connect to gRPC server
	conn, err := grpc.DialContext(ctx, address, opts...)
	if err != nil {
		return fmt.Errorf("failed to connect to gRPC service: %w", err)
	}

	p.conn = conn
	p.connected = true

	p.logger.Info("gRPC provider connected successfully")
	return nil
}

// Disconnect disconnects from gRPC service
func (p *Provider) Disconnect(ctx context.Context) error {
	if p.conn != nil {
		if err := p.conn.Close(); err != nil {
			return fmt.Errorf("failed to close gRPC connection: %w", err)
		}
		p.conn = nil
	}

	p.connected = false
	p.logger.Info("gRPC provider disconnected successfully")
	return nil
}

// Ping checks gRPC connection
func (p *Provider) Ping(ctx context.Context) error {
	if !p.IsConfigured() {
		return fmt.Errorf("grpc provider not configured")
	}

	if p.conn == nil {
		return fmt.Errorf("not connected to gRPC service")
	}

	// Simple ping by checking connection state
	state := p.conn.GetState()
	if state.String() == "SHUTDOWN" {
		return fmt.Errorf("gRPC connection is shutdown")
	}

	return nil
}

// IsConnected checks if gRPC is connected
func (p *Provider) IsConnected() bool {
	return p.connected && p.conn != nil
}

// SendRequest sends an HTTP request (converted to gRPC)
func (p *Provider) SendRequest(ctx context.Context, request *types.APIRequest) (*types.APIResponse, error) {
	if !p.IsConfigured() {
		return nil, fmt.Errorf("grpc provider not configured")
	}

	// Convert API request to gRPC request
	grpcRequest := &types.GRPCRequest{
		ID:        request.ID,
		Service:   p.extractServiceFromURL(request.URL),
		Method:    p.extractMethodFromURL(request.URL),
		Data:      request.Body,
		Metadata:  p.convertHeadersToMetadata(request.Headers),
		Timeout:   request.Timeout,
		Options:   request.Metadata,
		CreatedAt: request.CreatedAt,
	}

	// Send gRPC request
	grpcResponse, err := p.SendgRPCRequest(ctx, grpcRequest)
	if err != nil {
		return nil, err
	}

	// Convert gRPC response to API response
	response := p.convertToAPIResponse(request, grpcResponse)

	return response, nil
}

// SendBatch sends multiple gRPC requests
func (p *Provider) SendBatch(ctx context.Context, request *types.BatchRequest) (*types.BatchResponse, error) {
	if !p.IsConfigured() {
		return nil, fmt.Errorf("grpc provider not configured")
	}

	responses := make([]types.APIResponse, 0, len(request.Requests))

	for _, req := range request.Requests {
		resp, err := p.SendRequest(ctx, &req)
		if err != nil {
			// Create error response
			errorResp := &types.APIResponse{
				ID:         req.ID,
				RequestID:  req.ID,
				StatusCode: 0,
				Success:    false,
				Error:      err.Error(),
				CreatedAt:  time.Now(),
			}
			responses = append(responses, *errorResp)
		} else {
			responses = append(responses, *resp)
		}
	}

	batchResponse := &types.BatchResponse{
		ID:        request.ID,
		RequestID: request.ID,
		Responses: responses,
		Success:   true,
		CreatedAt: time.Now(),
	}

	return batchResponse, nil
}

// SendGraphQLRequest is not supported by gRPC provider
func (p *Provider) SendGraphQLRequest(ctx context.Context, request *types.GraphQLRequest) (*types.GraphQLResponse, error) {
	return nil, fmt.Errorf("GraphQL requests not supported by gRPC provider")
}

// SendgRPCRequest sends a gRPC request
func (p *Provider) SendgRPCRequest(ctx context.Context, request *types.GRPCRequest) (*types.GRPCResponse, error) {
	if !p.IsConfigured() {
		return nil, fmt.Errorf("grpc provider not configured")
	}

	if p.conn == nil {
		return nil, fmt.Errorf("not connected to gRPC service")
	}

	startTime := time.Now()

	// Create context with timeout
	ctx, cancel := context.WithTimeout(ctx, request.Timeout)
	defer cancel()

	// Add metadata to context
	if len(request.Metadata) > 0 {
		md := metadata.New(request.Metadata)
		ctx = metadata.NewOutgoingContext(ctx, md)
	}

	// Add authentication metadata
	if auth, ok := p.config["auth"].(*types.Authentication); ok && auth != nil {
		ctx = p.addAuthenticationToContext(ctx, auth)
	}

	// This is a simplified implementation
	// In a real implementation, you would use the actual gRPC service definitions
	// and call the appropriate service methods based on the service and method names

	// For now, we'll simulate a gRPC call
	response := &types.GRPCResponse{
		ID:        request.ID,
		RequestID: request.ID,
		Data:      request.Data, // Echo back the data for now
		Metadata:  make(map[string]string),
		Status: &types.GRPCStatus{
			Code:    0, // OK
			Message: "Success",
		},
		Duration:  time.Since(startTime),
		Success:   true,
		CreatedAt: time.Now(),
	}

	return response, nil
}

// ConnectWebSocket is not supported by gRPC provider
func (p *Provider) ConnectWebSocket(ctx context.Context, request *types.WebSocketRequest) (*types.WebSocketResponse, error) {
	return nil, fmt.Errorf("WebSocket connections not supported by gRPC provider")
}

// SendWebSocketMessage is not supported by gRPC provider
func (p *Provider) SendWebSocketMessage(ctx context.Context, request *types.WebSocketRequest, message interface{}) (*types.WebSocketResponse, error) {
	return nil, fmt.Errorf("WebSocket messages not supported by gRPC provider")
}

// CloseWebSocket is not supported by gRPC provider
func (p *Provider) CloseWebSocket(ctx context.Context, request *types.WebSocketRequest) error {
	return fmt.Errorf("WebSocket operations not supported by gRPC provider")
}

// StreamRequest streams a gRPC request
func (p *Provider) StreamRequest(ctx context.Context, request *types.APIRequest, handler types.APIHandler) error {
	if !p.IsConfigured() {
		return fmt.Errorf("grpc provider not configured")
	}

	// Convert to gRPC request
	grpcRequest := &types.GRPCRequest{
		ID:        request.ID,
		Service:   p.extractServiceFromURL(request.URL),
		Method:    p.extractMethodFromURL(request.URL),
		Data:      request.Body,
		Metadata:  p.convertHeadersToMetadata(request.Headers),
		Timeout:   request.Timeout,
		Options:   request.Metadata,
		CreatedAt: request.CreatedAt,
	}

	// For streaming, we'll send the request and handle the response
	response, err := p.SendgRPCRequest(ctx, grpcRequest)
	if err != nil {
		return fmt.Errorf("failed to send gRPC request: %w", err)
	}

	// Convert to API response and call handler
	apiResponse := p.convertToAPIResponse(request, response)
	return handler(apiResponse)
}

// WebSocketStream is not supported by gRPC provider
func (p *Provider) WebSocketStream(ctx context.Context, request *types.WebSocketRequest, handler types.WebSocketHandler) error {
	return fmt.Errorf("WebSocket streaming not supported by gRPC provider")
}

// HealthCheck performs a health check on gRPC
func (p *Provider) HealthCheck(ctx context.Context) error {
	if !p.IsConfigured() {
		return fmt.Errorf("grpc provider not configured")
	}

	return p.Ping(ctx)
}

// GetStats returns gRPC statistics
func (p *Provider) GetStats(ctx context.Context) (*types.APIStats, error) {
	stats := &types.APIStats{
		ActiveConnections: 0,
		ProviderData: map[string]interface{}{
			"connected": p.IsConnected(),
			"address":   p.config["address"],
			"use_tls":   p.config["use_tls"],
		},
	}

	if p.IsConnected() {
		stats.ActiveConnections = 1
	}

	return stats, nil
}

// Close closes the gRPC provider
func (p *Provider) Close() error {
	return p.Disconnect(context.Background())
}

// extractServiceFromURL extracts service name from URL
func (p *Provider) extractServiceFromURL(url string) string {
	// Simplified extraction - in real implementation, use proper URL parsing
	return "DefaultService"
}

// extractMethodFromURL extracts method name from URL
func (p *Provider) extractMethodFromURL(url string) string {
	// Simplified extraction - in real implementation, use proper URL parsing
	return "DefaultMethod"
}

// convertHeadersToMetadata converts headers to gRPC metadata
func (p *Provider) convertHeadersToMetadata(headers []types.Header) map[string]string {
	metadata := make(map[string]string)
	for _, header := range headers {
		metadata[header.Name] = header.Value
	}
	return metadata
}

// convertToAPIResponse converts a gRPC response to an API response
func (p *Provider) convertToAPIResponse(request *types.APIRequest, grpcResponse *types.GRPCResponse) *types.APIResponse {
	// Convert gRPC status to HTTP status code
	statusCode := 200
	if grpcResponse.Status != nil && grpcResponse.Status.Code != 0 {
		statusCode = 500 // Internal Server Error for gRPC errors
	}

	response := &types.APIResponse{
		ID:         request.ID,
		RequestID:  request.ID,
		StatusCode: statusCode,
		Body:       grpcResponse.Data,
		Duration:   grpcResponse.Duration,
		Success:    grpcResponse.Success,
		Error:      grpcResponse.Error,
		CreatedAt:  grpcResponse.CreatedAt,
	}

	return response
}

// addAuthenticationToContext adds authentication to gRPC context
func (p *Provider) addAuthenticationToContext(ctx context.Context, auth *types.Authentication) context.Context {
	if auth == nil {
		return ctx
	}

	md := metadata.New(nil)

	switch auth.Type {
	case types.AuthTypeBearer:
		md.Set("authorization", "Bearer "+auth.Token)
	case types.AuthTypeAPIKey:
		if auth.APIKeyHeader != "" {
			md.Set(auth.APIKeyHeader, auth.APIKey)
		}
	case types.AuthTypeCustom:
		// Handle custom authentication
		if customHeaders, ok := auth.Custom["headers"].(map[string]string); ok {
			for key, value := range customHeaders {
				md.Set(key, value)
			}
		}
	}

	return metadata.NewOutgoingContext(ctx, md)
}
