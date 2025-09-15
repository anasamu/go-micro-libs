package http

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/anasamu/go-micro-libs/api/types"
	"github.com/sirupsen/logrus"
)

// Provider implements APIProvider for HTTP
type Provider struct {
	config    map[string]interface{}
	logger    *logrus.Logger
	client    *http.Client
	connected bool
}

// NewProvider creates a new HTTP API provider
func NewProvider(logger *logrus.Logger) *Provider {
	return &Provider{
		config: make(map[string]interface{}),
		logger: logger,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// GetName returns the provider name
func (p *Provider) GetName() string {
	return "http"
}

// GetSupportedFeatures returns supported features
func (p *Provider) GetSupportedFeatures() []types.APIFeature {
	return []types.APIFeature{
		types.FeatureHTTP,
		types.FeatureHTTPS,
		types.FeatureAuthentication,
		types.FeatureRateLimit,
		types.FeatureRetry,
		types.FeatureCompression,
		types.FeatureLogging,
		types.FeatureMonitoring,
		types.FeatureValidation,
		types.FeatureTransformation,
		types.FeaturePagination,
		types.FeatureBatch,
		types.FeatureStreaming,
		types.FeatureAsync,
		types.FeatureSync,
	}
}

// GetConnectionInfo returns connection information
func (p *Provider) GetConnectionInfo() *types.ConnectionInfo {
	baseURL, _ := p.config["base_url"].(string)
	timeout, _ := p.config["timeout"].(time.Duration)

	if baseURL == "" {
		baseURL = "http://localhost"
	}
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	// Parse URL to get host and port
	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		return &types.ConnectionInfo{
			Host:     "localhost",
			Port:     80,
			Protocol: "http",
			Version:  "1.1",
			Secure:   false,
		}
	}

	host := parsedURL.Hostname()
	port := 80
	protocol := "http"
	secure := false

	if parsedURL.Scheme == "https" {
		port = 443
		protocol = "https"
		secure = true
	} else if parsedURL.Port() != "" {
		fmt.Sscanf(parsedURL.Port(), "%d", &port)
	}

	return &types.ConnectionInfo{
		Host:     host,
		Port:     port,
		Protocol: protocol,
		Version:  "1.1",
		Secure:   secure,
	}
}

// Configure configures the HTTP provider
func (p *Provider) Configure(config map[string]interface{}) error {
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

	p.config = config

	// Configure HTTP client
	timeout, _ := config["timeout"].(time.Duration)
	p.client.Timeout = timeout

	// Configure transport
	transport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
	}

	// Configure proxy if provided
	if proxyURL, ok := config["proxy_url"].(string); ok && proxyURL != "" {
		proxy, err := url.Parse(proxyURL)
		if err != nil {
			return fmt.Errorf("invalid proxy URL: %w", err)
		}
		transport.Proxy = http.ProxyURL(proxy)
	}

	// Configure TLS if provided
	if skipTLS, ok := config["skip_tls_verify"].(bool); ok && skipTLS {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	p.client.Transport = transport

	p.logger.Info("HTTP provider configured successfully")
	return nil
}

// IsConfigured checks if the provider is configured
func (p *Provider) IsConfigured() bool {
	return len(p.config) > 0
}

// Connect connects to HTTP service
func (p *Provider) Connect(ctx context.Context) error {
	if !p.IsConfigured() {
		return fmt.Errorf("http provider not configured")
	}

	// Test connection by making a simple request
	baseURL, _ := p.config["base_url"].(string)
	if baseURL == "" {
		// If no base URL, we can't test connection
		p.connected = true
		return nil
	}

	// Make a simple HEAD request to test connection
	req, err := http.NewRequestWithContext(ctx, "HEAD", baseURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create test request: %w", err)
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to connect to HTTP service: %w", err)
	}
	resp.Body.Close()

	p.connected = true
	p.logger.Info("HTTP provider connected successfully")
	return nil
}

// Disconnect disconnects from HTTP service
func (p *Provider) Disconnect(ctx context.Context) error {
	p.connected = false
	p.logger.Info("HTTP provider disconnected successfully")
	return nil
}

// Ping checks HTTP connection
func (p *Provider) Ping(ctx context.Context) error {
	if !p.IsConfigured() {
		return fmt.Errorf("http provider not configured")
	}

	baseURL, _ := p.config["base_url"].(string)
	if baseURL == "" {
		// If no base URL, we can't ping
		return nil
	}

	req, err := http.NewRequestWithContext(ctx, "HEAD", baseURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create ping request: %w", err)
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to ping HTTP service: %w", err)
	}
	resp.Body.Close()

	return nil
}

// IsConnected checks if HTTP is connected
func (p *Provider) IsConnected() bool {
	return p.connected
}

// SendRequest sends an HTTP request
func (p *Provider) SendRequest(ctx context.Context, request *types.APIRequest) (*types.APIResponse, error) {
	if !p.IsConfigured() {
		return nil, fmt.Errorf("http provider not configured")
	}

	startTime := time.Now()

	// Build URL
	fullURL := p.buildURL(request.URL, request.QueryParams)

	// Create HTTP request
	httpReq, err := p.createHTTPRequest(ctx, request, fullURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	// Add headers
	p.addHeaders(httpReq, request.Headers)

	// Add authentication
	if err := p.addAuthentication(httpReq, request.Auth); err != nil {
		return nil, fmt.Errorf("failed to add authentication: %w", err)
	}

	// Execute request
	resp, err := p.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to execute HTTP request: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Parse response
	response := p.parseResponse(request, resp, body, time.Since(startTime))

	return response, nil
}

// SendBatch sends multiple HTTP requests
func (p *Provider) SendBatch(ctx context.Context, request *types.BatchRequest) (*types.BatchResponse, error) {
	if !p.IsConfigured() {
		return nil, fmt.Errorf("http provider not configured")
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

// SendGraphQLRequest sends a GraphQL request
func (p *Provider) SendGraphQLRequest(ctx context.Context, request *types.GraphQLRequest) (*types.GraphQLResponse, error) {
	if !p.IsConfigured() {
		return nil, fmt.Errorf("http provider not configured")
	}

	startTime := time.Now()

	// Build GraphQL request body
	graphqlBody := map[string]interface{}{
		"query": request.Query,
	}

	if len(request.Variables) > 0 {
		graphqlBody["variables"] = request.Variables
	}

	if request.Operation != "" {
		graphqlBody["operationName"] = request.Operation
	}

	bodyBytes, err := json.Marshal(graphqlBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal GraphQL request: %w", err)
	}

	// Create HTTP request
	endpoint, _ := p.config["base_url"].(string)
	if endpoint == "" {
		endpoint = "http://localhost/graphql"
	}
	httpReq, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewBuffer(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create GraphQL request: %w", err)
	}

	// Set content type
	httpReq.Header.Set("Content-Type", string(types.ContentTypeJSON))

	// Add headers
	p.addHeaders(httpReq, request.Headers)

	// Add authentication
	if err := p.addAuthentication(httpReq, request.Auth); err != nil {
		return nil, fmt.Errorf("failed to add authentication: %w", err)
	}

	// Execute request
	resp, err := p.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to execute GraphQL request: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read GraphQL response: %w", err)
	}

	// Parse GraphQL response
	response := p.parseGraphQLResponse(request, resp, body, time.Since(startTime))

	return response, nil
}

// SendgRPCRequest is not supported by HTTP provider
func (p *Provider) SendgRPCRequest(ctx context.Context, request *types.GRPCRequest) (*types.GRPCResponse, error) {
	return nil, fmt.Errorf("gRPC requests not supported by HTTP provider")
}

// ConnectWebSocket connects to a WebSocket
func (p *Provider) ConnectWebSocket(ctx context.Context, request *types.WebSocketRequest) (*types.WebSocketResponse, error) {
	return nil, fmt.Errorf("WebSocket connections not supported by HTTP provider")
}

// SendWebSocketMessage is not supported by HTTP provider
func (p *Provider) SendWebSocketMessage(ctx context.Context, request *types.WebSocketRequest, message interface{}) (*types.WebSocketResponse, error) {
	return nil, fmt.Errorf("WebSocket messages not supported by HTTP provider")
}

// CloseWebSocket is not supported by HTTP provider
func (p *Provider) CloseWebSocket(ctx context.Context, request *types.WebSocketRequest) error {
	return fmt.Errorf("WebSocket operations not supported by HTTP provider")
}

// StreamRequest streams an HTTP request
func (p *Provider) StreamRequest(ctx context.Context, request *types.APIRequest, handler types.APIHandler) error {
	if !p.IsConfigured() {
		return fmt.Errorf("http provider not configured")
	}

	// Build URL
	fullURL := p.buildURL(request.URL, request.QueryParams)

	// Create HTTP request
	httpReq, err := p.createHTTPRequest(ctx, request, fullURL)
	if err != nil {
		return fmt.Errorf("failed to create HTTP request: %w", err)
	}

	// Add headers
	p.addHeaders(httpReq, request.Headers)

	// Add authentication
	if err := p.addAuthentication(httpReq, request.Auth); err != nil {
		return fmt.Errorf("failed to add authentication: %w", err)
	}

	// Execute request
	resp, err := p.client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("failed to execute HTTP request: %w", err)
	}
	defer resp.Body.Close()

	// Stream response
	buffer := make([]byte, 1024)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			n, err := resp.Body.Read(buffer)
			if err != nil {
				if err == io.EOF {
					break
				}
				return fmt.Errorf("failed to read response: %w", err)
			}

			// Create response chunk
			chunk := &types.APIResponse{
				ID:         request.ID,
				RequestID:  request.ID,
				StatusCode: resp.StatusCode,
				RawBody:    buffer[:n],
				Success:    resp.StatusCode >= 200 && resp.StatusCode < 300,
				CreatedAt:  time.Now(),
			}

			// Call handler
			if err := handler(chunk); err != nil {
				return fmt.Errorf("handler error: %w", err)
			}
		}
	}

	return nil
}

// WebSocketStream is not supported by HTTP provider
func (p *Provider) WebSocketStream(ctx context.Context, request *types.WebSocketRequest, handler types.WebSocketHandler) error {
	return fmt.Errorf("WebSocket streaming not supported by HTTP provider")
}

// HealthCheck performs a health check on HTTP
func (p *Provider) HealthCheck(ctx context.Context) error {
	if !p.IsConfigured() {
		return fmt.Errorf("http provider not configured")
	}

	return p.Ping(ctx)
}

// GetStats returns HTTP statistics
func (p *Provider) GetStats(ctx context.Context) (*types.APIStats, error) {
	stats := &types.APIStats{
		ActiveConnections: 0,
		ProviderData: map[string]interface{}{
			"connected": p.IsConnected(),
			"timeout":   p.client.Timeout,
		},
	}

	if p.IsConnected() {
		stats.ActiveConnections = 1
	}

	return stats, nil
}

// Close closes the HTTP provider
func (p *Provider) Close() error {
	return p.Disconnect(context.Background())
}

// buildURL builds the full URL with query parameters
func (p *Provider) buildURL(baseURL string, queryParams []types.QueryParam) string {
	if len(queryParams) == 0 {
		return baseURL
	}

	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		return baseURL
	}

	values := parsedURL.Query()
	for _, param := range queryParams {
		values.Add(param.Name, param.Value)
	}

	parsedURL.RawQuery = values.Encode()
	return parsedURL.String()
}

// createHTTPRequest creates an HTTP request
func (p *Provider) createHTTPRequest(ctx context.Context, request *types.APIRequest, fullURL string) (*http.Request, error) {
	var body io.Reader

	// Handle different body types
	if request.Body != nil {
		switch bodyType := request.Body.(type) {
		case string:
			body = strings.NewReader(bodyType)
		case []byte:
			body = bytes.NewReader(bodyType)
		case map[string]interface{}, []interface{}:
			// JSON body
			bodyBytes, err := json.Marshal(bodyType)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal JSON body: %w", err)
			}
			body = bytes.NewReader(bodyBytes)
		default:
			return nil, fmt.Errorf("unsupported body type: %T", bodyType)
		}
	} else if len(request.FormData) > 0 || len(request.Files) > 0 {
		// Form data
		var buf bytes.Buffer
		writer := multipart.NewWriter(&buf)

		// Add form data
		for _, formData := range request.FormData {
			writer.WriteField(formData.Name, formData.Value)
		}

		// Add files
		for _, file := range request.Files {
			part, err := writer.CreateFormFile(file.Name, file.Filename)
			if err != nil {
				return nil, fmt.Errorf("failed to create form file: %w", err)
			}
			part.Write(file.Data)
		}

		writer.Close()
		body = &buf
	}

	httpReq, err := http.NewRequestWithContext(ctx, string(request.Method), fullURL, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	// Set content type for form data
	if len(request.FormData) > 0 || len(request.Files) > 0 {
		httpReq.Header.Set("Content-Type", "multipart/form-data")
	} else if request.Body != nil {
		// Set content type for JSON
		httpReq.Header.Set("Content-Type", string(types.ContentTypeJSON))
	}

	return httpReq, nil
}

// addHeaders adds headers to the HTTP request
func (p *Provider) addHeaders(req *http.Request, headers []types.Header) {
	for _, header := range headers {
		req.Header.Set(header.Name, header.Value)
	}
}

// addAuthentication adds authentication to the HTTP request
func (p *Provider) addAuthentication(req *http.Request, auth *types.Authentication) error {
	if auth == nil {
		return nil
	}

	switch auth.Type {
	case types.AuthTypeBasic:
		req.SetBasicAuth(auth.Username, auth.Password)
	case types.AuthTypeBearer:
		req.Header.Set("Authorization", "Bearer "+auth.Token)
	case types.AuthTypeAPIKey:
		if auth.APIKeyHeader != "" {
			req.Header.Set(auth.APIKeyHeader, auth.APIKey)
		} else if auth.APIKeyQuery != "" {
			// Add API key as query parameter
			values := req.URL.Query()
			values.Add(auth.APIKeyQuery, auth.APIKey)
			req.URL.RawQuery = values.Encode()
		}
	case types.AuthTypeCustom:
		// Handle custom authentication
		if customHeaders, ok := auth.Custom["headers"].(map[string]string); ok {
			for key, value := range customHeaders {
				req.Header.Set(key, value)
			}
		}
	}

	return nil
}

// parseResponse parses HTTP response
func (p *Provider) parseResponse(request *types.APIRequest, resp *http.Response, body []byte, duration time.Duration) *types.APIResponse {
	// Parse headers
	headers := make([]types.Header, 0, len(resp.Header))
	for name, values := range resp.Header {
		for _, value := range values {
			headers = append(headers, types.Header{Name: name, Value: value})
		}
	}

	// Parse body
	var parsedBody interface{}
	contentType := resp.Header.Get("Content-Type")

	if strings.Contains(contentType, "application/json") {
		json.Unmarshal(body, &parsedBody)
	} else {
		parsedBody = string(body)
	}

	response := &types.APIResponse{
		ID:          request.ID,
		RequestID:   request.ID,
		StatusCode:  resp.StatusCode,
		Headers:     headers,
		Body:        parsedBody,
		RawBody:     body,
		ContentType: contentType,
		Size:        int64(len(body)),
		Duration:    duration,
		Success:     resp.StatusCode >= 200 && resp.StatusCode < 300,
		CreatedAt:   time.Now(),
	}

	return response
}

// parseGraphQLResponse parses GraphQL response
func (p *Provider) parseGraphQLResponse(request *types.GraphQLRequest, resp *http.Response, body []byte, duration time.Duration) *types.GraphQLResponse {
	// Parse headers
	headers := make([]types.Header, 0, len(resp.Header))
	for name, values := range resp.Header {
		for _, value := range values {
			headers = append(headers, types.Header{Name: name, Value: value})
		}
	}

	// Parse GraphQL response
	var graphqlResp struct {
		Data   interface{}          `json:"data"`
		Errors []types.GraphQLError `json:"errors"`
	}

	json.Unmarshal(body, &graphqlResp)

	response := &types.GraphQLResponse{
		ID:        request.ID,
		RequestID: request.ID,
		Data:      graphqlResp.Data,
		Errors:    graphqlResp.Errors,
		Headers:   headers,
		Duration:  duration,
		Success:   len(graphqlResp.Errors) == 0 && resp.StatusCode >= 200 && resp.StatusCode < 300,
		CreatedAt: time.Now(),
	}

	return response
}
