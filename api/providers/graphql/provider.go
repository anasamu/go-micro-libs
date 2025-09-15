package graphql

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/anasamu/go-micro-libs/api/types"
	"github.com/sirupsen/logrus"
)

// Provider implements APIProvider for GraphQL
type Provider struct {
	config    map[string]interface{}
	logger    *logrus.Logger
	client    *http.Client
	connected bool
}

// NewProvider creates a new GraphQL API provider
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
	return "graphql"
}

// GetSupportedFeatures returns supported features
func (p *Provider) GetSupportedFeatures() []types.APIFeature {
	return []types.APIFeature{
		types.FeatureGraphQL,
		types.FeatureHTTP,
		types.FeatureHTTPS,
		types.FeatureAuthentication,
		types.FeatureRateLimit,
		types.FeatureRetry,
		types.FeatureLogging,
		types.FeatureMonitoring,
		types.FeatureValidation,
		types.FeatureTransformation,
		types.FeatureAsync,
		types.FeatureSync,
	}
}

// GetConnectionInfo returns connection information
func (p *Provider) GetConnectionInfo() *types.ConnectionInfo {
	endpoint, _ := p.config["endpoint"].(string)
	timeout, _ := p.config["timeout"].(time.Duration)

	if endpoint == "" {
		endpoint = "http://localhost/graphql"
	}
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	// Parse endpoint to get host and port
	parsedURL, err := url.Parse(endpoint)
	if err != nil {
		return &types.ConnectionInfo{
			Host:     "localhost",
			Port:     80,
			Protocol: "http",
			Version:  "GraphQL",
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
		Version:  "GraphQL",
		Secure:   secure,
	}
}

// Configure configures the GraphQL provider
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

	p.logger.Info("GraphQL provider configured successfully")
	return nil
}

// IsConfigured checks if the provider is configured
func (p *Provider) IsConfigured() bool {
	endpoint, ok := p.config["endpoint"].(string)
	return ok && endpoint != ""
}

// Connect connects to GraphQL service
func (p *Provider) Connect(ctx context.Context) error {
	if !p.IsConfigured() {
		return fmt.Errorf("graphql provider not configured")
	}

	// Test connection by making a simple introspection query
	endpoint, _ := p.config["endpoint"].(string)

	// Create a simple introspection query
	introspectionQuery := `{
		__schema {
			queryType {
				name
			}
		}
	}`

	reqBody := map[string]interface{}{
		"query": introspectionQuery,
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("failed to marshal introspection query: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewBuffer(bodyBytes))
	if err != nil {
		return fmt.Errorf("failed to create test request: %w", err)
	}

	req.Header.Set("Content-Type", string(types.ContentTypeJSON))

	// Add authentication if configured
	if auth, ok := p.config["auth"].(*types.Authentication); ok && auth != nil {
		if err := p.addAuthentication(req, auth); err != nil {
			return fmt.Errorf("failed to add authentication: %w", err)
		}
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to connect to GraphQL service: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("GraphQL service returned status %d", resp.StatusCode)
	}

	p.connected = true
	p.logger.Info("GraphQL provider connected successfully")
	return nil
}

// Disconnect disconnects from GraphQL service
func (p *Provider) Disconnect(ctx context.Context) error {
	p.connected = false
	p.logger.Info("GraphQL provider disconnected successfully")
	return nil
}

// Ping checks GraphQL connection
func (p *Provider) Ping(ctx context.Context) error {
	if !p.IsConfigured() {
		return fmt.Errorf("graphql provider not configured")
	}

	endpoint, _ := p.config["endpoint"].(string)

	// Create a simple ping query
	pingQuery := `{
		__typename
	}`

	reqBody := map[string]interface{}{
		"query": pingQuery,
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("failed to marshal ping query: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewBuffer(bodyBytes))
	if err != nil {
		return fmt.Errorf("failed to create ping request: %w", err)
	}

	req.Header.Set("Content-Type", string(types.ContentTypeJSON))

	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to ping GraphQL service: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("GraphQL service returned status %d", resp.StatusCode)
	}

	return nil
}

// IsConnected checks if GraphQL is connected
func (p *Provider) IsConnected() bool {
	return p.connected
}

// SendRequest sends an HTTP request (converted to GraphQL)
func (p *Provider) SendRequest(ctx context.Context, request *types.APIRequest) (*types.APIResponse, error) {
	if !p.IsConfigured() {
		return nil, fmt.Errorf("graphql provider not configured")
	}

	// Convert API request to GraphQL request
	graphqlRequest := &types.GraphQLRequest{
		ID:        request.ID,
		Query:     p.convertToGraphQLQuery(request),
		Variables: p.convertToGraphQLVariables(request),
		Headers:   request.Headers,
		Auth:      request.Auth,
		Timeout:   request.Timeout,
		Metadata:  request.Metadata,
		CreatedAt: request.CreatedAt,
	}

	// Send GraphQL request
	graphqlResponse, err := p.SendGraphQLRequest(ctx, graphqlRequest)
	if err != nil {
		return nil, err
	}

	// Convert GraphQL response to API response
	response := p.convertToAPIResponse(request, graphqlResponse)

	return response, nil
}

// SendBatch sends multiple GraphQL requests
func (p *Provider) SendBatch(ctx context.Context, request *types.BatchRequest) (*types.BatchResponse, error) {
	if !p.IsConfigured() {
		return nil, fmt.Errorf("graphql provider not configured")
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
		return nil, fmt.Errorf("graphql provider not configured")
	}

	startTime := time.Now()
	endpoint, _ := p.config["endpoint"].(string)

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

// SendgRPCRequest is not supported by GraphQL provider
func (p *Provider) SendgRPCRequest(ctx context.Context, request *types.GRPCRequest) (*types.GRPCResponse, error) {
	return nil, fmt.Errorf("gRPC requests not supported by GraphQL provider")
}

// ConnectWebSocket connects to a WebSocket (for GraphQL subscriptions)
func (p *Provider) ConnectWebSocket(ctx context.Context, request *types.WebSocketRequest) (*types.WebSocketResponse, error) {
	// GraphQL subscriptions over WebSocket
	return nil, fmt.Errorf("WebSocket connections not implemented in GraphQL provider")
}

// SendWebSocketMessage is not supported by GraphQL provider
func (p *Provider) SendWebSocketMessage(ctx context.Context, request *types.WebSocketRequest, message interface{}) (*types.WebSocketResponse, error) {
	return nil, fmt.Errorf("WebSocket messages not supported by GraphQL provider")
}

// CloseWebSocket is not supported by GraphQL provider
func (p *Provider) CloseWebSocket(ctx context.Context, request *types.WebSocketRequest) error {
	return fmt.Errorf("WebSocket operations not supported by GraphQL provider")
}

// StreamRequest streams a GraphQL request
func (p *Provider) StreamRequest(ctx context.Context, request *types.APIRequest, handler types.APIHandler) error {
	if !p.IsConfigured() {
		return fmt.Errorf("graphql provider not configured")
	}

	// Convert to GraphQL request
	graphqlRequest := &types.GraphQLRequest{
		ID:        request.ID,
		Query:     p.convertToGraphQLQuery(request),
		Variables: p.convertToGraphQLVariables(request),
		Headers:   request.Headers,
		Auth:      request.Auth,
		Timeout:   request.Timeout,
		Metadata:  request.Metadata,
		CreatedAt: request.CreatedAt,
	}

	// For streaming, we'll send the request and handle the response
	response, err := p.SendGraphQLRequest(ctx, graphqlRequest)
	if err != nil {
		return fmt.Errorf("failed to send GraphQL request: %w", err)
	}

	// Convert to API response and call handler
	apiResponse := p.convertToAPIResponse(request, response)
	return handler(apiResponse)
}

// WebSocketStream is not supported by GraphQL provider
func (p *Provider) WebSocketStream(ctx context.Context, request *types.WebSocketRequest, handler types.WebSocketHandler) error {
	return fmt.Errorf("WebSocket streaming not supported by GraphQL provider")
}

// HealthCheck performs a health check on GraphQL
func (p *Provider) HealthCheck(ctx context.Context) error {
	if !p.IsConfigured() {
		return fmt.Errorf("graphql provider not configured")
	}

	return p.Ping(ctx)
}

// GetStats returns GraphQL statistics
func (p *Provider) GetStats(ctx context.Context) (*types.APIStats, error) {
	stats := &types.APIStats{
		ActiveConnections: 0,
		ProviderData: map[string]interface{}{
			"connected": p.IsConnected(),
			"timeout":   p.client.Timeout,
			"endpoint":  p.config["endpoint"],
		},
	}

	if p.IsConnected() {
		stats.ActiveConnections = 1
	}

	return stats, nil
}

// Close closes the GraphQL provider
func (p *Provider) Close() error {
	return p.Disconnect(context.Background())
}

// convertToGraphQLQuery converts an API request to a GraphQL query
func (p *Provider) convertToGraphQLQuery(request *types.APIRequest) string {
	// This is a simplified conversion
	// In a real implementation, you might want to use a more sophisticated approach

	switch request.Method {
	case types.MethodGET:
		// Convert GET request to GraphQL query
		return fmt.Sprintf(`query {
			%s
		}`, p.extractQueryFromURL(request.URL))
	case types.MethodPOST:
		// Convert POST request to GraphQL mutation
		return fmt.Sprintf(`mutation {
			%s
		}`, p.extractMutationFromBody(request.Body))
	default:
		// Default query
		return `query { __typename }`
	}
}

// convertToGraphQLVariables converts API request data to GraphQL variables
func (p *Provider) convertToGraphQLVariables(request *types.APIRequest) map[string]interface{} {
	variables := make(map[string]interface{})

	// Add query parameters as variables
	for _, param := range request.QueryParams {
		variables[param.Name] = param.Value
	}

	// Add body data as variables
	if request.Body != nil {
		if bodyMap, ok := request.Body.(map[string]interface{}); ok {
			for key, value := range bodyMap {
				variables[key] = value
			}
		}
	}

	return variables
}

// convertToAPIResponse converts a GraphQL response to an API response
func (p *Provider) convertToAPIResponse(request *types.APIRequest, graphqlResponse *types.GraphQLResponse) *types.APIResponse {
	// Convert GraphQL errors to API error
	var errorMsg string
	if len(graphqlResponse.Errors) > 0 {
		errorMsg = graphqlResponse.Errors[0].Message
	}

	response := &types.APIResponse{
		ID:         request.ID,
		RequestID:  request.ID,
		StatusCode: 200, // GraphQL typically returns 200 even with errors
		Body:       graphqlResponse.Data,
		Duration:   graphqlResponse.Duration,
		Success:    graphqlResponse.Success,
		Error:      errorMsg,
		Headers:    graphqlResponse.Headers,
		CreatedAt:  graphqlResponse.CreatedAt,
	}

	return response
}

// extractQueryFromURL extracts a query from URL path
func (p *Provider) extractQueryFromURL(url string) string {
	// Simplified extraction - in real implementation, use proper URL parsing
	return "getData"
}

// extractMutationFromBody extracts a mutation from request body
func (p *Provider) extractMutationFromBody(body interface{}) string {
	// Simplified extraction - in real implementation, use proper body parsing
	return "updateData"
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
