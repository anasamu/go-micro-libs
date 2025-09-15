package types

import (
	"time"

	"github.com/google/uuid"
)

// APIFeature represents an API feature
type APIFeature string

const (
	FeatureHTTP           APIFeature = "http"
	FeatureHTTPS          APIFeature = "https"
	FeatureGraphQL        APIFeature = "graphql"
	FeaturegRPC           APIFeature = "grpc"
	FeatureWebSocket      APIFeature = "websocket"
	FeatureAuthentication APIFeature = "authentication"
	FeatureRateLimit      APIFeature = "rate_limit"
	FeatureRetry          APIFeature = "retry"
	FeatureCircuitBreaker APIFeature = "circuit_breaker"
	FeatureCaching        APIFeature = "caching"
	FeatureCompression    APIFeature = "compression"
	FeatureEncryption     APIFeature = "encryption"
	FeatureLogging        APIFeature = "logging"
	FeatureMonitoring     APIFeature = "monitoring"
	FeatureTracing        APIFeature = "tracing"
	FeatureValidation     APIFeature = "validation"
	FeatureTransformation APIFeature = "transformation"
	FeaturePagination     APIFeature = "pagination"
	FeatureBatch          APIFeature = "batch"
	FeatureStreaming      APIFeature = "streaming"
	FeatureAsync          APIFeature = "async"
	FeatureSync           APIFeature = "sync"
)

// HTTPMethod represents HTTP methods
type HTTPMethod string

const (
	MethodGET     HTTPMethod = "GET"
	MethodPOST    HTTPMethod = "POST"
	MethodPUT     HTTPMethod = "PUT"
	MethodPATCH   HTTPMethod = "PATCH"
	MethodDELETE  HTTPMethod = "DELETE"
	MethodHEAD    HTTPMethod = "HEAD"
	MethodOPTIONS HTTPMethod = "OPTIONS"
)

// ContentType represents content types
type ContentType string

const (
	ContentTypeJSON      ContentType = "application/json"
	ContentTypeXML       ContentType = "application/xml"
	ContentTypeForm      ContentType = "application/x-www-form-urlencoded"
	ContentTypeMultipart ContentType = "multipart/form-data"
	ContentTypeText      ContentType = "text/plain"
	ContentTypeHTML      ContentType = "text/html"
	ContentTypeBinary    ContentType = "application/octet-stream"
	ContentTypeGraphQL   ContentType = "application/graphql"
	ContentTypeProtobuf  ContentType = "application/x-protobuf"
)

// AuthType represents authentication types
type AuthType string

const (
	AuthTypeNone   AuthType = "none"
	AuthTypeBasic  AuthType = "basic"
	AuthTypeBearer AuthType = "bearer"
	AuthTypeAPIKey AuthType = "api_key"
	AuthTypeOAuth2 AuthType = "oauth2"
	AuthTypeJWT    AuthType = "jwt"
	AuthTypeCustom AuthType = "custom"
)

// ConnectionInfo represents API connection information
type ConnectionInfo struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Version  string `json:"version"`
	Secure   bool   `json:"secure"`
}

// Header represents an HTTP header
type Header struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// QueryParam represents a query parameter
type QueryParam struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// FormData represents form data
type FormData struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// FileUpload represents a file upload
type FileUpload struct {
	Name        string `json:"name"`
	Filename    string `json:"filename"`
	ContentType string `json:"content_type"`
	Data        []byte `json:"data"`
}

// Authentication represents authentication configuration
type Authentication struct {
	Type         AuthType               `json:"type"`
	Username     string                 `json:"username,omitempty"`
	Password     string                 `json:"password,omitempty"`
	Token        string                 `json:"token,omitempty"`
	APIKey       string                 `json:"api_key,omitempty"`
	APIKeyHeader string                 `json:"api_key_header,omitempty"`
	APIKeyQuery  string                 `json:"api_key_query,omitempty"`
	OAuth2       *OAuth2Config          `json:"oauth2,omitempty"`
	JWT          *JWTConfig             `json:"jwt,omitempty"`
	Custom       map[string]interface{} `json:"custom,omitempty"`
}

// OAuth2Config represents OAuth2 configuration
type OAuth2Config struct {
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	TokenURL     string   `json:"token_url"`
	AuthURL      string   `json:"auth_url,omitempty"`
	Scopes       []string `json:"scopes,omitempty"`
	RedirectURL  string   `json:"redirect_url,omitempty"`
}

// JWTConfig represents JWT configuration
type JWTConfig struct {
	Secret     string                 `json:"secret"`
	Algorithm  string                 `json:"algorithm,omitempty"`
	Claims     map[string]interface{} `json:"claims,omitempty"`
	Expiration time.Duration          `json:"expiration,omitempty"`
}

// APIRequest represents a generic API request
type APIRequest struct {
	ID          uuid.UUID              `json:"id"`
	Method      HTTPMethod             `json:"method"`
	URL         string                 `json:"url"`
	Headers     []Header               `json:"headers,omitempty"`
	QueryParams []QueryParam           `json:"query_params,omitempty"`
	Body        interface{}            `json:"body,omitempty"`
	FormData    []FormData             `json:"form_data,omitempty"`
	Files       []FileUpload           `json:"files,omitempty"`
	Auth        *Authentication        `json:"auth,omitempty"`
	Timeout     time.Duration          `json:"timeout,omitempty"`
	Retries     int                    `json:"retries,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	CreatedAt   time.Time              `json:"created_at"`
}

// APIResponse represents a generic API response
type APIResponse struct {
	ID          uuid.UUID              `json:"id"`
	RequestID   uuid.UUID              `json:"request_id"`
	StatusCode  int                    `json:"status_code"`
	Headers     []Header               `json:"headers,omitempty"`
	Body        interface{}            `json:"body,omitempty"`
	RawBody     []byte                 `json:"raw_body,omitempty"`
	ContentType string                 `json:"content_type,omitempty"`
	Size        int64                  `json:"size"`
	Duration    time.Duration          `json:"duration"`
	Success     bool                   `json:"success"`
	Error       string                 `json:"error,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	CreatedAt   time.Time              `json:"created_at"`
}

// GraphQLRequest represents a GraphQL request
type GraphQLRequest struct {
	ID        uuid.UUID              `json:"id"`
	Query     string                 `json:"query"`
	Variables map[string]interface{} `json:"variables,omitempty"`
	Operation string                 `json:"operation,omitempty"`
	Headers   []Header               `json:"headers,omitempty"`
	Auth      *Authentication        `json:"auth,omitempty"`
	Timeout   time.Duration          `json:"timeout,omitempty"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
	CreatedAt time.Time              `json:"created_at"`
}

// GraphQLResponse represents a GraphQL response
type GraphQLResponse struct {
	ID        uuid.UUID              `json:"id"`
	RequestID uuid.UUID              `json:"request_id"`
	Data      interface{}            `json:"data,omitempty"`
	Errors    []GraphQLError         `json:"errors,omitempty"`
	Headers   []Header               `json:"headers,omitempty"`
	Duration  time.Duration          `json:"duration"`
	Success   bool                   `json:"success"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
	CreatedAt time.Time              `json:"created_at"`
}

// GraphQLError represents a GraphQL error
type GraphQLError struct {
	Message    string                 `json:"message"`
	Locations  []GraphQLLocation      `json:"locations,omitempty"`
	Path       []interface{}          `json:"path,omitempty"`
	Extensions map[string]interface{} `json:"extensions,omitempty"`
}

// GraphQLLocation represents a GraphQL error location
type GraphQLLocation struct {
	Line   int `json:"line"`
	Column int `json:"column"`
}

// GRPCRequest represents a gRPC request
type GRPCRequest struct {
	ID        uuid.UUID              `json:"id"`
	Service   string                 `json:"service"`
	Method    string                 `json:"method"`
	Data      interface{}            `json:"data,omitempty"`
	Metadata  map[string]string      `json:"metadata,omitempty"`
	Timeout   time.Duration          `json:"timeout,omitempty"`
	Options   map[string]interface{} `json:"options,omitempty"`
	CreatedAt time.Time              `json:"created_at"`
}

// GRPCResponse represents a gRPC response
type GRPCResponse struct {
	ID        uuid.UUID         `json:"id"`
	RequestID uuid.UUID         `json:"request_id"`
	Data      interface{}       `json:"data,omitempty"`
	Metadata  map[string]string `json:"metadata,omitempty"`
	Status    *GRPCStatus       `json:"status,omitempty"`
	Duration  time.Duration     `json:"duration"`
	Success   bool              `json:"success"`
	Error     string            `json:"error,omitempty"`
	CreatedAt time.Time         `json:"created_at"`
}

// GRPCStatus represents gRPC status
type GRPCStatus struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Details string `json:"details,omitempty"`
}

// WebSocketRequest represents a WebSocket request
type WebSocketRequest struct {
	ID        uuid.UUID              `json:"id"`
	URL       string                 `json:"url"`
	Headers   []Header               `json:"headers,omitempty"`
	Auth      *Authentication        `json:"auth,omitempty"`
	Protocols []string               `json:"protocols,omitempty"`
	Timeout   time.Duration          `json:"timeout,omitempty"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
	CreatedAt time.Time              `json:"created_at"`
}

// WebSocketResponse represents a WebSocket response
type WebSocketResponse struct {
	ID        uuid.UUID              `json:"id"`
	RequestID uuid.UUID              `json:"request_id"`
	Message   interface{}            `json:"message,omitempty"`
	Type      string                 `json:"type,omitempty"`
	Duration  time.Duration          `json:"duration"`
	Success   bool                   `json:"success"`
	Error     string                 `json:"error,omitempty"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
	CreatedAt time.Time              `json:"created_at"`
}

// BatchRequest represents a batch API request
type BatchRequest struct {
	ID        uuid.UUID              `json:"id"`
	Requests  []APIRequest           `json:"requests"`
	Options   map[string]interface{} `json:"options,omitempty"`
	CreatedAt time.Time              `json:"created_at"`
}

// BatchResponse represents a batch API response
type BatchResponse struct {
	ID        uuid.UUID              `json:"id"`
	RequestID uuid.UUID              `json:"request_id"`
	Responses []APIResponse          `json:"responses"`
	Success   bool                   `json:"success"`
	Error     string                 `json:"error,omitempty"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
	CreatedAt time.Time              `json:"created_at"`
}

// PaginationRequest represents pagination parameters
type PaginationRequest struct {
	Page    int    `json:"page,omitempty"`
	Limit   int    `json:"limit,omitempty"`
	Offset  int    `json:"offset,omitempty"`
	Cursor  string `json:"cursor,omitempty"`
	SortBy  string `json:"sort_by,omitempty"`
	SortDir string `json:"sort_dir,omitempty"`
}

// PaginationResponse represents pagination response
type PaginationResponse struct {
	Page       int    `json:"page"`
	Limit      int    `json:"limit"`
	Total      int64  `json:"total"`
	TotalPages int    `json:"total_pages"`
	HasNext    bool   `json:"has_next"`
	HasPrev    bool   `json:"has_prev"`
	NextCursor string `json:"next_cursor,omitempty"`
	PrevCursor string `json:"prev_cursor,omitempty"`
}

// APIStats represents API statistics
type APIStats struct {
	TotalRequests       int64                  `json:"total_requests"`
	SuccessfulRequests  int64                  `json:"successful_requests"`
	FailedRequests      int64                  `json:"failed_requests"`
	AverageResponseTime time.Duration          `json:"average_response_time"`
	ActiveConnections   int                    `json:"active_connections"`
	ProviderData        map[string]interface{} `json:"provider_data"`
}

// WebSocketHandler handles WebSocket messages
type WebSocketHandler func(response *WebSocketResponse) error

// APIHandler handles API responses
type APIHandler func(response *APIResponse) error

// CreateAPIRequest creates a new API request with default values
func CreateAPIRequest(method HTTPMethod, url string) *APIRequest {
	return &APIRequest{
		ID:          uuid.New(),
		Method:      method,
		URL:         url,
		Headers:     make([]Header, 0),
		QueryParams: make([]QueryParam, 0),
		Metadata:    make(map[string]interface{}),
		CreatedAt:   time.Now(),
	}
}

// CreateGraphQLRequest creates a new GraphQL request with default values
func CreateGraphQLRequest(query string) *GraphQLRequest {
	return &GraphQLRequest{
		ID:        uuid.New(),
		Query:     query,
		Variables: make(map[string]interface{}),
		Headers:   make([]Header, 0),
		Metadata:  make(map[string]interface{}),
		CreatedAt: time.Now(),
	}
}

// CreateGRPCRequest creates a new gRPC request with default values
func CreateGRPCRequest(service, method string) *GRPCRequest {
	return &GRPCRequest{
		ID:        uuid.New(),
		Service:   service,
		Method:    method,
		Metadata:  make(map[string]string),
		Options:   make(map[string]interface{}),
		CreatedAt: time.Now(),
	}
}

// CreateWebSocketRequest creates a new WebSocket request with default values
func CreateWebSocketRequest(url string) *WebSocketRequest {
	return &WebSocketRequest{
		ID:        uuid.New(),
		URL:       url,
		Headers:   make([]Header, 0),
		Protocols: make([]string, 0),
		Metadata:  make(map[string]interface{}),
		CreatedAt: time.Now(),
	}
}

// AddHeader adds a header to the request
func (r *APIRequest) AddHeader(name, value string) {
	r.Headers = append(r.Headers, Header{Name: name, Value: value})
}

// GetHeader retrieves a header from the request
func (r *APIRequest) GetHeader(name string) (string, bool) {
	for _, header := range r.Headers {
		if header.Name == name {
			return header.Value, true
		}
	}
	return "", false
}

// AddQueryParam adds a query parameter to the request
func (r *APIRequest) AddQueryParam(name, value string) {
	r.QueryParams = append(r.QueryParams, QueryParam{Name: name, Value: value})
}

// GetQueryParam retrieves a query parameter from the request
func (r *APIRequest) GetQueryParam(name string) (string, bool) {
	for _, param := range r.QueryParams {
		if param.Name == name {
			return param.Value, true
		}
	}
	return "", false
}

// AddFormData adds form data to the request
func (r *APIRequest) AddFormData(name, value string) {
	r.FormData = append(r.FormData, FormData{Name: name, Value: value})
}

// AddFile adds a file to the request
func (r *APIRequest) AddFile(name, filename, contentType string, data []byte) {
	r.Files = append(r.Files, FileUpload{
		Name:        name,
		Filename:    filename,
		ContentType: contentType,
		Data:        data,
	})
}

// SetAuth sets authentication for the request
func (r *APIRequest) SetAuth(auth *Authentication) {
	r.Auth = auth
}

// SetTimeout sets timeout for the request
func (r *APIRequest) SetTimeout(timeout time.Duration) {
	r.Timeout = timeout
}

// SetRetries sets retry count for the request
func (r *APIRequest) SetRetries(retries int) {
	r.Retries = retries
}

// AddMetadata adds metadata to the request
func (r *APIRequest) AddMetadata(key string, value interface{}) {
	if r.Metadata == nil {
		r.Metadata = make(map[string]interface{})
	}
	r.Metadata[key] = value
}

// GetMetadata retrieves metadata from the request
func (r *APIRequest) GetMetadata(key string) (interface{}, bool) {
	if r.Metadata == nil {
		return nil, false
	}
	value, exists := r.Metadata[key]
	return value, exists
}

// AddHeader adds a header to the GraphQL request
func (r *GraphQLRequest) AddHeader(name, value string) {
	r.Headers = append(r.Headers, Header{Name: name, Value: value})
}

// GetHeader retrieves a header from the GraphQL request
func (r *GraphQLRequest) GetHeader(name string) (string, bool) {
	for _, header := range r.Headers {
		if header.Name == name {
			return header.Value, true
		}
	}
	return "", false
}

// AddVariable adds a variable to the GraphQL request
func (r *GraphQLRequest) AddVariable(name string, value interface{}) {
	if r.Variables == nil {
		r.Variables = make(map[string]interface{})
	}
	r.Variables[name] = value
}

// GetVariable retrieves a variable from the GraphQL request
func (r *GraphQLRequest) GetVariable(name string) (interface{}, bool) {
	if r.Variables == nil {
		return nil, false
	}
	value, exists := r.Variables[name]
	return value, exists
}

// SetAuth sets authentication for the GraphQL request
func (r *GraphQLRequest) SetAuth(auth *Authentication) {
	r.Auth = auth
}

// SetTimeout sets timeout for the GraphQL request
func (r *GraphQLRequest) SetTimeout(timeout time.Duration) {
	r.Timeout = timeout
}

// AddMetadata adds metadata to the GraphQL request
func (r *GraphQLRequest) AddMetadata(key string, value interface{}) {
	if r.Metadata == nil {
		r.Metadata = make(map[string]interface{})
	}
	r.Metadata[key] = value
}

// GetMetadata retrieves metadata from the GraphQL request
func (r *GraphQLRequest) GetMetadata(key string) (interface{}, bool) {
	if r.Metadata == nil {
		return nil, false
	}
	value, exists := r.Metadata[key]
	return value, exists
}

// AddMetadata adds metadata to the gRPC request
func (r *GRPCRequest) AddMetadata(key, value string) {
	if r.Metadata == nil {
		r.Metadata = make(map[string]string)
	}
	r.Metadata[key] = value
}

// GetMetadata retrieves metadata from the gRPC request
func (r *GRPCRequest) GetMetadata(key string) (string, bool) {
	if r.Metadata == nil {
		return "", false
	}
	value, exists := r.Metadata[key]
	return value, exists
}

// SetTimeout sets timeout for the gRPC request
func (r *GRPCRequest) SetTimeout(timeout time.Duration) {
	r.Timeout = timeout
}

// AddOption adds an option to the gRPC request
func (r *GRPCRequest) AddOption(key string, value interface{}) {
	if r.Options == nil {
		r.Options = make(map[string]interface{})
	}
	r.Options[key] = value
}

// GetOption retrieves an option from the gRPC request
func (r *GRPCRequest) GetOption(key string) (interface{}, bool) {
	if r.Options == nil {
		return nil, false
	}
	value, exists := r.Options[key]
	return value, exists
}

// AddHeader adds a header to the WebSocket request
func (r *WebSocketRequest) AddHeader(name, value string) {
	r.Headers = append(r.Headers, Header{Name: name, Value: value})
}

// GetHeader retrieves a header from the WebSocket request
func (r *WebSocketRequest) GetHeader(name string) (string, bool) {
	for _, header := range r.Headers {
		if header.Name == name {
			return header.Value, true
		}
	}
	return "", false
}

// AddProtocol adds a protocol to the WebSocket request
func (r *WebSocketRequest) AddProtocol(protocol string) {
	r.Protocols = append(r.Protocols, protocol)
}

// SetAuth sets authentication for the WebSocket request
func (r *WebSocketRequest) SetAuth(auth *Authentication) {
	r.Auth = auth
}

// SetTimeout sets timeout for the WebSocket request
func (r *WebSocketRequest) SetTimeout(timeout time.Duration) {
	r.Timeout = timeout
}

// AddMetadata adds metadata to the WebSocket request
func (r *WebSocketRequest) AddMetadata(key string, value interface{}) {
	if r.Metadata == nil {
		r.Metadata = make(map[string]interface{})
	}
	r.Metadata[key] = value
}

// GetMetadata retrieves metadata from the WebSocket request
func (r *WebSocketRequest) GetMetadata(key string) (interface{}, bool) {
	if r.Metadata == nil {
		return nil, false
	}
	value, exists := r.Metadata[key]
	return value, exists
}
