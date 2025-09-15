package types

import (
	"context"
	"time"
)

// EdgeProvider defines the interface for edge computing providers
type EdgeProvider interface {
	// Deploy deploys a microservice to the edge
	Deploy(ctx context.Context, req *DeployRequest) (*DeployResponse, error)

	// Undeploy removes a microservice from the edge
	Undeploy(ctx context.Context, req *UndeployRequest) error

	// Update updates an existing deployment
	Update(ctx context.Context, req *UpdateRequest) (*UpdateResponse, error)

	// GetDeployment returns deployment information
	GetDeployment(ctx context.Context, req *GetDeploymentRequest) (*DeploymentInfo, error)

	// ListDeployments lists all deployments
	ListDeployments(ctx context.Context) ([]*DeploymentInfo, error)

	// Invoke invokes a deployed function
	Invoke(ctx context.Context, req *InvokeRequest) (*InvokeResponse, error)

	// GetLogs retrieves logs from a deployment
	GetLogs(ctx context.Context, req *GetLogsRequest) (*LogsResponse, error)

	// GetMetrics retrieves metrics from a deployment
	GetMetrics(ctx context.Context, req *GetMetricsRequest) (*MetricsResponse, error)

	// GetProviderName returns the name of the provider
	GetProviderName() string

	// IsHealthy checks if the provider is healthy
	IsHealthy(ctx context.Context) error

	// GetSupportedRuntimes returns supported runtimes
	GetSupportedRuntimes() []string

	// GetSupportedRegions returns supported regions
	GetSupportedRegions() []string
}

// DeployRequest represents a deployment request
type DeployRequest struct {
	Name        string                 `json:"name"`
	Runtime     string                 `json:"runtime"`     // go, wasm, js, etc.
	Code        []byte                 `json:"code"`        // Compiled code/bytecode
	Handler     string                 `json:"handler"`     // Entry point function
	Environment map[string]string      `json:"environment"` // Environment variables
	Memory      int                    `json:"memory"`      // Memory limit in MB
	Timeout     time.Duration          `json:"timeout"`     // Execution timeout
	Region      string                 `json:"region"`      // Deployment region
	Triggers    []Trigger              `json:"triggers"`    // Event triggers
	Config      map[string]interface{} `json:"config"`      // Provider-specific config
}

// DeployResponse represents a deployment response
type DeployResponse struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Status     string     `json:"status"`
	URL        string     `json:"url,omitempty"`
	Region     string     `json:"region"`
	DeployedAt time.Time  `json:"deployed_at"`
	Version    string     `json:"version"`
	Error      *EdgeError `json:"error,omitempty"`
}

// UndeployRequest represents an undeploy request
type UndeployRequest struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// UpdateRequest represents an update request
type UpdateRequest struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Code        []byte                 `json:"code,omitempty"`
	Environment map[string]string      `json:"environment,omitempty"`
	Memory      int                    `json:"memory,omitempty"`
	Timeout     time.Duration          `json:"timeout,omitempty"`
	Config      map[string]interface{} `json:"config,omitempty"`
}

// UpdateResponse represents an update response
type UpdateResponse struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	Status    string     `json:"status"`
	UpdatedAt time.Time  `json:"updated_at"`
	Version   string     `json:"version"`
	Error     *EdgeError `json:"error,omitempty"`
}

// GetDeploymentRequest represents a get deployment request
type GetDeploymentRequest struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// DeploymentInfo represents deployment information
type DeploymentInfo struct {
	ID          string             `json:"id"`
	Name        string             `json:"name"`
	Runtime     string             `json:"runtime"`
	Status      string             `json:"status"`
	URL         string             `json:"url,omitempty"`
	Region      string             `json:"region"`
	Memory      int                `json:"memory"`
	Timeout     time.Duration      `json:"timeout"`
	Environment map[string]string  `json:"environment"`
	Triggers    []Trigger          `json:"triggers"`
	DeployedAt  time.Time          `json:"deployed_at"`
	UpdatedAt   time.Time          `json:"updated_at"`
	Version     string             `json:"version"`
	Metrics     *DeploymentMetrics `json:"metrics,omitempty"`
}

// Trigger represents an event trigger
type Trigger struct {
	Type    string                 `json:"type"` // http, cron, event, etc.
	Config  map[string]interface{} `json:"config"`
	Enabled bool                   `json:"enabled"`
}

// InvokeRequest represents an invoke request
type InvokeRequest struct {
	DeploymentID string            `json:"deployment_id"`
	Function     string            `json:"function,omitempty"`
	Payload      []byte            `json:"payload"`
	Headers      map[string]string `json:"headers,omitempty"`
	Async        bool              `json:"async,omitempty"`
}

// InvokeResponse represents an invoke response
type InvokeResponse struct {
	ID       string            `json:"id"`
	Status   string            `json:"status"`
	Result   []byte            `json:"result,omitempty"`
	Headers  map[string]string `json:"headers,omitempty"`
	Duration time.Duration     `json:"duration"`
	Error    *EdgeError        `json:"error,omitempty"`
	Logs     []string          `json:"logs,omitempty"`
}

// GetLogsRequest represents a get logs request
type GetLogsRequest struct {
	DeploymentID string    `json:"deployment_id"`
	StartTime    time.Time `json:"start_time,omitempty"`
	EndTime      time.Time `json:"end_time,omitempty"`
	Limit        int       `json:"limit,omitempty"`
	Level        string    `json:"level,omitempty"` // debug, info, warn, error
}

// LogsResponse represents a logs response
type LogsResponse struct {
	Logs  []LogEntry `json:"logs"`
	Total int        `json:"total"`
	Error *EdgeError `json:"error,omitempty"`
}

// LogEntry represents a log entry
type LogEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Level     string    `json:"level"`
	Message   string    `json:"message"`
	Source    string    `json:"source"`
	RequestID string    `json:"request_id,omitempty"`
}

// GetMetricsRequest represents a get metrics request
type GetMetricsRequest struct {
	DeploymentID string    `json:"deployment_id"`
	StartTime    time.Time `json:"start_time,omitempty"`
	EndTime      time.Time `json:"end_time,omitempty"`
	Granularity  string    `json:"granularity,omitempty"` // 1m, 5m, 1h, 1d
}

// MetricsResponse represents a metrics response
type MetricsResponse struct {
	Metrics DeploymentMetrics `json:"metrics"`
	Error   *EdgeError        `json:"error,omitempty"`
}

// DeploymentMetrics represents deployment metrics
type DeploymentMetrics struct {
	Invocations    int64     `json:"invocations"`
	Errors         int64     `json:"errors"`
	AvgDuration    float64   `json:"avg_duration_ms"`
	MaxDuration    float64   `json:"max_duration_ms"`
	MinDuration    float64   `json:"min_duration_ms"`
	MemoryUsage    float64   `json:"memory_usage_mb"`
	CPUUsage       float64   `json:"cpu_usage_percent"`
	ColdStarts     int64     `json:"cold_starts"`
	WarmStarts     int64     `json:"warm_starts"`
	LastInvocation time.Time `json:"last_invocation"`
	DataIn         int64     `json:"data_in_bytes"`
	DataOut        int64     `json:"data_out_bytes"`
}

// EdgeError represents an edge provider error
type EdgeError struct {
	Code    string                 `json:"code"`
	Message string                 `json:"message"`
	Type    string                 `json:"type"`
	Details map[string]interface{} `json:"details,omitempty"`
}

// ProviderConfig represents configuration for an edge provider
type ProviderConfig struct {
	Name          string                 `json:"name"`
	APIKey        string                 `json:"api_key,omitempty"`
	AccountID     string                 `json:"account_id,omitempty"`
	BaseURL       string                 `json:"base_url,omitempty"`
	Timeout       time.Duration          `json:"timeout,omitempty"`
	MaxRetries    int                    `json:"max_retries,omitempty"`
	Headers       map[string]string      `json:"headers,omitempty"`
	Regions       []string               `json:"regions,omitempty"`
	DefaultRegion string                 `json:"default_region,omitempty"`
	Config        map[string]interface{} `json:"config,omitempty"`
}

// HealthStatus represents the health status of a provider
type HealthStatus struct {
	Provider  string    `json:"provider"`
	Healthy   bool      `json:"healthy"`
	Message   string    `json:"message,omitempty"`
	CheckedAt time.Time `json:"checked_at"`
}

// ProviderStats represents statistics for a provider
type ProviderStats struct {
	Provider          string    `json:"provider"`
	TotalDeployments  int64     `json:"total_deployments"`
	TotalInvocations  int64     `json:"total_invocations"`
	SuccessRate       float64   `json:"success_rate"`
	AvgLatency        float64   `json:"avg_latency_ms"`
	LastUsed          time.Time `json:"last_used"`
	ActiveDeployments int64     `json:"active_deployments"`
}

// RuntimeInfo represents runtime information
type RuntimeInfo struct {
	Name        string        `json:"name"`
	Version     string        `json:"version"`
	Description string        `json:"description"`
	SupportedOS []string      `json:"supported_os"`
	MaxMemory   int           `json:"max_memory_mb"`
	MaxTimeout  time.Duration `json:"max_timeout"`
	Features    []string      `json:"features"`
}

// RegionInfo represents region information
type RegionInfo struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	Country     string  `json:"country"`
	Latitude    float64 `json:"latitude"`
	Longitude   float64 `json:"longitude"`
	Available   bool    `json:"available"`
	Description string  `json:"description,omitempty"`
}

// CompilationRequest represents a compilation request for WASM
type CompilationRequest struct {
	SourceCode   []byte                 `json:"source_code"`
	Language     string                 `json:"language"`     // go, rust, c, cpp, etc.
	Target       string                 `json:"target"`       // wasm32-unknown-unknown
	Optimization string                 `json:"optimization"` // size, speed, balanced
	Features     []string               `json:"features,omitempty"`
	Config       map[string]interface{} `json:"config,omitempty"`
}

// CompilationResponse represents a compilation response
type CompilationResponse struct {
	WasmCode     []byte     `json:"wasm_code"`
	Size         int64      `json:"size_bytes"`
	CompiledAt   time.Time  `json:"compiled_at"`
	Optimization string     `json:"optimization"`
	Features     []string   `json:"features"`
	Error        *EdgeError `json:"error,omitempty"`
}

// WASMRuntime represents a WASM runtime interface
type WASMRuntime interface {
	// Compile compiles source code to WASM
	Compile(ctx context.Context, req *CompilationRequest) (*CompilationResponse, error)

	// Execute executes WASM code
	Execute(ctx context.Context, wasmCode []byte, input []byte) ([]byte, error)

	// GetSupportedLanguages returns supported programming languages
	GetSupportedLanguages() []string

	// GetSupportedTargets returns supported compilation targets
	GetSupportedTargets() []string

	// IsHealthy checks if the runtime is healthy
	IsHealthy(ctx context.Context) error
}

// StreamCallback represents a callback function for streaming responses
type StreamCallback func(chunk *InvokeResponse) error

// DeploymentEvent represents a deployment event
type DeploymentEvent struct {
	Type         string      `json:"type"`
	DeploymentID string      `json:"deployment_id"`
	Timestamp    time.Time   `json:"timestamp"`
	Data         interface{} `json:"data"`
}

// EventCallback represents a callback function for deployment events
type EventCallback func(event *DeploymentEvent) error
