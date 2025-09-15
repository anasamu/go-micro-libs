package fastly

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/anasamu/go-micro-libs/edge/types"
)

// FastlyProvider implements the EdgeProvider interface for Fastly Compute
type FastlyProvider struct {
	config     *types.ProviderConfig
	httpClient *http.Client
	baseURL    string
}

// NewFastlyProvider creates a new Fastly provider
func NewFastlyProvider(config *types.ProviderConfig) *FastlyProvider {
	baseURL := "https://api.fastly.com"
	if config.BaseURL != "" {
		baseURL = config.BaseURL
	}

	timeout := 30 * time.Second
	if config.Timeout > 0 {
		timeout = config.Timeout
	}

	return &FastlyProvider{
		config: config,
		httpClient: &http.Client{
			Timeout: timeout,
		},
		baseURL: baseURL,
	}
}

// Deploy deploys a compute service to Fastly
func (p *FastlyProvider) Deploy(ctx context.Context, req *types.DeployRequest) (*types.DeployResponse, error) {
	// First, create a package
	packageResp, err := p.createPackage(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to create package: %w", err)
	}

	// Then, create a service
	serviceResp, err := p.createService(ctx, req, packageResp.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to create service: %w", err)
	}

	// Finally, activate the service
	activationResp, err := p.activateService(ctx, serviceResp.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to activate service: %w", err)
	}

	return &types.DeployResponse{
		ID:         serviceResp.ID,
		Name:       req.Name,
		Status:     "deployed",
		URL:        serviceResp.URL,
		Region:     req.Region,
		DeployedAt: time.Now(),
		Version:    activationResp.Version,
	}, nil
}

// createPackage creates a package with the compute code
func (p *FastlyProvider) createPackage(ctx context.Context, req *types.DeployRequest) (*PackageResponse, error) {
	// Create a multipart form to upload the package
	var _ bytes.Buffer

	// For simplicity, we'll create a basic package structure
	packageData := map[string]interface{}{
		"name":        req.Name,
		"description": "Compute service package",
		"language":    req.Runtime,
		"main":        req.Handler,
	}

	jsonData, err := json.Marshal(packageData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal package data: %w", err)
	}

	url := fmt.Sprintf("%s/packages", p.baseURL)
	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Fastly-Key", p.config.APIKey)

	resp, err := p.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to create package: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("package creation failed with status %d: %s", resp.StatusCode, string(body))
	}

	var packageResp PackageResponse
	if err := json.Unmarshal(body, &packageResp); err != nil {
		return nil, fmt.Errorf("failed to parse package response: %w", err)
	}

	return &packageResp, nil
}

// createService creates a compute service
func (p *FastlyProvider) createService(ctx context.Context, req *types.DeployRequest, packageID string) (*ServiceResponse, error) {
	serviceData := map[string]interface{}{
		"name":        req.Name,
		"description": "Compute service",
		"package_id":  packageID,
	}

	// Add environment variables
	if req.Environment != nil {
		serviceData["vars"] = req.Environment
	}

	// Add memory and timeout limits
	if req.Memory > 0 {
		serviceData["memory_limit"] = req.Memory
	}
	if req.Timeout > 0 {
		serviceData["timeout"] = int(req.Timeout.Milliseconds())
	}

	jsonData, err := json.Marshal(serviceData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal service data: %w", err)
	}

	url := fmt.Sprintf("%s/services", p.baseURL)
	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Fastly-Key", p.config.APIKey)

	resp, err := p.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to create service: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("service creation failed with status %d: %s", resp.StatusCode, string(body))
	}

	var serviceResp ServiceResponse
	if err := json.Unmarshal(body, &serviceResp); err != nil {
		return nil, fmt.Errorf("failed to parse service response: %w", err)
	}

	// Set the service URL
	serviceResp.URL = fmt.Sprintf("https://%s.fastly-edge.com", serviceResp.ID)

	return &serviceResp, nil
}

// activateService activates a compute service
func (p *FastlyProvider) activateService(ctx context.Context, serviceID string) (*ActivationResponse, error) {
	url := fmt.Sprintf("%s/services/%s/versions", p.baseURL, serviceID)
	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Fastly-Key", p.config.APIKey)

	resp, err := p.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to activate service: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("service activation failed with status %d: %s", resp.StatusCode, string(body))
	}

	var activationResp ActivationResponse
	if err := json.Unmarshal(body, &activationResp); err != nil {
		return nil, fmt.Errorf("failed to parse activation response: %w", err)
	}

	return &activationResp, nil
}

// Undeploy removes a compute service from Fastly
func (p *FastlyProvider) Undeploy(ctx context.Context, req *types.UndeployRequest) error {
	url := fmt.Sprintf("%s/services/%s", p.baseURL, req.ID)

	httpReq, err := http.NewRequestWithContext(ctx, "DELETE", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Fastly-Key", p.config.APIKey)

	resp, err := p.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("failed to undeploy service: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("undeploy failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// Update updates an existing compute service deployment
func (p *FastlyProvider) Update(ctx context.Context, req *types.UpdateRequest) (*types.UpdateResponse, error) {
	// Get current service info
	serviceInfo, err := p.getServiceInfo(ctx, req.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to get service info: %w", err)
	}

	// Update service configuration
	updateData := make(map[string]interface{})

	if req.Environment != nil {
		updateData["vars"] = req.Environment
	}

	if req.Memory > 0 {
		updateData["memory_limit"] = req.Memory
	}

	if req.Timeout > 0 {
		updateData["timeout"] = int(req.Timeout.Milliseconds())
	}

	if len(updateData) == 0 {
		return &types.UpdateResponse{
			ID:        req.ID,
			Name:      req.Name,
			Status:    "updated",
			UpdatedAt: time.Now(),
			Version:   serviceInfo.Version,
		}, nil
	}

	jsonData, err := json.Marshal(updateData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal update data: %w", err)
	}

	url := fmt.Sprintf("%s/services/%s", p.baseURL, req.ID)
	httpReq, err := http.NewRequestWithContext(ctx, "PATCH", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Fastly-Key", p.config.APIKey)

	resp, err := p.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to update service: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return &types.UpdateResponse{
			Error: &types.EdgeError{
				Code:    fmt.Sprintf("HTTP_%d", resp.StatusCode),
				Message: fmt.Sprintf("update failed: %s", string(body)),
				Type:    "update_error",
			},
		}, nil
	}

	return &types.UpdateResponse{
		ID:        req.ID,
		Name:      req.Name,
		Status:    "updated",
		UpdatedAt: time.Now(),
		Version:   serviceInfo.Version,
	}, nil
}

// getServiceInfo gets service information
func (p *FastlyProvider) getServiceInfo(ctx context.Context, serviceID string) (*ServiceInfo, error) {
	url := fmt.Sprintf("%s/services/%s", p.baseURL, serviceID)

	httpReq, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Fastly-Key", p.config.APIKey)

	resp, err := p.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to get service info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("service not found")
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get service info with status %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var serviceInfo ServiceInfo
	if err := json.Unmarshal(body, &serviceInfo); err != nil {
		return nil, fmt.Errorf("failed to parse service info: %w", err)
	}

	return &serviceInfo, nil
}

// GetDeployment returns deployment information
func (p *FastlyProvider) GetDeployment(ctx context.Context, req *types.GetDeploymentRequest) (*types.DeploymentInfo, error) {
	serviceInfo, err := p.getServiceInfo(ctx, req.ID)
	if err != nil {
		return nil, err
	}

	// Convert environment variables
	environment := make(map[string]string)
	for k, v := range serviceInfo.Vars {
		if str, ok := v.(string); ok {
			environment[k] = str
		}
	}

	return &types.DeploymentInfo{
		ID:          serviceInfo.ID,
		Name:        serviceInfo.Name,
		Runtime:     serviceInfo.Language,
		Status:      "deployed",
		URL:         serviceInfo.URL,
		Memory:      serviceInfo.MemoryLimit,
		Timeout:     time.Duration(serviceInfo.Timeout) * time.Millisecond,
		Environment: environment,
		DeployedAt:  serviceInfo.CreatedAt,
		UpdatedAt:   serviceInfo.UpdatedAt,
		Version:     serviceInfo.Version,
	}, nil
}

// ListDeployments lists all deployments
func (p *FastlyProvider) ListDeployments(ctx context.Context) ([]*types.DeploymentInfo, error) {
	url := fmt.Sprintf("%s/services", p.baseURL)

	httpReq, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Fastly-Key", p.config.APIKey)

	resp, err := p.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to list services: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to list services with status %d: %w", resp.StatusCode, err)
	}

	var servicesResp struct {
		Services []ServiceInfo `json:"services"`
	}

	if err := json.Unmarshal(body, &servicesResp); err != nil {
		return nil, fmt.Errorf("failed to parse services response: %w", err)
	}

	deployments := make([]*types.DeploymentInfo, len(servicesResp.Services))
	for i, service := range servicesResp.Services {
		// Convert environment variables
		environment := make(map[string]string)
		for k, v := range service.Vars {
			if str, ok := v.(string); ok {
				environment[k] = str
			}
		}

		deployments[i] = &types.DeploymentInfo{
			ID:          service.ID,
			Name:        service.Name,
			Runtime:     service.Language,
			Status:      "deployed",
			URL:         service.URL,
			Memory:      service.MemoryLimit,
			Timeout:     time.Duration(service.Timeout) * time.Millisecond,
			Environment: environment,
			DeployedAt:  service.CreatedAt,
			UpdatedAt:   service.UpdatedAt,
			Version:     service.Version,
		}
	}

	return deployments, nil
}

// Invoke invokes a deployed compute service
func (p *FastlyProvider) Invoke(ctx context.Context, req *types.InvokeRequest) (*types.InvokeResponse, error) {
	// Get deployment info to construct URL
	deploymentReq := &types.GetDeploymentRequest{
		ID: req.DeploymentID,
	}

	deployment, err := p.GetDeployment(ctx, deploymentReq)
	if err != nil {
		return nil, fmt.Errorf("failed to get deployment: %w", err)
	}

	// Construct the service URL
	url := deployment.URL
	if req.Function != "" {
		url = fmt.Sprintf("%s/%s", url, req.Function)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(req.Payload))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	httpReq.Header.Set("Content-Type", "application/json")
	for k, v := range req.Headers {
		httpReq.Header.Set(k, v)
	}

	start := time.Now()
	resp, err := p.httpClient.Do(httpReq)
	duration := time.Since(start)

	if err != nil {
		return nil, fmt.Errorf("failed to invoke service: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Convert headers
	headers := make(map[string]string)
	for k, v := range resp.Header {
		if len(v) > 0 {
			headers[k] = v[0]
		}
	}

	status := "success"
	if resp.StatusCode >= 400 {
		status = "error"
	}

	response := &types.InvokeResponse{
		ID:       fmt.Sprintf("%d", time.Now().UnixNano()),
		Status:   status,
		Result:   body,
		Headers:  headers,
		Duration: duration,
	}

	if resp.StatusCode >= 400 {
		response.Error = &types.EdgeError{
			Code:    fmt.Sprintf("HTTP_%d", resp.StatusCode),
			Message: string(body),
			Type:    "invocation_error",
		}
	}

	return response, nil
}

// GetLogs retrieves logs from a deployment
func (p *FastlyProvider) GetLogs(ctx context.Context, req *types.GetLogsRequest) (*types.LogsResponse, error) {
	// Fastly Compute logs are available through the Real-time Analytics API
	url := fmt.Sprintf("%s/services/%s/logs", p.baseURL, req.DeploymentID)

	httpReq, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Fastly-Key", p.config.APIKey)

	resp, err := p.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to get logs: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return &types.LogsResponse{
			Logs:  []types.LogEntry{},
			Total: 0,
		}, nil
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get logs with status %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Parse logs response
	var logsResp struct {
		Logs []struct {
			Timestamp string `json:"timestamp"`
			Level     string `json:"level"`
			Message   string `json:"message"`
		} `json:"logs"`
	}

	if err := json.Unmarshal(body, &logsResp); err != nil {
		return nil, fmt.Errorf("failed to parse logs response: %w", err)
	}

	logs := make([]types.LogEntry, len(logsResp.Logs))
	for i, log := range logsResp.Logs {
		timestamp, _ := time.Parse(time.RFC3339, log.Timestamp)
		logs[i] = types.LogEntry{
			Timestamp: timestamp,
			Level:     log.Level,
			Message:   log.Message,
			Source:    "fastly-compute",
		}
	}

	return &types.LogsResponse{
		Logs:  logs,
		Total: len(logs),
	}, nil
}

// GetMetrics retrieves metrics from a deployment
func (p *FastlyProvider) GetMetrics(ctx context.Context, req *types.GetMetricsRequest) (*types.MetricsResponse, error) {
	// Fastly Compute metrics are available through the Real-time Analytics API
	url := fmt.Sprintf("%s/services/%s/stats", p.baseURL, req.DeploymentID)

	httpReq, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Fastly-Key", p.config.APIKey)

	resp, err := p.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to get metrics: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get metrics with status %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Parse metrics response
	var metricsResp struct {
		Stats struct {
			Invocations int64   `json:"invocations"`
			Errors      int64   `json:"errors"`
			AvgDuration float64 `json:"avg_duration_ms"`
			MaxDuration float64 `json:"max_duration_ms"`
			MinDuration float64 `json:"min_duration_ms"`
		} `json:"stats"`
	}

	if err := json.Unmarshal(body, &metricsResp); err != nil {
		return nil, fmt.Errorf("failed to parse metrics response: %w", err)
	}

	metrics := types.DeploymentMetrics{
		Invocations:    metricsResp.Stats.Invocations,
		Errors:         metricsResp.Stats.Errors,
		AvgDuration:    metricsResp.Stats.AvgDuration,
		MaxDuration:    metricsResp.Stats.MaxDuration,
		MinDuration:    metricsResp.Stats.MinDuration,
		LastInvocation: time.Now(),
	}

	return &types.MetricsResponse{
		Metrics: metrics,
	}, nil
}

// GetProviderName returns the name of the provider
func (p *FastlyProvider) GetProviderName() string {
	return "fastly"
}

// IsHealthy checks if the provider is healthy
func (p *FastlyProvider) IsHealthy(ctx context.Context) error {
	url := fmt.Sprintf("%s/user", p.baseURL)

	httpReq, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create health check request: %w", err)
	}

	httpReq.Header.Set("Fastly-Key", p.config.APIKey)

	resp, err := p.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("health check failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health check failed with status %d", resp.StatusCode)
	}

	return nil
}

// GetSupportedRuntimes returns supported runtimes
func (p *FastlyProvider) GetSupportedRuntimes() []string {
	return []string{"rust", "javascript", "typescript", "go", "wasm"}
}

// GetSupportedRegions returns supported regions
func (p *FastlyProvider) GetSupportedRegions() []string {
	return []string{
		"global", "us-east", "us-west", "eu-west", "eu-central",
		"ap-southeast", "ap-northeast", "ap-south", "sa-east",
	}
}

// PackageResponse represents a Fastly package response
type PackageResponse struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// ServiceResponse represents a Fastly service response
type ServiceResponse struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	URL  string `json:"url"`
}

// ActivationResponse represents a Fastly activation response
type ActivationResponse struct {
	Version string `json:"version"`
}

// ServiceInfo represents Fastly service information
type ServiceInfo struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Language    string                 `json:"language"`
	MemoryLimit int                    `json:"memory_limit"`
	Timeout     int                    `json:"timeout"`
	Vars        map[string]interface{} `json:"vars"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
	Version     string                 `json:"version"`
	URL         string                 `json:"url"`
}
