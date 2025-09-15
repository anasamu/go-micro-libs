package cloudflare

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

// CloudflareProvider implements the EdgeProvider interface for Cloudflare Workers
type CloudflareProvider struct {
	config     *types.ProviderConfig
	httpClient *http.Client
	baseURL    string
}

// NewCloudflareProvider creates a new Cloudflare provider
func NewCloudflareProvider(config *types.ProviderConfig) *CloudflareProvider {
	baseURL := "https://api.cloudflare.com/client/v4"
	if config.BaseURL != "" {
		baseURL = config.BaseURL
	}

	timeout := 30 * time.Second
	if config.Timeout > 0 {
		timeout = config.Timeout
	}

	return &CloudflareProvider{
		config: config,
		httpClient: &http.Client{
			Timeout: timeout,
		},
		baseURL: baseURL,
	}
}

// Deploy deploys a worker to Cloudflare
func (p *CloudflareProvider) Deploy(ctx context.Context, req *types.DeployRequest) (*types.DeployResponse, error) {
	// Prepare the request payload
	payload := map[string]interface{}{
		"name":                req.Name,
		"main_module":         "worker.js",
		"compatibility_date":  "2024-01-01",
		"compatibility_flags": []string{"nodejs_compat"},
	}

	if req.Environment != nil {
		payload["vars"] = req.Environment
	}

	if req.Memory > 0 {
		payload["limits"] = map[string]interface{}{
			"cpu_ms": int(req.Timeout.Milliseconds()),
		}
	}

	// Add triggers
	if len(req.Triggers) > 0 {
		routes := make([]string, 0)
		for _, trigger := range req.Triggers {
			if trigger.Type == "http" && trigger.Enabled {
				if route, ok := trigger.Config["route"].(string); ok {
					routes = append(routes, route)
				}
			}
		}
		if len(routes) > 0 {
			payload["routes"] = routes
		}
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %w", err)
	}

	// Create the request
	url := fmt.Sprintf("%s/accounts/%s/workers/scripts/%s", p.baseURL, p.config.AccountID, req.Name)
	httpReq, err := http.NewRequestWithContext(ctx, "PUT", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+p.config.APIKey)

	// Upload the worker script
	if len(req.Code) > 0 {
		scriptReq, err := http.NewRequestWithContext(ctx, "PUT", url, bytes.NewReader(req.Code))
		if err != nil {
			return nil, fmt.Errorf("failed to create script upload request: %w", err)
		}

		scriptReq.Header.Set("Content-Type", "application/javascript")
		scriptReq.Header.Set("Authorization", "Bearer "+p.config.APIKey)

		resp, err := p.httpClient.Do(scriptReq)
		if err != nil {
			return nil, fmt.Errorf("failed to upload script: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			return nil, fmt.Errorf("script upload failed with status %d: %s", resp.StatusCode, string(body))
		}
	}

	// Deploy the worker
	resp, err := p.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to deploy worker: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return &types.DeployResponse{
			Error: &types.EdgeError{
				Code:    fmt.Sprintf("HTTP_%d", resp.StatusCode),
				Message: fmt.Sprintf("deployment failed: %s", string(body)),
				Type:    "deployment_error",
			},
		}, nil
	}

	// Parse response
	var cloudflareResp struct {
		Success bool `json:"success"`
		Result  struct {
			ID  string `json:"id"`
			Tag string `json:"tag"`
		} `json:"result"`
		Errors []struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"errors"`
	}

	if err := json.Unmarshal(body, &cloudflareResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	if !cloudflareResp.Success {
		if len(cloudflareResp.Errors) > 0 {
			return &types.DeployResponse{
				Error: &types.EdgeError{
					Code:    fmt.Sprintf("CLOUDFLARE_%d", cloudflareResp.Errors[0].Code),
					Message: cloudflareResp.Errors[0].Message,
					Type:    "cloudflare_error",
				},
			}, nil
		}
		return &types.DeployResponse{
			Error: &types.EdgeError{
				Code:    "DEPLOYMENT_FAILED",
				Message: "deployment failed",
				Type:    "deployment_error",
			},
		}, nil
	}

	// Get worker URL
	workerURL := fmt.Sprintf("https://%s.%s.workers.dev", req.Name, p.config.AccountID)

	return &types.DeployResponse{
		ID:         cloudflareResp.Result.ID,
		Name:       req.Name,
		Status:     "deployed",
		URL:        workerURL,
		Region:     req.Region,
		DeployedAt: time.Now(),
		Version:    cloudflareResp.Result.Tag,
	}, nil
}

// Undeploy removes a worker from Cloudflare
func (p *CloudflareProvider) Undeploy(ctx context.Context, req *types.UndeployRequest) error {
	url := fmt.Sprintf("%s/accounts/%s/workers/scripts/%s", p.baseURL, p.config.AccountID, req.Name)

	httpReq, err := http.NewRequestWithContext(ctx, "DELETE", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Authorization", "Bearer "+p.config.APIKey)

	resp, err := p.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("failed to undeploy worker: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("undeploy failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// Update updates an existing worker deployment
func (p *CloudflareProvider) Update(ctx context.Context, req *types.UpdateRequest) (*types.UpdateResponse, error) {
	// First get the current deployment
	deploymentReq := &types.GetDeploymentRequest{
		ID:   req.ID,
		Name: req.Name,
	}

	currentDeployment, err := p.GetDeployment(ctx, deploymentReq)
	if err != nil {
		return nil, fmt.Errorf("failed to get current deployment: %w", err)
	}

	// Prepare update payload
	payload := map[string]interface{}{}

	if len(req.Code) > 0 {
		// Upload new script
		url := fmt.Sprintf("%s/accounts/%s/workers/scripts/%s", p.baseURL, p.config.AccountID, req.Name)
		scriptReq, err := http.NewRequestWithContext(ctx, "PUT", url, bytes.NewReader(req.Code))
		if err != nil {
			return nil, fmt.Errorf("failed to create script upload request: %w", err)
		}

		scriptReq.Header.Set("Content-Type", "application/javascript")
		scriptReq.Header.Set("Authorization", "Bearer "+p.config.APIKey)

		resp, err := p.httpClient.Do(scriptReq)
		if err != nil {
			return nil, fmt.Errorf("failed to upload script: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			return nil, fmt.Errorf("script upload failed with status %d: %s", resp.StatusCode, string(body))
		}
	}

	if req.Environment != nil {
		payload["vars"] = req.Environment
	}

	if req.Memory > 0 {
		payload["limits"] = map[string]interface{}{
			"cpu_ms": int(req.Timeout.Milliseconds()),
		}
	}

	if len(payload) == 0 {
		return &types.UpdateResponse{
			ID:        req.ID,
			Name:      req.Name,
			Status:    "updated",
			UpdatedAt: time.Now(),
			Version:   currentDeployment.Version,
		}, nil
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %w", err)
	}

	// Update the worker configuration
	url := fmt.Sprintf("%s/accounts/%s/workers/scripts/%s", p.baseURL, p.config.AccountID, req.Name)
	httpReq, err := http.NewRequestWithContext(ctx, "PATCH", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+p.config.APIKey)

	resp, err := p.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to update worker: %w", err)
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
		Version:   currentDeployment.Version,
	}, nil
}

// GetDeployment returns deployment information
func (p *CloudflareProvider) GetDeployment(ctx context.Context, req *types.GetDeploymentRequest) (*types.DeploymentInfo, error) {
	url := fmt.Sprintf("%s/accounts/%s/workers/scripts/%s", p.baseURL, p.config.AccountID, req.Name)

	httpReq, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Authorization", "Bearer "+p.config.APIKey)

	resp, err := p.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to get deployment: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("deployment not found")
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get deployment with status %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var cloudflareResp struct {
		Success bool `json:"success"`
		Result  struct {
			ID         string                 `json:"id"`
			Tag        string                 `json:"tag"`
			CreatedOn  string                 `json:"created_on"`
			ModifiedOn string                 `json:"modified_on"`
			Vars       map[string]interface{} `json:"vars"`
		} `json:"result"`
	}

	if err := json.Unmarshal(body, &cloudflareResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	if !cloudflareResp.Success {
		return nil, fmt.Errorf("failed to get deployment information")
	}

	// Convert environment variables
	environment := make(map[string]string)
	for k, v := range cloudflareResp.Result.Vars {
		if str, ok := v.(string); ok {
			environment[k] = str
		}
	}

	// Parse timestamps
	createdAt, _ := time.Parse(time.RFC3339, cloudflareResp.Result.CreatedOn)
	modifiedAt, _ := time.Parse(time.RFC3339, cloudflareResp.Result.ModifiedOn)

	workerURL := fmt.Sprintf("https://%s.%s.workers.dev", req.Name, p.config.AccountID)

	return &types.DeploymentInfo{
		ID:          cloudflareResp.Result.ID,
		Name:        req.Name,
		Runtime:     "javascript",
		Status:      "deployed",
		URL:         workerURL,
		Environment: environment,
		DeployedAt:  createdAt,
		UpdatedAt:   modifiedAt,
		Version:     cloudflareResp.Result.Tag,
	}, nil
}

// ListDeployments lists all deployments
func (p *CloudflareProvider) ListDeployments(ctx context.Context) ([]*types.DeploymentInfo, error) {
	url := fmt.Sprintf("%s/accounts/%s/workers/scripts", p.baseURL, p.config.AccountID)

	httpReq, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Authorization", "Bearer "+p.config.APIKey)

	resp, err := p.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to list deployments: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to list deployments with status %d: %s", resp.StatusCode, string(body))
	}

	var cloudflareResp struct {
		Success bool `json:"success"`
		Result  []struct {
			ID         string `json:"id"`
			Name       string `json:"name"`
			Tag        string `json:"tag"`
			CreatedOn  string `json:"created_on"`
			ModifiedOn string `json:"modified_on"`
		} `json:"result"`
	}

	if err := json.Unmarshal(body, &cloudflareResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	if !cloudflareResp.Success {
		return nil, fmt.Errorf("failed to list deployments")
	}

	deployments := make([]*types.DeploymentInfo, len(cloudflareResp.Result))
	for i, result := range cloudflareResp.Result {
		createdAt, _ := time.Parse(time.RFC3339, result.CreatedOn)
		modifiedAt, _ := time.Parse(time.RFC3339, result.ModifiedOn)

		workerURL := fmt.Sprintf("https://%s.%s.workers.dev", result.Name, p.config.AccountID)

		deployments[i] = &types.DeploymentInfo{
			ID:         result.ID,
			Name:       result.Name,
			Runtime:    "javascript",
			Status:     "deployed",
			URL:        workerURL,
			DeployedAt: createdAt,
			UpdatedAt:  modifiedAt,
			Version:    result.Tag,
		}
	}

	return deployments, nil
}

// Invoke invokes a deployed worker
func (p *CloudflareProvider) Invoke(ctx context.Context, req *types.InvokeRequest) (*types.InvokeResponse, error) {
	// Get deployment info to construct URL
	deploymentReq := &types.GetDeploymentRequest{
		ID: req.DeploymentID,
	}

	deployment, err := p.GetDeployment(ctx, deploymentReq)
	if err != nil {
		return nil, fmt.Errorf("failed to get deployment: %w", err)
	}

	// Construct the worker URL
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
		return nil, fmt.Errorf("failed to invoke worker: %w", err)
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
func (p *CloudflareProvider) GetLogs(ctx context.Context, req *types.GetLogsRequest) (*types.LogsResponse, error) {
	// Cloudflare Workers logs are available through the Analytics API
	url := fmt.Sprintf("%s/accounts/%s/workers/scripts/%s/analytics", p.baseURL, p.config.AccountID, req.DeploymentID)

	httpReq, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Authorization", "Bearer "+p.config.APIKey)

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
		Success bool `json:"success"`
		Result  []struct {
			Timestamp string `json:"timestamp"`
			Level     string `json:"level"`
			Message   string `json:"message"`
		} `json:"result"`
	}

	if err := json.Unmarshal(body, &logsResp); err != nil {
		return nil, fmt.Errorf("failed to parse logs response: %w", err)
	}

	logs := make([]types.LogEntry, len(logsResp.Result))
	for i, log := range logsResp.Result {
		timestamp, _ := time.Parse(time.RFC3339, log.Timestamp)
		logs[i] = types.LogEntry{
			Timestamp: timestamp,
			Level:     log.Level,
			Message:   log.Message,
			Source:    "cloudflare-worker",
		}
	}

	return &types.LogsResponse{
		Logs:  logs,
		Total: len(logs),
	}, nil
}

// GetMetrics retrieves metrics from a deployment
func (p *CloudflareProvider) GetMetrics(ctx context.Context, req *types.GetMetricsRequest) (*types.MetricsResponse, error) {
	// Cloudflare Workers metrics are available through the Analytics API
	url := fmt.Sprintf("%s/accounts/%s/workers/scripts/%s/analytics", p.baseURL, p.config.AccountID, req.DeploymentID)

	httpReq, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Authorization", "Bearer "+p.config.APIKey)

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
		Success bool `json:"success"`
		Result  struct {
			Invocations int64   `json:"invocations"`
			Errors      int64   `json:"errors"`
			AvgDuration float64 `json:"avg_duration_ms"`
			MaxDuration float64 `json:"max_duration_ms"`
			MinDuration float64 `json:"min_duration_ms"`
		} `json:"result"`
	}

	if err := json.Unmarshal(body, &metricsResp); err != nil {
		return nil, fmt.Errorf("failed to parse metrics response: %w", err)
	}

	metrics := types.DeploymentMetrics{
		Invocations:    metricsResp.Result.Invocations,
		Errors:         metricsResp.Result.Errors,
		AvgDuration:    metricsResp.Result.AvgDuration,
		MaxDuration:    metricsResp.Result.MaxDuration,
		MinDuration:    metricsResp.Result.MinDuration,
		LastInvocation: time.Now(),
	}

	return &types.MetricsResponse{
		Metrics: metrics,
	}, nil
}

// GetProviderName returns the name of the provider
func (p *CloudflareProvider) GetProviderName() string {
	return "cloudflare"
}

// IsHealthy checks if the provider is healthy
func (p *CloudflareProvider) IsHealthy(ctx context.Context) error {
	url := fmt.Sprintf("%s/accounts/%s", p.baseURL, p.config.AccountID)

	httpReq, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create health check request: %w", err)
	}

	httpReq.Header.Set("Authorization", "Bearer "+p.config.APIKey)

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
func (p *CloudflareProvider) GetSupportedRuntimes() []string {
	return []string{"javascript", "typescript", "wasm", "rust", "go"}
}

// GetSupportedRegions returns supported regions
func (p *CloudflareProvider) GetSupportedRegions() []string {
	return []string{
		"global", "us-east", "us-west", "eu-west", "eu-central",
		"ap-southeast", "ap-northeast", "ap-south", "sa-east",
	}
}
