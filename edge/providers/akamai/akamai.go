package akamai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/anasamu/go-micro-libs/edge/types"
)

// AkamaiProvider implements the EdgeProvider interface for Akamai EdgeWorkers
type AkamaiProvider struct {
	config     *types.ProviderConfig
	httpClient *http.Client
	baseURL    string
}

// NewAkamaiProvider creates a new Akamai provider
func NewAkamaiProvider(config *types.ProviderConfig) *AkamaiProvider {
	baseURL := "https://api.akamai.com"
	if config.BaseURL != "" {
		baseURL = config.BaseURL
	}

	timeout := 30 * time.Second
	if config.Timeout > 0 {
		timeout = config.Timeout
	}

	return &AkamaiProvider{
		config: config,
		httpClient: &http.Client{
			Timeout: timeout,
		},
		baseURL: baseURL,
	}
}

// Deploy deploys an EdgeWorker to Akamai
func (p *AkamaiProvider) Deploy(ctx context.Context, req *types.DeployRequest) (*types.DeployResponse, error) {
	// First, create an EdgeWorker
	workerResp, err := p.createEdgeWorker(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to create EdgeWorker: %w", err)
	}

	// Then, create a version with the code
	versionResp, err := p.createVersion(ctx, workerResp.EdgeWorkerID, req)
	if err != nil {
		return nil, fmt.Errorf("failed to create version: %w", err)
	}

	// Finally, activate the version
	activationResp, err := p.activateVersion(ctx, workerResp.EdgeWorkerID, versionResp.Version)
	if err != nil {
		return nil, fmt.Errorf("failed to activate version: %w", err)
	}

	return &types.DeployResponse{
		ID:         fmt.Sprintf("%d", workerResp.EdgeWorkerID),
		Name:       req.Name,
		Status:     "deployed",
		URL:        activationResp.URL,
		Region:     req.Region,
		DeployedAt: time.Now(),
		Version:    versionResp.Version,
	}, nil
}

// createEdgeWorker creates an EdgeWorker
func (p *AkamaiProvider) createEdgeWorker(ctx context.Context, req *types.DeployRequest) (*EdgeWorkerResponse, error) {
	workerData := map[string]interface{}{
		"name":         req.Name,
		"groupID":      p.config.AccountID, // Using AccountID as groupID
		"resourceTier": "STANDARD",
	}

	jsonData, err := json.Marshal(workerData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal worker data: %w", err)
	}

	url := fmt.Sprintf("%s/edgeworkers/v1/ids", p.baseURL)
	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+p.config.APIKey)

	resp, err := p.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to create EdgeWorker: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("EdgeWorker creation failed with status %d: %s", resp.StatusCode, string(body))
	}

	var workerResp EdgeWorkerResponse
	if err := json.Unmarshal(body, &workerResp); err != nil {
		return nil, fmt.Errorf("failed to parse EdgeWorker response: %w", err)
	}

	return &workerResp, nil
}

// createVersion creates a version with code
func (p *AkamaiProvider) createVersion(ctx context.Context, edgeWorkerID int, req *types.DeployRequest) (*VersionResponse, error) {
	// Create a version
	versionData := map[string]interface{}{
		"edgeWorkerId": edgeWorkerID,
		"version":      "1.0.0",
	}

	jsonData, err := json.Marshal(versionData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal version data: %w", err)
	}

	url := fmt.Sprintf("%s/edgeworkers/v1/ids/%d/versions", p.baseURL, edgeWorkerID)
	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create version request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+p.config.APIKey)

	resp, err := p.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to create version: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("version creation failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Upload the bundle
	if len(req.Code) > 0 {
		if err := p.uploadBundle(ctx, edgeWorkerID, "1.0.0", string(req.Code)); err != nil {
			return nil, fmt.Errorf("failed to upload bundle: %w", err)
		}
	}

	return &VersionResponse{
		Version: "1.0.0",
	}, nil
}

// uploadBundle uploads the EdgeWorker bundle
func (p *AkamaiProvider) uploadBundle(ctx context.Context, edgeWorkerID int, version, bundleData string) error {
	url := fmt.Sprintf("%s/edgeworkers/v1/ids/%d/versions/%s/content", p.baseURL, edgeWorkerID, version)

	// For simplicity, we'll create a basic bundle structure
	// In a real implementation, you would create a proper EdgeWorker bundle
	bundle := []byte(bundleData)

	httpReq, err := http.NewRequestWithContext(ctx, "PUT", url, bytes.NewReader(bundle))
	if err != nil {
		return fmt.Errorf("failed to create bundle upload request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/gzip")
	httpReq.Header.Set("Authorization", "Bearer "+p.config.APIKey)

	resp, err := p.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("failed to upload bundle: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("bundle upload failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// activateVersion activates a version
func (p *AkamaiProvider) activateVersion(ctx context.Context, edgeWorkerID int, version string) (*ActivationResponse, error) {
	activationData := map[string]interface{}{
		"network": "STAGING", // Start with staging, can be promoted to production
	}

	jsonData, err := json.Marshal(activationData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal activation data: %w", err)
	}

	url := fmt.Sprintf("%s/edgeworkers/v1/ids/%d/versions/%s/activations", p.baseURL, edgeWorkerID, version)
	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create activation request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+p.config.APIKey)

	resp, err := p.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to activate version: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("version activation failed with status %d: %s", resp.StatusCode, string(body))
	}

	var activationResp ActivationResponse
	if err := json.Unmarshal(body, &activationResp); err != nil {
		return nil, fmt.Errorf("failed to parse activation response: %w", err)
	}

	// Set a placeholder URL since Akamai EdgeWorkers don't have direct URLs
	activationResp.URL = fmt.Sprintf("https://edgeworker-%d.akamai.com", edgeWorkerID)

	return &activationResp, nil
}

// Undeploy removes an EdgeWorker from Akamai
func (p *AkamaiProvider) Undeploy(ctx context.Context, req *types.UndeployRequest) error {
	url := fmt.Sprintf("%s/edgeworkers/v1/ids/%s", p.baseURL, req.ID)

	httpReq, err := http.NewRequestWithContext(ctx, "DELETE", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Authorization", "Bearer "+p.config.APIKey)

	resp, err := p.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("failed to undeploy EdgeWorker: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusNotFound {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("undeploy failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// Update updates an existing EdgeWorker deployment
func (p *AkamaiProvider) Update(ctx context.Context, req *types.UpdateRequest) (*types.UpdateResponse, error) {
	// Get current EdgeWorker info
	workerInfo, err := p.getEdgeWorkerInfo(ctx, req.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to get EdgeWorker info: %w", err)
	}

	// Create a new version if code is provided
	if len(req.Code) > 0 {
		newVersion := fmt.Sprintf("%d.0.0", time.Now().Unix())

		// Create new version
		versionData := map[string]interface{}{
			"edgeWorkerId": req.ID,
			"version":      newVersion,
		}

		jsonData, err := json.Marshal(versionData)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal version data: %w", err)
		}

		url := fmt.Sprintf("%s/edgeworkers/v1/ids/%s/versions", p.baseURL, req.ID)
		httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonData))
		if err != nil {
			return nil, fmt.Errorf("failed to create version request: %w", err)
		}

		httpReq.Header.Set("Content-Type", "application/json")
		httpReq.Header.Set("Authorization", "Bearer "+p.config.APIKey)

		resp, err := p.httpClient.Do(httpReq)
		if err != nil {
			return nil, fmt.Errorf("failed to create version: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusCreated {
			body, _ := io.ReadAll(resp.Body)
			return &types.UpdateResponse{
				Error: &types.EdgeError{
					Code:    fmt.Sprintf("HTTP_%d", resp.StatusCode),
					Message: fmt.Sprintf("version creation failed: %s", string(body)),
					Type:    "update_error",
				},
			}, nil
		}

		// Upload new bundle
		workerID, err := strconv.Atoi(req.ID)
		if err != nil {
			return &types.UpdateResponse{
				Error: &types.EdgeError{
					Code:    "INVALID_ID",
					Message: "invalid worker ID",
					Type:    "update_error",
				},
			}, nil
		}
		if err := p.uploadBundle(ctx, workerID, newVersion, string(req.Code)); err != nil {
			return &types.UpdateResponse{
				Error: &types.EdgeError{
					Code:    "BUNDLE_UPLOAD_FAILED",
					Message: err.Error(),
					Type:    "update_error",
				},
			}, nil
		}

		// Activate new version
		_, err = p.activateVersion(ctx, workerID, newVersion)
		if err != nil {
			return &types.UpdateResponse{
				Error: &types.EdgeError{
					Code:    "ACTIVATION_FAILED",
					Message: err.Error(),
					Type:    "update_error",
				},
			}, nil
		}

		workerInfo.Version = newVersion
	}

	return &types.UpdateResponse{
		ID:        req.ID,
		Name:      req.Name,
		Status:    "updated",
		UpdatedAt: time.Now(),
		Version:   workerInfo.Version,
	}, nil
}

// getEdgeWorkerInfo gets EdgeWorker information
func (p *AkamaiProvider) getEdgeWorkerInfo(ctx context.Context, edgeWorkerID string) (*EdgeWorkerInfo, error) {
	url := fmt.Sprintf("%s/edgeworkers/v1/ids/%s", p.baseURL, edgeWorkerID)

	httpReq, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Authorization", "Bearer "+p.config.APIKey)

	resp, err := p.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to get EdgeWorker info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("EdgeWorker not found")
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get EdgeWorker info with status %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var workerInfo EdgeWorkerInfo
	if err := json.Unmarshal(body, &workerInfo); err != nil {
		return nil, fmt.Errorf("failed to parse EdgeWorker info: %w", err)
	}

	return &workerInfo, nil
}

// GetDeployment returns deployment information
func (p *AkamaiProvider) GetDeployment(ctx context.Context, req *types.GetDeploymentRequest) (*types.DeploymentInfo, error) {
	workerInfo, err := p.getEdgeWorkerInfo(ctx, req.ID)
	if err != nil {
		return nil, err
	}

	return &types.DeploymentInfo{
		ID:         req.ID,
		Name:       workerInfo.Name,
		Runtime:    "javascript",
		Status:     "deployed",
		URL:        fmt.Sprintf("https://edgeworker-%s.akamai.com", req.ID),
		DeployedAt: workerInfo.CreatedTime,
		UpdatedAt:  workerInfo.LastModifiedTime,
		Version:    workerInfo.Version,
	}, nil
}

// ListDeployments lists all deployments
func (p *AkamaiProvider) ListDeployments(ctx context.Context) ([]*types.DeploymentInfo, error) {
	url := fmt.Sprintf("%s/edgeworkers/v1/ids", p.baseURL)

	httpReq, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Authorization", "Bearer "+p.config.APIKey)

	resp, err := p.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to list EdgeWorkers: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to list EdgeWorkers with status %d: %s", resp.StatusCode, string(body))
	}

	var workersResp struct {
		EdgeWorkers []EdgeWorkerInfo `json:"edgeWorkers"`
	}

	if err := json.Unmarshal(body, &workersResp); err != nil {
		return nil, fmt.Errorf("failed to parse EdgeWorkers response: %w", err)
	}

	deployments := make([]*types.DeploymentInfo, len(workersResp.EdgeWorkers))
	for i, worker := range workersResp.EdgeWorkers {
		deployments[i] = &types.DeploymentInfo{
			ID:         fmt.Sprintf("%d", worker.EdgeWorkerID),
			Name:       worker.Name,
			Runtime:    "javascript",
			Status:     "deployed",
			URL:        fmt.Sprintf("https://edgeworker-%d.akamai.com", worker.EdgeWorkerID),
			DeployedAt: worker.CreatedTime,
			UpdatedAt:  worker.LastModifiedTime,
			Version:    worker.Version,
		}
	}

	return deployments, nil
}

// Invoke invokes a deployed EdgeWorker
func (p *AkamaiProvider) Invoke(ctx context.Context, req *types.InvokeRequest) (*types.InvokeResponse, error) {
	// Get deployment info to construct URL
	deploymentReq := &types.GetDeploymentRequest{
		ID: req.DeploymentID,
	}

	deployment, err := p.GetDeployment(ctx, deploymentReq)
	if err != nil {
		return nil, fmt.Errorf("failed to get deployment: %w", err)
	}

	// Construct the EdgeWorker URL
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
		return nil, fmt.Errorf("failed to invoke EdgeWorker: %w", err)
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
func (p *AkamaiProvider) GetLogs(ctx context.Context, req *types.GetLogsRequest) (*types.LogsResponse, error) {
	// Akamai EdgeWorkers logs are available through the Diagnostic Tools API
	url := fmt.Sprintf("%s/edgeworkers/v1/ids/%s/diagnostics", p.baseURL, req.DeploymentID)

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
			Source:    "akamai-edgeworker",
		}
	}

	return &types.LogsResponse{
		Logs:  logs,
		Total: len(logs),
	}, nil
}

// GetMetrics retrieves metrics from a deployment
func (p *AkamaiProvider) GetMetrics(ctx context.Context, req *types.GetMetricsRequest) (*types.MetricsResponse, error) {
	// Akamai EdgeWorkers metrics are available through the Analytics API
	url := fmt.Sprintf("%s/edgeworkers/v1/ids/%s/analytics", p.baseURL, req.DeploymentID)

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
		Metrics struct {
			Invocations int64   `json:"invocations"`
			Errors      int64   `json:"errors"`
			AvgDuration float64 `json:"avg_duration_ms"`
			MaxDuration float64 `json:"max_duration_ms"`
			MinDuration float64 `json:"min_duration_ms"`
		} `json:"metrics"`
	}

	if err := json.Unmarshal(body, &metricsResp); err != nil {
		return nil, fmt.Errorf("failed to parse metrics response: %w", err)
	}

	metrics := types.DeploymentMetrics{
		Invocations:    metricsResp.Metrics.Invocations,
		Errors:         metricsResp.Metrics.Errors,
		AvgDuration:    metricsResp.Metrics.AvgDuration,
		MaxDuration:    metricsResp.Metrics.MaxDuration,
		MinDuration:    metricsResp.Metrics.MinDuration,
		LastInvocation: time.Now(),
	}

	return &types.MetricsResponse{
		Metrics: metrics,
	}, nil
}

// GetProviderName returns the name of the provider
func (p *AkamaiProvider) GetProviderName() string {
	return "akamai"
}

// IsHealthy checks if the provider is healthy
func (p *AkamaiProvider) IsHealthy(ctx context.Context) error {
	url := fmt.Sprintf("%s/edgeworkers/v1/ids", p.baseURL)

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
func (p *AkamaiProvider) GetSupportedRuntimes() []string {
	return []string{"javascript", "typescript"}
}

// GetSupportedRegions returns supported regions
func (p *AkamaiProvider) GetSupportedRegions() []string {
	return []string{
		"global", "us-east", "us-west", "eu-west", "eu-central",
		"ap-southeast", "ap-northeast", "ap-south", "sa-east",
	}
}

// EdgeWorkerResponse represents an Akamai EdgeWorker response
type EdgeWorkerResponse struct {
	EdgeWorkerID int    `json:"edgeWorkerId"`
	Name         string `json:"name"`
}

// VersionResponse represents an Akamai version response
type VersionResponse struct {
	Version string `json:"version"`
}

// ActivationResponse represents an Akamai activation response
type ActivationResponse struct {
	URL string `json:"url"`
}

// EdgeWorkerInfo represents Akamai EdgeWorker information
type EdgeWorkerInfo struct {
	EdgeWorkerID     int       `json:"edgeWorkerId"`
	Name             string    `json:"name"`
	Version          string    `json:"version"`
	CreatedTime      time.Time `json:"createdTime"`
	LastModifiedTime time.Time `json:"lastModifiedTime"`
	ResourceTier     string    `json:"resourceTier"`
}
