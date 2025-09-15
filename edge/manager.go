package edge

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/anasamu/go-micro-libs/edge/providers/akamai"
	"github.com/anasamu/go-micro-libs/edge/providers/cloudflare"
	"github.com/anasamu/go-micro-libs/edge/providers/fastly"
	"github.com/anasamu/go-micro-libs/edge/providers/wasm"
	"github.com/anasamu/go-micro-libs/edge/types"
)

// EdgeManager manages multiple edge computing providers
type EdgeManager struct {
	providers   map[string]types.EdgeProvider
	wasmRuntime types.WASMRuntime
	configs     map[string]*types.ProviderConfig
	stats       map[string]*types.ProviderStats
	mu          sync.RWMutex
}

// NewEdgeManager creates a new edge manager
func NewEdgeManager() *EdgeManager {
	return &EdgeManager{
		providers: make(map[string]types.EdgeProvider),
		configs:   make(map[string]*types.ProviderConfig),
		stats:     make(map[string]*types.ProviderStats),
	}
}

// AddProvider adds a new edge provider
func (m *EdgeManager) AddProvider(config *types.ProviderConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if config.Name == "" {
		return fmt.Errorf("provider name is required")
	}

	var provider types.EdgeProvider

	switch config.Name {
	case "cloudflare":
		provider = cloudflare.NewCloudflareProvider(config)
	case "fastly":
		provider = fastly.NewFastlyProvider(config)
	case "akamai":
		provider = akamai.NewAkamaiProvider(config)
	case "wasm":
		provider = wasm.NewWASMProvider(config)
	default:
		return fmt.Errorf("unsupported provider: %s", config.Name)
	}

	// Test the provider
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := provider.IsHealthy(ctx); err != nil {
		return fmt.Errorf("provider %s health check failed: %w", config.Name, err)
	}

	m.providers[config.Name] = provider
	m.configs[config.Name] = config
	m.stats[config.Name] = &types.ProviderStats{
		Provider:          config.Name,
		TotalDeployments:  0,
		TotalInvocations:  0,
		SuccessRate:       0.0,
		AvgLatency:        0.0,
		LastUsed:          time.Now(),
		ActiveDeployments: 0,
	}

	return nil
}

// SetWASMRuntime sets the WASM runtime for compilation
func (m *EdgeManager) SetWASMRuntime(runtime types.WASMRuntime) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.wasmRuntime = runtime
}

// RemoveProvider removes an edge provider
func (m *EdgeManager) RemoveProvider(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.providers[name]; !exists {
		return fmt.Errorf("provider %s not found", name)
	}

	delete(m.providers, name)
	delete(m.configs, name)
	delete(m.stats, name)

	return nil
}

// GetProvider returns a provider by name
func (m *EdgeManager) GetProvider(name string) (types.EdgeProvider, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	provider, exists := m.providers[name]
	if !exists {
		return nil, fmt.Errorf("provider %s not found", name)
	}

	return provider, nil
}

// ListProviders returns a list of all provider names
func (m *EdgeManager) ListProviders() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	providers := make([]string, 0, len(m.providers))
	for name := range m.providers {
		providers = append(providers, name)
	}

	return providers
}

// Deploy deploys a microservice to a specific provider
func (m *EdgeManager) Deploy(ctx context.Context, providerName string, req *types.DeployRequest) (*types.DeployResponse, error) {
	provider, err := m.GetProvider(providerName)
	if err != nil {
		return nil, err
	}

	start := time.Now()
	resp, err := provider.Deploy(ctx, req)
	duration := time.Since(start)

	// Update stats
	m.updateStats(providerName, duration, err == nil, true, false)

	if err == nil {
		m.incrementDeployments(providerName)
	}

	return resp, err
}

// Undeploy removes a deployment from a specific provider
func (m *EdgeManager) Undeploy(ctx context.Context, providerName string, req *types.UndeployRequest) error {
	provider, err := m.GetProvider(providerName)
	if err != nil {
		return err
	}

	start := time.Now()
	err = provider.Undeploy(ctx, req)
	duration := time.Since(start)

	// Update stats
	m.updateStats(providerName, duration, err == nil, false, false)

	if err == nil {
		m.decrementDeployments(providerName)
	}

	return err
}

// Update updates a deployment on a specific provider
func (m *EdgeManager) Update(ctx context.Context, providerName string, req *types.UpdateRequest) (*types.UpdateResponse, error) {
	provider, err := m.GetProvider(providerName)
	if err != nil {
		return nil, err
	}

	start := time.Now()
	resp, err := provider.Update(ctx, req)
	duration := time.Since(start)

	// Update stats
	m.updateStats(providerName, duration, err == nil, false, false)

	return resp, err
}

// GetDeployment returns deployment information from a specific provider
func (m *EdgeManager) GetDeployment(ctx context.Context, providerName string, req *types.GetDeploymentRequest) (*types.DeploymentInfo, error) {
	provider, err := m.GetProvider(providerName)
	if err != nil {
		return nil, err
	}

	return provider.GetDeployment(ctx, req)
}

// ListDeployments lists all deployments from a specific provider
func (m *EdgeManager) ListDeployments(ctx context.Context, providerName string) ([]*types.DeploymentInfo, error) {
	provider, err := m.GetProvider(providerName)
	if err != nil {
		return nil, err
	}

	return provider.ListDeployments(ctx)
}

// Invoke invokes a deployed function on a specific provider
func (m *EdgeManager) Invoke(ctx context.Context, providerName string, req *types.InvokeRequest) (*types.InvokeResponse, error) {
	provider, err := m.GetProvider(providerName)
	if err != nil {
		return nil, err
	}

	start := time.Now()
	resp, err := provider.Invoke(ctx, req)
	duration := time.Since(start)

	// Update stats
	m.updateStats(providerName, duration, err == nil, false, true)

	return resp, err
}

// GetLogs retrieves logs from a deployment on a specific provider
func (m *EdgeManager) GetLogs(ctx context.Context, providerName string, req *types.GetLogsRequest) (*types.LogsResponse, error) {
	provider, err := m.GetProvider(providerName)
	if err != nil {
		return nil, err
	}

	return provider.GetLogs(ctx, req)
}

// GetMetrics retrieves metrics from a deployment on a specific provider
func (m *EdgeManager) GetMetrics(ctx context.Context, providerName string, req *types.GetMetricsRequest) (*types.MetricsResponse, error) {
	provider, err := m.GetProvider(providerName)
	if err != nil {
		return nil, err
	}

	return provider.GetMetrics(ctx, req)
}

// CompileToWASM compiles source code to WASM using the WASM runtime
func (m *EdgeManager) CompileToWASM(ctx context.Context, req *types.CompilationRequest) (*types.CompilationResponse, error) {
	m.mu.RLock()
	runtime := m.wasmRuntime
	m.mu.RUnlock()

	if runtime == nil {
		return nil, fmt.Errorf("WASM runtime not configured")
	}

	return runtime.Compile(ctx, req)
}

// GetSupportedRuntimes returns supported runtimes for all providers
func (m *EdgeManager) GetSupportedRuntimes(ctx context.Context) (map[string][]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	runtimes := make(map[string][]string)

	for name, provider := range m.providers {
		runtimeList := provider.GetSupportedRuntimes()
		runtimes[name] = runtimeList
	}

	return runtimes, nil
}

// GetSupportedRegions returns supported regions for all providers
func (m *EdgeManager) GetSupportedRegions(ctx context.Context) (map[string][]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	regions := make(map[string][]string)

	for name, provider := range m.providers {
		regionList := provider.GetSupportedRegions()
		regions[name] = regionList
	}

	return regions, nil
}

// HealthCheck checks the health of all providers
func (m *EdgeManager) HealthCheck(ctx context.Context) (map[string]*types.HealthStatus, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	healthStatus := make(map[string]*types.HealthStatus)

	for name, provider := range m.providers {
		status := &types.HealthStatus{
			Provider:  name,
			Healthy:   false,
			CheckedAt: time.Now(),
		}

		if err := provider.IsHealthy(ctx); err != nil {
			status.Message = err.Error()
		} else {
			status.Healthy = true
		}

		healthStatus[name] = status
	}

	return healthStatus, nil
}

// GetStats returns statistics for all providers
func (m *EdgeManager) GetStats() map[string]*types.ProviderStats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := make(map[string]*types.ProviderStats)
	for name, stat := range m.stats {
		stats[name] = &types.ProviderStats{
			Provider:          stat.Provider,
			TotalDeployments:  stat.TotalDeployments,
			TotalInvocations:  stat.TotalInvocations,
			SuccessRate:       stat.SuccessRate,
			AvgLatency:        stat.AvgLatency,
			LastUsed:          stat.LastUsed,
			ActiveDeployments: stat.ActiveDeployments,
		}
	}

	return stats
}

// GetProviderStats returns statistics for a specific provider
func (m *EdgeManager) GetProviderStats(providerName string) (*types.ProviderStats, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats, exists := m.stats[providerName]
	if !exists {
		return nil, fmt.Errorf("provider %s not found", providerName)
	}

	return &types.ProviderStats{
		Provider:          stats.Provider,
		TotalDeployments:  stats.TotalDeployments,
		TotalInvocations:  stats.TotalInvocations,
		SuccessRate:       stats.SuccessRate,
		AvgLatency:        stats.AvgLatency,
		LastUsed:          stats.LastUsed,
		ActiveDeployments: stats.ActiveDeployments,
	}, nil
}

// DeployWithFallback deploys with automatic fallback to other providers
func (m *EdgeManager) DeployWithFallback(ctx context.Context, primaryProvider string, req *types.DeployRequest) (*types.DeployResponse, error) {
	providers := m.ListProviders()
	if len(providers) == 0 {
		return nil, fmt.Errorf("no providers available")
	}

	// Try primary provider first
	if primaryProvider != "" {
		if _, err := m.GetProvider(primaryProvider); err == nil {
			resp, err := m.Deploy(ctx, primaryProvider, req)
			if err == nil && resp.Error == nil {
				return resp, nil
			}
		}
	}

	// Try other providers
	for _, providerName := range providers {
		if providerName == primaryProvider {
			continue
		}

		resp, err := m.Deploy(ctx, providerName, req)
		if err == nil && resp.Error == nil {
			return resp, nil
		}
	}

	return nil, fmt.Errorf("all providers failed")
}

// InvokeWithFallback invokes with automatic fallback to other providers
func (m *EdgeManager) InvokeWithFallback(ctx context.Context, primaryProvider string, req *types.InvokeRequest) (*types.InvokeResponse, error) {
	providers := m.ListProviders()
	if len(providers) == 0 {
		return nil, fmt.Errorf("no providers available")
	}

	// Try primary provider first
	if primaryProvider != "" {
		if _, err := m.GetProvider(primaryProvider); err == nil {
			resp, err := m.Invoke(ctx, primaryProvider, req)
			if err == nil && resp.Error == nil {
				return resp, nil
			}
		}
	}

	// Try other providers
	for _, providerName := range providers {
		if providerName == primaryProvider {
			continue
		}

		resp, err := m.Invoke(ctx, providerName, req)
		if err == nil && resp.Error == nil {
			return resp, nil
		}
	}

	return nil, fmt.Errorf("all providers failed")
}

// updateStats updates provider statistics
func (m *EdgeManager) updateStats(providerName string, duration time.Duration, success bool, isDeployment bool, isInvocation bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	stats, exists := m.stats[providerName]
	if !exists {
		return
	}

	stats.LastUsed = time.Now()

	if isInvocation {
		stats.TotalInvocations++
	}

	// Update latency
	if stats.AvgLatency == 0 {
		stats.AvgLatency = float64(duration.Milliseconds())
	} else {
		stats.AvgLatency = (stats.AvgLatency + float64(duration.Milliseconds())) / 2
	}

	// Update success rate
	totalOps := stats.TotalInvocations
	if isDeployment {
		totalOps = stats.TotalDeployments
	}

	if success {
		stats.SuccessRate = (stats.SuccessRate*float64(totalOps-1) + 1.0) / float64(totalOps)
	} else {
		stats.SuccessRate = (stats.SuccessRate * float64(totalOps-1)) / float64(totalOps)
	}
}

// incrementDeployments increments the deployment count
func (m *EdgeManager) incrementDeployments(providerName string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if stats, exists := m.stats[providerName]; exists {
		stats.TotalDeployments++
		stats.ActiveDeployments++
	}
}

// decrementDeployments decrements the deployment count
func (m *EdgeManager) decrementDeployments(providerName string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if stats, exists := m.stats[providerName]; exists {
		if stats.ActiveDeployments > 0 {
			stats.ActiveDeployments--
		}
	}
}
