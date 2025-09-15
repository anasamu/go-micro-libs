package wasm

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/anasamu/go-micro-libs/edge/types"
)

// WASMProvider implements the EdgeProvider interface for WASM runtime
type WASMProvider struct {
	config  *types.ProviderConfig
	runtime types.WASMRuntime
	tempDir string
}

// NewWASMProvider creates a new WASM provider
func NewWASMProvider(config *types.ProviderConfig) *WASMProvider {
	tempDir := os.TempDir()
	if config.Config != nil {
		if dir, ok := config.Config["temp_dir"].(string); ok {
			tempDir = dir
		}
	}

	return &WASMProvider{
		config:  config,
		runtime: NewTinyGoRuntime(),
		tempDir: tempDir,
	}
}

// Deploy deploys a WASM module
func (p *WASMProvider) Deploy(ctx context.Context, req *types.DeployRequest) (*types.DeployResponse, error) {
	// Compile source code to WASM if needed
	var wasmCode []byte

	if req.Runtime == "wasm" && len(req.Code) > 0 {
		// Code is already compiled WASM
		wasmCode = req.Code
	} else {
		// Compile source code to WASM
		compilationReq := &types.CompilationRequest{
			SourceCode:   req.Code,
			Language:     req.Runtime,
			Target:       "wasm32-unknown-unknown",
			Optimization: "size",
		}

		compilationResp, err := p.runtime.Compile(ctx, compilationReq)
		if err != nil {
			return nil, fmt.Errorf("failed to compile to WASM: %w", err)
		}

		if compilationResp.Error != nil {
			return &types.DeployResponse{
				Error: compilationResp.Error,
			}, nil
		}

		wasmCode = compilationResp.WasmCode
	}

	// Create a temporary file for the WASM module
	wasmFile := filepath.Join(p.tempDir, fmt.Sprintf("%s.wasm", req.Name))
	if err := os.WriteFile(wasmFile, wasmCode, 0644); err != nil {
		return nil, fmt.Errorf("failed to write WASM file: %w", err)
	}

	// Create deployment info
	deploymentID := fmt.Sprintf("wasm-%s-%d", req.Name, time.Now().Unix())

	return &types.DeployResponse{
		ID:         deploymentID,
		Name:       req.Name,
		Status:     "deployed",
		URL:        fmt.Sprintf("wasm://%s", deploymentID),
		Region:     "local",
		DeployedAt: time.Now(),
		Version:    "1.0.0",
	}, nil
}

// Undeploy removes a WASM deployment
func (p *WASMProvider) Undeploy(ctx context.Context, req *types.UndeployRequest) error {
	// Remove the WASM file
	wasmFile := filepath.Join(p.tempDir, fmt.Sprintf("%s.wasm", req.Name))
	if err := os.Remove(wasmFile); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove WASM file: %w", err)
	}

	return nil
}

// Update updates an existing WASM deployment
func (p *WASMProvider) Update(ctx context.Context, req *types.UpdateRequest) (*types.UpdateResponse, error) {
	// Get current deployment info
	deploymentReq := &types.GetDeploymentRequest{
		ID: req.ID,
	}

	currentDeployment, err := p.GetDeployment(ctx, deploymentReq)
	if err != nil {
		return nil, fmt.Errorf("failed to get current deployment: %w", err)
	}

	// If code is provided, recompile
	if len(req.Code) > 0 {
		compilationReq := &types.CompilationRequest{
			SourceCode:   req.Code,
			Language:     currentDeployment.Runtime,
			Target:       "wasm32-unknown-unknown",
			Optimization: "size",
		}

		compilationResp, err := p.runtime.Compile(ctx, compilationReq)
		if err != nil {
			return nil, fmt.Errorf("failed to compile to WASM: %w", err)
		}

		if compilationResp.Error != nil {
			return &types.UpdateResponse{
				Error: compilationResp.Error,
			}, nil
		}

		// Update the WASM file
		wasmFile := filepath.Join(p.tempDir, fmt.Sprintf("%s.wasm", req.Name))
		if err := os.WriteFile(wasmFile, compilationResp.WasmCode, 0644); err != nil {
			return nil, fmt.Errorf("failed to update WASM file: %w", err)
		}
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
func (p *WASMProvider) GetDeployment(ctx context.Context, req *types.GetDeploymentRequest) (*types.DeploymentInfo, error) {
	wasmFile := filepath.Join(p.tempDir, fmt.Sprintf("%s.wasm", req.Name))

	// Check if WASM file exists
	if _, err := os.Stat(wasmFile); os.IsNotExist(err) {
		return nil, fmt.Errorf("deployment not found")
	}

	// Get file info
	fileInfo, err := os.Stat(wasmFile)
	if err != nil {
		return nil, fmt.Errorf("failed to get file info: %w", err)
	}

	return &types.DeploymentInfo{
		ID:         req.ID,
		Name:       req.Name,
		Runtime:    "wasm",
		Status:     "deployed",
		URL:        fmt.Sprintf("wasm://%s", req.ID),
		Region:     "local",
		DeployedAt: fileInfo.ModTime(),
		UpdatedAt:  fileInfo.ModTime(),
		Version:    "1.0.0",
	}, nil
}

// ListDeployments lists all deployments
func (p *WASMProvider) ListDeployments(ctx context.Context) ([]*types.DeploymentInfo, error) {
	files, err := filepath.Glob(filepath.Join(p.tempDir, "*.wasm"))
	if err != nil {
		return nil, fmt.Errorf("failed to list WASM files: %w", err)
	}

	deployments := make([]*types.DeploymentInfo, 0, len(files))
	for _, file := range files {
		fileName := filepath.Base(file)
		name := fileName[:len(fileName)-5] // Remove .wasm extension

		fileInfo, err := os.Stat(file)
		if err != nil {
			continue
		}

		deploymentID := fmt.Sprintf("wasm-%s-%d", name, fileInfo.ModTime().Unix())

		deployments = append(deployments, &types.DeploymentInfo{
			ID:         deploymentID,
			Name:       name,
			Runtime:    "wasm",
			Status:     "deployed",
			URL:        fmt.Sprintf("wasm://%s", deploymentID),
			Region:     "local",
			DeployedAt: fileInfo.ModTime(),
			UpdatedAt:  fileInfo.ModTime(),
			Version:    "1.0.0",
		})
	}

	return deployments, nil
}

// Invoke invokes a deployed WASM module
func (p *WASMProvider) Invoke(ctx context.Context, req *types.InvokeRequest) (*types.InvokeResponse, error) {
	// Get deployment info
	deploymentReq := &types.GetDeploymentRequest{
		ID: req.DeploymentID,
	}

	deployment, err := p.GetDeployment(ctx, deploymentReq)
	if err != nil {
		return nil, fmt.Errorf("failed to get deployment: %w", err)
	}

	// Load WASM file
	wasmFile := filepath.Join(p.tempDir, fmt.Sprintf("%s.wasm", deployment.Name))
	wasmCode, err := os.ReadFile(wasmFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read WASM file: %w", err)
	}

	start := time.Now()

	// Execute WASM module
	result, err := p.runtime.Execute(ctx, wasmCode, req.Payload)

	duration := time.Since(start)

	if err != nil {
		return &types.InvokeResponse{
			ID:       fmt.Sprintf("%d", time.Now().UnixNano()),
			Status:   "error",
			Duration: duration,
			Error: &types.EdgeError{
				Code:    "WASM_EXECUTION_ERROR",
				Message: err.Error(),
				Type:    "execution_error",
			},
		}, nil
	}

	return &types.InvokeResponse{
		ID:       fmt.Sprintf("%d", time.Now().UnixNano()),
		Status:   "success",
		Result:   result,
		Duration: duration,
	}, nil
}

// GetLogs retrieves logs from a deployment
func (p *WASMProvider) GetLogs(ctx context.Context, req *types.GetLogsRequest) (*types.LogsResponse, error) {
	// WASM runtime doesn't have persistent logs, return empty response
	return &types.LogsResponse{
		Logs:  []types.LogEntry{},
		Total: 0,
	}, nil
}

// GetMetrics retrieves metrics from a deployment
func (p *WASMProvider) GetMetrics(ctx context.Context, req *types.GetMetricsRequest) (*types.MetricsResponse, error) {
	// WASM runtime doesn't have persistent metrics, return empty response
	metrics := types.DeploymentMetrics{
		LastInvocation: time.Now(),
	}

	return &types.MetricsResponse{
		Metrics: metrics,
	}, nil
}

// GetProviderName returns the name of the provider
func (p *WASMProvider) GetProviderName() string {
	return "wasm"
}

// IsHealthy checks if the provider is healthy
func (p *WASMProvider) IsHealthy(ctx context.Context) error {
	// Check if the runtime is healthy
	if err := p.runtime.IsHealthy(ctx); err != nil {
		return fmt.Errorf("WASM runtime health check failed: %w", err)
	}

	// Check if temp directory is writable
	tempFile := filepath.Join(p.tempDir, "health_check.tmp")
	if err := os.WriteFile(tempFile, []byte("health check"), 0644); err != nil {
		return fmt.Errorf("temp directory not writable: %w", err)
	}
	defer os.Remove(tempFile)

	return nil
}

// GetSupportedRuntimes returns supported runtimes
func (p *WASMProvider) GetSupportedRuntimes() []string {
	return p.runtime.GetSupportedLanguages()
}

// GetSupportedRegions returns supported regions
func (p *WASMProvider) GetSupportedRegions() []string {
	return []string{"local"}
}

// TinyGoRuntime implements the WASMRuntime interface using TinyGo
type TinyGoRuntime struct {
	tempDir string
}

// NewTinyGoRuntime creates a new TinyGo runtime
func NewTinyGoRuntime() *TinyGoRuntime {
	return &TinyGoRuntime{
		tempDir: os.TempDir(),
	}
}

// Compile compiles source code to WASM
func (r *TinyGoRuntime) Compile(ctx context.Context, req *types.CompilationRequest) (*types.CompilationResponse, error) {
	// Create temporary files
	sourceFile := filepath.Join(r.tempDir, fmt.Sprintf("source_%d.%s", time.Now().UnixNano(), getFileExtension(req.Language)))
	wasmFile := filepath.Join(r.tempDir, fmt.Sprintf("output_%d.wasm", time.Now().UnixNano()))

	defer func() {
		os.Remove(sourceFile)
		os.Remove(wasmFile)
	}()

	// Write source code to file
	if err := os.WriteFile(sourceFile, req.SourceCode, 0644); err != nil {
		return nil, fmt.Errorf("failed to write source file: %w", err)
	}

	// Compile based on language
	var cmd *exec.Cmd
	switch req.Language {
	case "go":
		cmd = exec.CommandContext(ctx, "tinygo", "build", "-target", req.Target, "-o", wasmFile, sourceFile)
	case "rust":
		cmd = exec.CommandContext(ctx, "cargo", "build", "--target", req.Target, "--release")
		// Set output directory
		cmd.Env = append(os.Environ(), "CARGO_TARGET_DIR="+filepath.Dir(wasmFile))
	case "c", "cpp":
		cmd = exec.CommandContext(ctx, "emcc", sourceFile, "-s", "WASM=1", "-o", wasmFile)
	default:
		return &types.CompilationResponse{
			Error: &types.EdgeError{
				Code:    "UNSUPPORTED_LANGUAGE",
				Message: fmt.Sprintf("unsupported language: %s", req.Language),
				Type:    "compilation_error",
			},
		}, nil
	}

	// Execute compilation
	output, err := cmd.CombinedOutput()
	if err != nil {
		return &types.CompilationResponse{
			Error: &types.EdgeError{
				Code:    "COMPILATION_FAILED",
				Message: fmt.Sprintf("compilation failed: %s", string(output)),
				Type:    "compilation_error",
			},
		}, nil
	}

	// Read compiled WASM
	wasmCode, err := os.ReadFile(wasmFile)
	if err != nil {
		return &types.CompilationResponse{
			Error: &types.EdgeError{
				Code:    "READ_WASM_FAILED",
				Message: fmt.Sprintf("failed to read compiled WASM: %v", err),
				Type:    "compilation_error",
			},
		}, nil
	}

	return &types.CompilationResponse{
		WasmCode:     wasmCode,
		Size:         int64(len(wasmCode)),
		CompiledAt:   time.Now(),
		Optimization: req.Optimization,
		Features:     req.Features,
	}, nil
}

// Execute executes WASM code
func (r *TinyGoRuntime) Execute(ctx context.Context, wasmCode []byte, input []byte) ([]byte, error) {
	// For simplicity, we'll use a basic WASM execution approach
	// In a real implementation, you would use a proper WASM runtime like Wasmtime or Wazero

	// Create a temporary WASM file
	wasmFile := filepath.Join(r.tempDir, fmt.Sprintf("execute_%d.wasm", time.Now().UnixNano()))
	defer os.Remove(wasmFile)

	if err := os.WriteFile(wasmFile, wasmCode, 0644); err != nil {
		return nil, fmt.Errorf("failed to write WASM file: %w", err)
	}

	// For demonstration, we'll use a simple approach
	// In production, you would use a proper WASM runtime
	result := []byte(fmt.Sprintf("WASM execution result for input: %s", string(input)))

	return result, nil
}

// GetSupportedLanguages returns supported programming languages
func (r *TinyGoRuntime) GetSupportedLanguages() []string {
	return []string{"go", "rust", "c", "cpp", "assemblyscript"}
}

// GetSupportedTargets returns supported compilation targets
func (r *TinyGoRuntime) GetSupportedTargets() []string {
	return []string{
		"wasm32-unknown-unknown",
		"wasm32-wasi",
		"wasm32-unknown-wasi",
	}
}

// IsHealthy checks if the runtime is healthy
func (r *TinyGoRuntime) IsHealthy(ctx context.Context) error {
	// Check if required tools are available
	tools := []string{"tinygo", "cargo", "emcc"}

	for _, tool := range tools {
		if _, err := exec.LookPath(tool); err != nil {
			// Tool not found, but that's okay - we only need at least one
			continue
		}
		return nil
	}

	return fmt.Errorf("no WASM compilation tools found (tinygo, cargo, emcc)")
}

// getFileExtension returns the file extension for a given language
func getFileExtension(language string) string {
	switch language {
	case "go":
		return "go"
	case "rust":
		return "rs"
	case "c":
		return "c"
	case "cpp":
		return "cpp"
	case "assemblyscript":
		return "ts"
	default:
		return "txt"
	}
}
