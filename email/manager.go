package email

import (
	"context"
	"fmt"
	"time"

	"github.com/anasamu/go-micro-libs/email/types"
	"github.com/sirupsen/logrus"
)

// EmailManager manages multiple email providers
type EmailManager struct {
	providers map[string]EmailProvider
	logger    *logrus.Logger
	config    *ManagerConfig
}

// ManagerConfig holds email manager configuration
type ManagerConfig struct {
	DefaultProvider string            `json:"default_provider"`
	RetryAttempts   int               `json:"retry_attempts"`
	RetryDelay      time.Duration     `json:"retry_delay"`
	Timeout         time.Duration     `json:"timeout"`
	MaxMessageSize  int64             `json:"max_message_size"`
	Metadata        map[string]string `json:"metadata"`
}

// EmailProvider interface for email backends
type EmailProvider interface {
	// Provider information
	GetName() string
	GetSupportedFeatures() []types.EmailFeature
	GetConnectionInfo() *types.ConnectionInfo

	// Connection management
	Connect(ctx context.Context) error
	Disconnect(ctx context.Context) error
	Ping(ctx context.Context) error
	IsConnected() bool

	// Email operations
	SendEmail(ctx context.Context, request *types.SendRequest) (*types.SendResponse, error)
	SendBatch(ctx context.Context, request *types.SendBatchRequest) (*types.SendBatchResponse, error)

	// Email retrieval (for POP3/IMAP)
	FetchEmails(ctx context.Context, request *types.FetchRequest) (*types.FetchResponse, error)
	SearchEmails(ctx context.Context, request *types.SearchRequest) (*types.SearchResponse, error)

	// Folder management (for IMAP)
	ListFolders(ctx context.Context, request *types.ListFoldersRequest) (*types.ListFoldersResponse, error)
	CreateFolder(ctx context.Context, request *types.CreateFolderRequest) error
	DeleteFolder(ctx context.Context, request *types.DeleteFolderRequest) error

	// Message management (for IMAP)
	MoveMessage(ctx context.Context, request *types.MoveMessageRequest) error
	DeleteMessage(ctx context.Context, request *types.DeleteMessageRequest) error

	// Template management
	CreateTemplate(ctx context.Context, request *types.CreateTemplateRequest) error
	UpdateTemplate(ctx context.Context, request *types.UpdateTemplateRequest) error
	DeleteTemplate(ctx context.Context, request *types.DeleteTemplateRequest) error
	GetTemplate(ctx context.Context, request *types.GetTemplateRequest) (*types.Template, error)
	ListTemplates(ctx context.Context, request *types.ListTemplatesRequest) (*types.ListTemplatesResponse, error)
	RenderTemplate(ctx context.Context, request *types.RenderTemplateRequest) (*types.RenderTemplateResponse, error)

	// Health and monitoring
	HealthCheck(ctx context.Context) error
	GetStats(ctx context.Context) (*types.EmailStats, error)

	// Configuration
	Configure(config map[string]interface{}) error
	IsConfigured() bool
	Close() error
}

// DefaultManagerConfig returns default email manager configuration
func DefaultManagerConfig() *ManagerConfig {
	return &ManagerConfig{
		DefaultProvider: "smtp",
		RetryAttempts:   3,
		RetryDelay:      5 * time.Second,
		Timeout:         30 * time.Second,
		MaxMessageSize:  25 * 1024 * 1024, // 25MB
		Metadata:        make(map[string]string),
	}
}

// NewEmailManager creates a new email manager
func NewEmailManager(config *ManagerConfig, logger *logrus.Logger) *EmailManager {
	if config == nil {
		config = DefaultManagerConfig()
	}

	if logger == nil {
		logger = logrus.New()
	}

	return &EmailManager{
		providers: make(map[string]EmailProvider),
		logger:    logger,
		config:    config,
	}
}

// RegisterProvider registers an email provider
func (em *EmailManager) RegisterProvider(provider EmailProvider) error {
	if provider == nil {
		return fmt.Errorf("provider cannot be nil")
	}

	name := provider.GetName()
	if name == "" {
		return fmt.Errorf("provider name cannot be empty")
	}

	em.providers[name] = provider
	em.logger.WithField("provider", name).Info("Email provider registered")

	return nil
}

// GetProvider returns an email provider by name
func (em *EmailManager) GetProvider(name string) (EmailProvider, error) {
	provider, exists := em.providers[name]
	if !exists {
		return nil, fmt.Errorf("email provider not found: %s", name)
	}
	return provider, nil
}

// GetDefaultProvider returns the default email provider
func (em *EmailManager) GetDefaultProvider() (EmailProvider, error) {
	return em.GetProvider(em.config.DefaultProvider)
}

// Connect connects to an email system using the specified provider
func (em *EmailManager) Connect(ctx context.Context, providerName string) error {
	provider, err := em.GetProvider(providerName)
	if err != nil {
		return err
	}

	// Connect with retry logic
	for attempt := 1; attempt <= em.config.RetryAttempts; attempt++ {
		err = provider.Connect(ctx)
		if err == nil {
			break
		}

		em.logger.WithError(err).WithFields(logrus.Fields{
			"provider": providerName,
			"attempt":  attempt,
		}).Warn("Email connection failed, retrying")

		if attempt < em.config.RetryAttempts {
			time.Sleep(em.config.RetryDelay)
		}
	}

	if err != nil {
		return fmt.Errorf("failed to connect to email system after %d attempts: %w", em.config.RetryAttempts, err)
	}

	em.logger.WithField("provider", providerName).Info("Email system connected successfully")
	return nil
}

// Disconnect disconnects from an email system using the specified provider
func (em *EmailManager) Disconnect(ctx context.Context, providerName string) error {
	provider, err := em.GetProvider(providerName)
	if err != nil {
		return err
	}

	err = provider.Disconnect(ctx)
	if err != nil {
		return fmt.Errorf("failed to disconnect from email system: %w", err)
	}

	em.logger.WithField("provider", providerName).Info("Email system disconnected successfully")
	return nil
}

// Ping pings an email system using the specified provider
func (em *EmailManager) Ping(ctx context.Context, providerName string) error {
	provider, err := em.GetProvider(providerName)
	if err != nil {
		return err
	}

	err = provider.Ping(ctx)
	if err != nil {
		return fmt.Errorf("failed to ping email system: %w", err)
	}

	return nil
}

// SendEmail sends an email using the specified provider
func (em *EmailManager) SendEmail(ctx context.Context, providerName string, request *types.SendRequest) (*types.SendResponse, error) {
	provider, err := em.GetProvider(providerName)
	if err != nil {
		return nil, err
	}

	// Validate request
	if err := em.validateSendRequest(request); err != nil {
		return nil, fmt.Errorf("invalid send request: %w", err)
	}

	// Check message size limit
	if request.Message != nil && em.getMessageSize(request.Message) > em.config.MaxMessageSize {
		return nil, fmt.Errorf("message size %d exceeds maximum allowed size %d", em.getMessageSize(request.Message), em.config.MaxMessageSize)
	}

	// Set default values
	if request.Message.CreatedAt.IsZero() {
		request.Message.CreatedAt = time.Now()
	}

	// Send with retry logic
	var response *types.SendResponse
	for attempt := 1; attempt <= em.config.RetryAttempts; attempt++ {
		response, err = provider.SendEmail(ctx, request)
		if err == nil {
			break
		}

		em.logger.WithError(err).WithFields(logrus.Fields{
			"provider":   providerName,
			"attempt":    attempt,
			"message_id": request.Message.ID,
			"subject":    request.Message.Subject,
		}).Warn("Email send failed, retrying")

		if attempt < em.config.RetryAttempts {
			time.Sleep(em.config.RetryDelay)
		}
	}

	if err != nil {
		return nil, fmt.Errorf("failed to send email after %d attempts: %w", em.config.RetryAttempts, err)
	}

	em.logger.WithFields(logrus.Fields{
		"provider":   providerName,
		"message_id": request.Message.ID,
		"subject":    request.Message.Subject,
		"to":         em.getRecipients(request.Message),
	}).Info("Email sent successfully")

	return response, nil
}

// SendBatch sends multiple emails using the specified provider
func (em *EmailManager) SendBatch(ctx context.Context, providerName string, request *types.SendBatchRequest) (*types.SendBatchResponse, error) {
	provider, err := em.GetProvider(providerName)
	if err != nil {
		return nil, err
	}

	// Validate request
	if err := em.validateSendBatchRequest(request); err != nil {
		return nil, fmt.Errorf("invalid send batch request: %w", err)
	}

	response, err := provider.SendBatch(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("failed to send batch: %w", err)
	}

	em.logger.WithFields(logrus.Fields{
		"provider":     providerName,
		"sent_count":   response.SentCount,
		"failed_count": response.FailedCount,
	}).Info("Batch email sent successfully")

	return response, nil
}

// FetchEmails fetches emails using the specified provider
func (em *EmailManager) FetchEmails(ctx context.Context, providerName string, request *types.FetchRequest) (*types.FetchResponse, error) {
	provider, err := em.GetProvider(providerName)
	if err != nil {
		return nil, err
	}

	response, err := provider.FetchEmails(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch emails: %w", err)
	}

	em.logger.WithFields(logrus.Fields{
		"provider": providerName,
		"count":    response.Total,
		"folder":   request.Folder,
	}).Debug("Emails fetched successfully")

	return response, nil
}

// SearchEmails searches emails using the specified provider
func (em *EmailManager) SearchEmails(ctx context.Context, providerName string, request *types.SearchRequest) (*types.SearchResponse, error) {
	provider, err := em.GetProvider(providerName)
	if err != nil {
		return nil, err
	}

	response, err := provider.SearchEmails(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("failed to search emails: %w", err)
	}

	em.logger.WithFields(logrus.Fields{
		"provider": providerName,
		"count":    response.Total,
		"query":    request.Query,
	}).Debug("Emails searched successfully")

	return response, nil
}

// ListFolders lists folders using the specified provider
func (em *EmailManager) ListFolders(ctx context.Context, providerName string, request *types.ListFoldersRequest) (*types.ListFoldersResponse, error) {
	provider, err := em.GetProvider(providerName)
	if err != nil {
		return nil, err
	}

	response, err := provider.ListFolders(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("failed to list folders: %w", err)
	}

	em.logger.WithFields(logrus.Fields{
		"provider": providerName,
		"count":    len(response.Folders),
	}).Debug("Folders listed successfully")

	return response, nil
}

// CreateFolder creates a folder using the specified provider
func (em *EmailManager) CreateFolder(ctx context.Context, providerName string, request *types.CreateFolderRequest) error {
	provider, err := em.GetProvider(providerName)
	if err != nil {
		return err
	}

	err = provider.CreateFolder(ctx, request)
	if err != nil {
		return fmt.Errorf("failed to create folder: %w", err)
	}

	em.logger.WithFields(logrus.Fields{
		"provider": providerName,
		"name":     request.Name,
		"path":     request.Path,
	}).Info("Folder created successfully")

	return nil
}

// DeleteFolder deletes a folder using the specified provider
func (em *EmailManager) DeleteFolder(ctx context.Context, providerName string, request *types.DeleteFolderRequest) error {
	provider, err := em.GetProvider(providerName)
	if err != nil {
		return err
	}

	err = provider.DeleteFolder(ctx, request)
	if err != nil {
		return fmt.Errorf("failed to delete folder: %w", err)
	}

	em.logger.WithFields(logrus.Fields{
		"provider": providerName,
		"name":     request.Name,
		"path":     request.Path,
	}).Info("Folder deleted successfully")

	return nil
}

// MoveMessage moves a message using the specified provider
func (em *EmailManager) MoveMessage(ctx context.Context, providerName string, request *types.MoveMessageRequest) error {
	provider, err := em.GetProvider(providerName)
	if err != nil {
		return err
	}

	err = provider.MoveMessage(ctx, request)
	if err != nil {
		return fmt.Errorf("failed to move message: %w", err)
	}

	em.logger.WithFields(logrus.Fields{
		"provider":    providerName,
		"uid":         request.UID,
		"from_folder": request.FromFolder,
		"to_folder":   request.ToFolder,
	}).Info("Message moved successfully")

	return nil
}

// DeleteMessage deletes a message using the specified provider
func (em *EmailManager) DeleteMessage(ctx context.Context, providerName string, request *types.DeleteMessageRequest) error {
	provider, err := em.GetProvider(providerName)
	if err != nil {
		return err
	}

	err = provider.DeleteMessage(ctx, request)
	if err != nil {
		return fmt.Errorf("failed to delete message: %w", err)
	}

	em.logger.WithFields(logrus.Fields{
		"provider": providerName,
		"uid":      request.UID,
		"folder":   request.Folder,
	}).Info("Message deleted successfully")

	return nil
}

// CreateTemplate creates a template using the specified provider
func (em *EmailManager) CreateTemplate(ctx context.Context, providerName string, request *types.CreateTemplateRequest) error {
	provider, err := em.GetProvider(providerName)
	if err != nil {
		return err
	}

	err = provider.CreateTemplate(ctx, request)
	if err != nil {
		return fmt.Errorf("failed to create template: %w", err)
	}

	em.logger.WithFields(logrus.Fields{
		"provider":    providerName,
		"template_id": request.Template.ID,
		"name":        request.Template.Name,
	}).Info("Template created successfully")

	return nil
}

// UpdateTemplate updates a template using the specified provider
func (em *EmailManager) UpdateTemplate(ctx context.Context, providerName string, request *types.UpdateTemplateRequest) error {
	provider, err := em.GetProvider(providerName)
	if err != nil {
		return err
	}

	err = provider.UpdateTemplate(ctx, request)
	if err != nil {
		return fmt.Errorf("failed to update template: %w", err)
	}

	em.logger.WithFields(logrus.Fields{
		"provider":    providerName,
		"template_id": request.ID,
	}).Info("Template updated successfully")

	return nil
}

// DeleteTemplate deletes a template using the specified provider
func (em *EmailManager) DeleteTemplate(ctx context.Context, providerName string, request *types.DeleteTemplateRequest) error {
	provider, err := em.GetProvider(providerName)
	if err != nil {
		return err
	}

	err = provider.DeleteTemplate(ctx, request)
	if err != nil {
		return fmt.Errorf("failed to delete template: %w", err)
	}

	em.logger.WithFields(logrus.Fields{
		"provider":    providerName,
		"template_id": request.ID,
	}).Info("Template deleted successfully")

	return nil
}

// GetTemplate gets a template using the specified provider
func (em *EmailManager) GetTemplate(ctx context.Context, providerName string, request *types.GetTemplateRequest) (*types.Template, error) {
	provider, err := em.GetProvider(providerName)
	if err != nil {
		return nil, err
	}

	template, err := provider.GetTemplate(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("failed to get template: %w", err)
	}

	return template, nil
}

// ListTemplates lists templates using the specified provider
func (em *EmailManager) ListTemplates(ctx context.Context, providerName string, request *types.ListTemplatesRequest) (*types.ListTemplatesResponse, error) {
	provider, err := em.GetProvider(providerName)
	if err != nil {
		return nil, err
	}

	response, err := provider.ListTemplates(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("failed to list templates: %w", err)
	}

	em.logger.WithFields(logrus.Fields{
		"provider": providerName,
		"count":    len(response.Templates),
	}).Debug("Templates listed successfully")

	return response, nil
}

// RenderTemplate renders a template using the specified provider
func (em *EmailManager) RenderTemplate(ctx context.Context, providerName string, request *types.RenderTemplateRequest) (*types.RenderTemplateResponse, error) {
	provider, err := em.GetProvider(providerName)
	if err != nil {
		return nil, err
	}

	response, err := provider.RenderTemplate(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("failed to render template: %w", err)
	}

	em.logger.WithFields(logrus.Fields{
		"provider":    providerName,
		"template_id": request.TemplateID,
	}).Debug("Template rendered successfully")

	return response, nil
}

// HealthCheck performs health check on all providers
func (em *EmailManager) HealthCheck(ctx context.Context) map[string]error {
	results := make(map[string]error)

	for name, provider := range em.providers {
		err := provider.HealthCheck(ctx)
		results[name] = err
	}

	return results
}

// GetStats gets statistics from a provider
func (em *EmailManager) GetStats(ctx context.Context, providerName string) (*types.EmailStats, error) {
	provider, err := em.GetProvider(providerName)
	if err != nil {
		return nil, err
	}

	stats, err := provider.GetStats(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get email stats: %w", err)
	}

	return stats, nil
}

// GetSupportedProviders returns a list of registered providers
func (em *EmailManager) GetSupportedProviders() []string {
	providers := make([]string, 0, len(em.providers))
	for name := range em.providers {
		providers = append(providers, name)
	}
	return providers
}

// GetProviderCapabilities returns capabilities of a provider
func (em *EmailManager) GetProviderCapabilities(providerName string) ([]types.EmailFeature, *types.ConnectionInfo, error) {
	provider, err := em.GetProvider(providerName)
	if err != nil {
		return nil, nil, err
	}

	return provider.GetSupportedFeatures(), provider.GetConnectionInfo(), nil
}

// Close closes all email connections
func (em *EmailManager) Close() error {
	var lastErr error

	for name, provider := range em.providers {
		if err := provider.Close(); err != nil {
			em.logger.WithError(err).WithField("provider", name).Error("Failed to close email provider")
			lastErr = err
		}
	}

	return lastErr
}

// IsProviderConnected checks if a provider is connected
func (em *EmailManager) IsProviderConnected(providerName string) bool {
	provider, err := em.GetProvider(providerName)
	if err != nil {
		return false
	}
	return provider.IsConnected()
}

// GetConnectedProviders returns a list of connected providers
func (em *EmailManager) GetConnectedProviders() []string {
	connected := make([]string, 0)
	for name, provider := range em.providers {
		if provider.IsConnected() {
			connected = append(connected, name)
		}
	}
	return connected
}

// validateSendRequest validates a send request
func (em *EmailManager) validateSendRequest(request *types.SendRequest) error {
	if request.Message == nil {
		return fmt.Errorf("message is required")
	}

	if request.Message.From == nil {
		return fmt.Errorf("from address is required")
	}

	if len(request.Message.To) == 0 {
		return fmt.Errorf("to address is required")
	}

	if request.Message.Subject == "" {
		return fmt.Errorf("subject is required")
	}

	if request.Message.Body == "" && request.Message.HTMLBody == "" {
		return fmt.Errorf("body or html_body is required")
	}

	return nil
}

// validateSendBatchRequest validates a send batch request
func (em *EmailManager) validateSendBatchRequest(request *types.SendBatchRequest) error {
	if len(request.Messages) == 0 {
		return fmt.Errorf("messages are required")
	}

	for i, message := range request.Messages {
		if message == nil {
			return fmt.Errorf("message %d is nil", i)
		}
		if message.From == nil {
			return fmt.Errorf("message %d: from address is required", i)
		}
		if len(message.To) == 0 {
			return fmt.Errorf("message %d: to address is required", i)
		}
		if message.Subject == "" {
			return fmt.Errorf("message %d: subject is required", i)
		}
		if message.Body == "" && message.HTMLBody == "" {
			return fmt.Errorf("message %d: body or html_body is required", i)
		}
	}

	return nil
}

// getMessageSize calculates the approximate size of a message
func (em *EmailManager) getMessageSize(message *types.EmailMessage) int64 {
	size := int64(len(message.Subject) + len(message.Body) + len(message.HTMLBody))

	// Add attachment sizes
	for _, attachment := range message.Attachments {
		size += int64(len(attachment.Data))
	}

	return size
}

// getRecipients returns a string representation of recipients
func (em *EmailManager) getRecipients(message *types.EmailMessage) string {
	recipients := make([]string, 0, len(message.To))
	for _, to := range message.To {
		recipients = append(recipients, to.Address)
	}

	if len(recipients) > 3 {
		return fmt.Sprintf("%s and %d more", recipients[0], len(recipients)-1)
	}

	result := ""
	for i, recipient := range recipients {
		if i > 0 {
			result += ", "
		}
		result += recipient
	}

	return result
}
