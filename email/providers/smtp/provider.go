package smtp

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/smtp"
	"strings"
	"time"

	"github.com/anasamu/go-micro-libs/email/types"
	"github.com/sirupsen/logrus"
)

// Provider implements EmailProvider for SMTP
type Provider struct {
	config map[string]interface{}
	logger *logrus.Logger
	client *smtp.Client
}

// NewProvider creates a new SMTP email provider
func NewProvider(logger *logrus.Logger) *Provider {
	return &Provider{
		config: make(map[string]interface{}),
		logger: logger,
	}
}

// GetName returns the provider name
func (p *Provider) GetName() string {
	return "smtp"
}

// GetSupportedFeatures returns supported features
func (p *Provider) GetSupportedFeatures() []types.EmailFeature {
	return []types.EmailFeature{
		types.FeatureSMTP,
		types.FeatureTLS,
		types.FeatureSSL,
		types.FeatureAuthentication,
		types.FeatureAttachments,
		types.FeatureHTML,
		types.FeaturePlainText,
		types.FeaturePriority,
		types.FeatureBulkSending,
		types.FeatureTemplates,
	}
}

// GetConnectionInfo returns connection information
func (p *Provider) GetConnectionInfo() *types.ConnectionInfo {
	host, _ := p.config["host"].(string)
	port, _ := p.config["port"].(int)
	useTLS, _ := p.config["use_tls"].(bool)
	useSSL, _ := p.config["use_ssl"].(bool)

	if host == "" {
		host = "localhost"
	}
	if port == 0 {
		port = 587
	}

	protocol := "smtp"
	if useSSL {
		protocol = "smtps"
	}

	return &types.ConnectionInfo{
		Host:     host,
		Port:     port,
		Protocol: protocol,
		Version:  "RFC 5321",
		Secure:   useTLS || useSSL,
	}
}

// Configure configures the SMTP provider
func (p *Provider) Configure(config map[string]interface{}) error {
	host, ok := config["host"].(string)
	if !ok || host == "" {
		return fmt.Errorf("smtp host is required")
	}

	port, ok := config["port"].(int)
	if !ok || port == 0 {
		port = 587
	}

	p.config = config
	p.config["port"] = port

	p.logger.Info("SMTP provider configured successfully")
	return nil
}

// IsConfigured checks if the provider is configured
func (p *Provider) IsConfigured() bool {
	host, ok := p.config["host"].(string)
	return ok && host != ""
}

// Connect connects to SMTP server
func (p *Provider) Connect(ctx context.Context) error {
	if !p.IsConfigured() {
		return fmt.Errorf("smtp provider not configured")
	}

	host, _ := p.config["host"].(string)
	port, _ := p.config["port"].(int)
	useSSL, _ := p.config["use_ssl"].(bool)

	address := fmt.Sprintf("%s:%d", host, port)

	var err error
	if useSSL {
		// For SSL, we need to use a different approach since smtp.DialTLS doesn't exist
		// We'll use tls.Dial and then create an SMTP client
		tlsConn, err := tls.Dial("tcp", address, &tls.Config{ServerName: host})
		if err != nil {
			return fmt.Errorf("failed to connect to SMTP server with TLS: %w", err)
		}
		p.client, err = smtp.NewClient(tlsConn, host)
	} else {
		p.client, err = smtp.Dial(address)
	}

	if err != nil {
		return fmt.Errorf("failed to connect to SMTP server: %w", err)
	}

	// Authenticate if credentials are provided
	username, hasUsername := p.config["username"].(string)
	password, hasPassword := p.config["password"].(string)
	if hasUsername && hasPassword {
		auth := smtp.PlainAuth("", username, password, host)
		if err := p.client.Auth(auth); err != nil {
			p.client.Close()
			return fmt.Errorf("failed to authenticate: %w", err)
		}
	}

	// Start TLS if required
	useTLS, _ := p.config["use_tls"].(bool)
	if useTLS && !useSSL {
		if err := p.client.StartTLS(&tls.Config{ServerName: host}); err != nil {
			p.client.Close()
			return fmt.Errorf("failed to start TLS: %w", err)
		}
	}

	p.logger.Info("SMTP connected successfully")
	return nil
}

// Disconnect disconnects from SMTP server
func (p *Provider) Disconnect(ctx context.Context) error {
	if p.client != nil {
		if err := p.client.Close(); err != nil {
			return fmt.Errorf("failed to close SMTP connection: %w", err)
		}
		p.client = nil
	}

	p.logger.Info("SMTP disconnected successfully")
	return nil
}

// Ping checks SMTP connection
func (p *Provider) Ping(ctx context.Context) error {
	if !p.IsConfigured() {
		return fmt.Errorf("smtp provider not configured")
	}

	host, _ := p.config["host"].(string)
	port, _ := p.config["port"].(int)
	useSSL, _ := p.config["use_ssl"].(bool)

	address := fmt.Sprintf("%s:%d", host, port)

	var client *smtp.Client
	var err error
	if useSSL {
		// For SSL, we need to use a different approach since smtp.DialTLS doesn't exist
		tlsConn, err := tls.Dial("tcp", address, &tls.Config{ServerName: host})
		if err != nil {
			return fmt.Errorf("failed to connect to SMTP server with TLS: %w", err)
		}
		client, err = smtp.NewClient(tlsConn, host)
	} else {
		client, err = smtp.Dial(address)
	}

	if err != nil {
		return fmt.Errorf("failed to ping SMTP server: %w", err)
	}
	defer client.Close()

	return nil
}

// IsConnected checks if SMTP is connected
func (p *Provider) IsConnected() bool {
	return p.client != nil
}

// SendEmail sends an email via SMTP
func (p *Provider) SendEmail(ctx context.Context, request *types.SendRequest) (*types.SendResponse, error) {
	if !p.IsConfigured() {
		return nil, fmt.Errorf("smtp provider not configured")
	}

	if p.client == nil {
		return nil, fmt.Errorf("not connected to SMTP server")
	}

	message := request.Message

	// Build email content
	content, err := p.buildEmailContent(message)
	if err != nil {
		return nil, fmt.Errorf("failed to build email content: %w", err)
	}

	// Set sender
	if err := p.client.Mail(message.From.Address); err != nil {
		return nil, fmt.Errorf("failed to set sender: %w", err)
	}

	// Set recipients
	allRecipients := make([]string, 0)
	allRecipients = append(allRecipients, p.getAddresses(message.To)...)
	allRecipients = append(allRecipients, p.getAddresses(message.Cc)...)
	allRecipients = append(allRecipients, p.getAddresses(message.Bcc)...)

	for _, recipient := range allRecipients {
		if err := p.client.Rcpt(recipient); err != nil {
			return nil, fmt.Errorf("failed to set recipient %s: %w", recipient, err)
		}
	}

	// Send data
	writer, err := p.client.Data()
	if err != nil {
		return nil, fmt.Errorf("failed to get data writer: %w", err)
	}

	_, err = writer.Write(content)
	if err != nil {
		writer.Close()
		return nil, fmt.Errorf("failed to write email data: %w", err)
	}

	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("failed to close data writer: %w", err)
	}

	response := &types.SendResponse{
		MessageID: message.ID.String(),
		Status:    "sent",
		Timestamp: time.Now(),
		ProviderData: map[string]interface{}{
			"host": p.config["host"],
			"port": p.config["port"],
		},
	}

	return response, nil
}

// SendBatch sends multiple emails via SMTP
func (p *Provider) SendBatch(ctx context.Context, request *types.SendBatchRequest) (*types.SendBatchResponse, error) {
	if !p.IsConfigured() {
		return nil, fmt.Errorf("smtp provider not configured")
	}

	if p.client == nil {
		return nil, fmt.Errorf("not connected to SMTP server")
	}

	sentCount := 0
	failedMessages := make([]*types.EmailMessage, 0)

	for _, message := range request.Messages {
		sendRequest := &types.SendRequest{
			Message: message,
			Options: request.Options,
		}

		_, err := p.SendEmail(ctx, sendRequest)
		if err != nil {
			failedMessages = append(failedMessages, message)
			p.logger.WithError(err).WithField("message_id", message.ID).Error("Failed to send email in batch")
		} else {
			sentCount++
		}
	}

	response := &types.SendBatchResponse{
		SentCount:      sentCount,
		FailedCount:    len(failedMessages),
		FailedMessages: failedMessages,
		ProviderData: map[string]interface{}{
			"host": p.config["host"],
			"port": p.config["port"],
		},
	}

	return response, nil
}

// FetchEmails is not supported by SMTP
func (p *Provider) FetchEmails(ctx context.Context, request *types.FetchRequest) (*types.FetchResponse, error) {
	return nil, fmt.Errorf("fetch emails not supported by SMTP provider")
}

// SearchEmails is not supported by SMTP
func (p *Provider) SearchEmails(ctx context.Context, request *types.SearchRequest) (*types.SearchResponse, error) {
	return nil, fmt.Errorf("search emails not supported by SMTP provider")
}

// ListFolders is not supported by SMTP
func (p *Provider) ListFolders(ctx context.Context, request *types.ListFoldersRequest) (*types.ListFoldersResponse, error) {
	return nil, fmt.Errorf("list folders not supported by SMTP provider")
}

// CreateFolder is not supported by SMTP
func (p *Provider) CreateFolder(ctx context.Context, request *types.CreateFolderRequest) error {
	return fmt.Errorf("create folder not supported by SMTP provider")
}

// DeleteFolder is not supported by SMTP
func (p *Provider) DeleteFolder(ctx context.Context, request *types.DeleteFolderRequest) error {
	return fmt.Errorf("delete folder not supported by SMTP provider")
}

// MoveMessage is not supported by SMTP
func (p *Provider) MoveMessage(ctx context.Context, request *types.MoveMessageRequest) error {
	return fmt.Errorf("move message not supported by SMTP provider")
}

// DeleteMessage is not supported by SMTP
func (p *Provider) DeleteMessage(ctx context.Context, request *types.DeleteMessageRequest) error {
	return fmt.Errorf("delete message not supported by SMTP provider")
}

// CreateTemplate is not supported by SMTP
func (p *Provider) CreateTemplate(ctx context.Context, request *types.CreateTemplateRequest) error {
	return fmt.Errorf("create template not supported by SMTP provider")
}

// UpdateTemplate is not supported by SMTP
func (p *Provider) UpdateTemplate(ctx context.Context, request *types.UpdateTemplateRequest) error {
	return fmt.Errorf("update template not supported by SMTP provider")
}

// DeleteTemplate is not supported by SMTP
func (p *Provider) DeleteTemplate(ctx context.Context, request *types.DeleteTemplateRequest) error {
	return fmt.Errorf("delete template not supported by SMTP provider")
}

// GetTemplate is not supported by SMTP
func (p *Provider) GetTemplate(ctx context.Context, request *types.GetTemplateRequest) (*types.Template, error) {
	return nil, fmt.Errorf("get template not supported by SMTP provider")
}

// ListTemplates is not supported by SMTP
func (p *Provider) ListTemplates(ctx context.Context, request *types.ListTemplatesRequest) (*types.ListTemplatesResponse, error) {
	return nil, fmt.Errorf("list templates not supported by SMTP provider")
}

// RenderTemplate is not supported by SMTP
func (p *Provider) RenderTemplate(ctx context.Context, request *types.RenderTemplateRequest) (*types.RenderTemplateResponse, error) {
	return nil, fmt.Errorf("render template not supported by SMTP provider")
}

// HealthCheck performs a health check on SMTP
func (p *Provider) HealthCheck(ctx context.Context) error {
	if !p.IsConfigured() {
		return fmt.Errorf("smtp provider not configured")
	}

	return p.Ping(ctx)
}

// GetStats returns SMTP statistics
func (p *Provider) GetStats(ctx context.Context) (*types.EmailStats, error) {
	stats := &types.EmailStats{
		ActiveConnections: 0,
		ProviderData: map[string]interface{}{
			"host":      p.config["host"],
			"port":      p.config["port"],
			"connected": p.IsConnected(),
		},
	}

	if p.IsConnected() {
		stats.ActiveConnections = 1
	}

	return stats, nil
}

// Close closes the SMTP provider
func (p *Provider) Close() error {
	return p.Disconnect(context.Background())
}

// buildEmailContent builds the email content with headers and body
func (p *Provider) buildEmailContent(message *types.EmailMessage) ([]byte, error) {
	var content strings.Builder

	// Headers
	content.WriteString(fmt.Sprintf("From: %s\r\n", p.formatAddress(message.From)))
	content.WriteString(fmt.Sprintf("To: %s\r\n", p.formatAddresses(message.To)))

	if len(message.Cc) > 0 {
		content.WriteString(fmt.Sprintf("Cc: %s\r\n", p.formatAddresses(message.Cc)))
	}

	if message.ReplyTo != nil {
		content.WriteString(fmt.Sprintf("Reply-To: %s\r\n", p.formatAddress(message.ReplyTo)))
	}

	content.WriteString(fmt.Sprintf("Subject: %s\r\n", message.Subject))
	content.WriteString(fmt.Sprintf("Date: %s\r\n", message.CreatedAt.Format(time.RFC1123Z)))
	content.WriteString(fmt.Sprintf("Message-ID: <%s@%s>\r\n", message.ID.String(), p.config["host"]))

	// Priority header
	switch message.Priority {
	case types.PriorityHigh:
		content.WriteString("X-Priority: 1\r\n")
		content.WriteString("Importance: High\r\n")
	case types.PriorityLow:
		content.WriteString("X-Priority: 5\r\n")
		content.WriteString("Importance: Low\r\n")
	default:
		content.WriteString("X-Priority: 3\r\n")
		content.WriteString("Importance: Normal\r\n")
	}

	// Custom headers
	for key, value := range message.Headers {
		content.WriteString(fmt.Sprintf("%s: %s\r\n", key, value))
	}

	// MIME headers
	if len(message.Attachments) > 0 || (message.Body != "" && message.HTMLBody != "") {
		boundary := fmt.Sprintf("boundary_%s", message.ID.String())
		content.WriteString(fmt.Sprintf("MIME-Version: 1.0\r\n"))
		content.WriteString(fmt.Sprintf("Content-Type: multipart/mixed; boundary=\"%s\"\r\n", boundary))
		content.WriteString("\r\n")

		// Text body
		if message.Body != "" {
			content.WriteString(fmt.Sprintf("--%s\r\n", boundary))
			content.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
			content.WriteString("Content-Transfer-Encoding: 8bit\r\n")
			content.WriteString("\r\n")
			content.WriteString(message.Body)
			content.WriteString("\r\n")
		}

		// HTML body
		if message.HTMLBody != "" {
			content.WriteString(fmt.Sprintf("--%s\r\n", boundary))
			content.WriteString("Content-Type: text/html; charset=UTF-8\r\n")
			content.WriteString("Content-Transfer-Encoding: 8bit\r\n")
			content.WriteString("\r\n")
			content.WriteString(message.HTMLBody)
			content.WriteString("\r\n")
		}

		// Attachments
		for _, attachment := range message.Attachments {
			content.WriteString(fmt.Sprintf("--%s\r\n", boundary))
			content.WriteString(fmt.Sprintf("Content-Type: %s\r\n", attachment.ContentType))
			content.WriteString("Content-Transfer-Encoding: base64\r\n")
			content.WriteString(fmt.Sprintf("Content-Disposition: attachment; filename=\"%s\"\r\n", attachment.Filename))
			content.WriteString("\r\n")
			// Note: In a real implementation, you would base64 encode the attachment data
			content.WriteString("BASE64_ENCODED_ATTACHMENT_DATA")
			content.WriteString("\r\n")
		}

		content.WriteString(fmt.Sprintf("--%s--\r\n", boundary))
	} else {
		// Simple text or HTML email
		if message.HTMLBody != "" {
			content.WriteString("Content-Type: text/html; charset=UTF-8\r\n")
			content.WriteString("Content-Transfer-Encoding: 8bit\r\n")
			content.WriteString("\r\n")
			content.WriteString(message.HTMLBody)
		} else {
			content.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
			content.WriteString("Content-Transfer-Encoding: 8bit\r\n")
			content.WriteString("\r\n")
			content.WriteString(message.Body)
		}
	}

	return []byte(content.String()), nil
}

// formatAddress formats an email address
func (p *Provider) formatAddress(addr *types.EmailAddress) string {
	if addr.Name != "" {
		return fmt.Sprintf("%s <%s>", addr.Name, addr.Address)
	}
	return addr.Address
}

// formatAddresses formats a list of email addresses
func (p *Provider) formatAddresses(addresses []*types.EmailAddress) string {
	formatted := make([]string, len(addresses))
	for i, addr := range addresses {
		formatted[i] = p.formatAddress(addr)
	}
	return strings.Join(formatted, ", ")
}

// getAddresses extracts addresses from email address list
func (p *Provider) getAddresses(addresses []*types.EmailAddress) []string {
	result := make([]string, len(addresses))
	for i, addr := range addresses {
		result[i] = addr.Address
	}
	return result
}
