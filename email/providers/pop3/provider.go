package pop3

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/anasamu/go-micro-libs/email/types"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

// Provider implements EmailProvider for POP3
type Provider struct {
	config map[string]interface{}
	logger *logrus.Logger
	conn   net.Conn
}

// NewProvider creates a new POP3 email provider
func NewProvider(logger *logrus.Logger) *Provider {
	return &Provider{
		config: make(map[string]interface{}),
		logger: logger,
	}
}

// GetName returns the provider name
func (p *Provider) GetName() string {
	return "pop3"
}

// GetSupportedFeatures returns supported features
func (p *Provider) GetSupportedFeatures() []types.EmailFeature {
	return []types.EmailFeature{
		types.FeaturePOP3,
		types.FeatureTLS,
		types.FeatureSSL,
		types.FeatureAuthentication,
		types.FeatureHTML,
		types.FeaturePlainText,
		types.FeatureSearching,
	}
}

// GetConnectionInfo returns connection information
func (p *Provider) GetConnectionInfo() *types.ConnectionInfo {
	host, _ := p.config["host"].(string)
	port, _ := p.config["port"].(int)
	useSSL, _ := p.config["use_ssl"].(bool)

	if host == "" {
		host = "localhost"
	}
	if port == 0 {
		port = 110
	}

	protocol := "pop3"
	if useSSL {
		protocol = "pop3s"
	}

	return &types.ConnectionInfo{
		Host:     host,
		Port:     port,
		Protocol: protocol,
		Version:  "RFC 1939",
		Secure:   useSSL,
	}
}

// Configure configures the POP3 provider
func (p *Provider) Configure(config map[string]interface{}) error {
	host, ok := config["host"].(string)
	if !ok || host == "" {
		return fmt.Errorf("pop3 host is required")
	}

	port, ok := config["port"].(int)
	if !ok || port == 0 {
		port = 110
	}

	p.config = config
	p.config["port"] = port

	p.logger.Info("POP3 provider configured successfully")
	return nil
}

// IsConfigured checks if the provider is configured
func (p *Provider) IsConfigured() bool {
	host, ok := p.config["host"].(string)
	return ok && host != ""
}

// Connect connects to POP3 server
func (p *Provider) Connect(ctx context.Context) error {
	if !p.IsConfigured() {
		return fmt.Errorf("pop3 provider not configured")
	}

	host, _ := p.config["host"].(string)
	port, _ := p.config["port"].(int)
	useSSL, _ := p.config["use_ssl"].(bool)

	address := fmt.Sprintf("%s:%d", host, port)

	var err error
	if useSSL {
		p.conn, err = tls.Dial("tcp", address, &tls.Config{ServerName: host})
	} else {
		p.conn, err = net.Dial("tcp", address)
	}

	if err != nil {
		return fmt.Errorf("failed to connect to POP3 server: %w", err)
	}

	// Read welcome message
	response, err := p.readResponse()
	if err != nil {
		p.conn.Close()
		return fmt.Errorf("failed to read welcome message: %w", err)
	}

	if !strings.HasPrefix(response, "+OK") {
		p.conn.Close()
		return fmt.Errorf("unexpected welcome message: %s", response)
	}

	// Authenticate if credentials are provided
	username, hasUsername := p.config["username"].(string)
	password, hasPassword := p.config["password"].(string)
	if hasUsername && hasPassword {
		if err := p.authenticate(username, password); err != nil {
			p.conn.Close()
			return fmt.Errorf("failed to authenticate: %w", err)
		}
	}

	p.logger.Info("POP3 connected successfully")
	return nil
}

// Disconnect disconnects from POP3 server
func (p *Provider) Disconnect(ctx context.Context) error {
	if p.conn != nil {
		// Send QUIT command
		p.sendCommand("QUIT")
		p.conn.Close()
		p.conn = nil
	}

	p.logger.Info("POP3 disconnected successfully")
	return nil
}

// Ping checks POP3 connection
func (p *Provider) Ping(ctx context.Context) error {
	if !p.IsConfigured() {
		return fmt.Errorf("pop3 provider not configured")
	}

	host, _ := p.config["host"].(string)
	port, _ := p.config["port"].(int)
	useSSL, _ := p.config["use_ssl"].(bool)

	address := fmt.Sprintf("%s:%d", host, port)

	var conn net.Conn
	var err error
	if useSSL {
		conn, err = tls.Dial("tcp", address, &tls.Config{ServerName: host})
	} else {
		conn, err = net.Dial("tcp", address)
	}

	if err != nil {
		return fmt.Errorf("failed to ping POP3 server: %w", err)
	}
	defer conn.Close()

	// Read welcome message
	response := make([]byte, 1024)
	n, err := conn.Read(response)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	if !strings.HasPrefix(string(response[:n]), "+OK") {
		return fmt.Errorf("unexpected response: %s", string(response[:n]))
	}

	return nil
}

// IsConnected checks if POP3 is connected
func (p *Provider) IsConnected() bool {
	return p.conn != nil
}

// SendEmail is not supported by POP3
func (p *Provider) SendEmail(ctx context.Context, request *types.SendRequest) (*types.SendResponse, error) {
	return nil, fmt.Errorf("send email not supported by POP3 provider")
}

// SendBatch is not supported by POP3
func (p *Provider) SendBatch(ctx context.Context, request *types.SendBatchRequest) (*types.SendBatchResponse, error) {
	return nil, fmt.Errorf("send batch not supported by POP3 provider")
}

// FetchEmails fetches emails from POP3 server
func (p *Provider) FetchEmails(ctx context.Context, request *types.FetchRequest) (*types.FetchResponse, error) {
	if !p.IsConfigured() {
		return nil, fmt.Errorf("pop3 provider not configured")
	}

	if p.conn == nil {
		return nil, fmt.Errorf("not connected to POP3 server")
	}

	// Get message count
	response, err := p.sendCommand("STAT")
	if err != nil {
		return nil, fmt.Errorf("failed to get message count: %w", err)
	}

	parts := strings.Fields(response)
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid STAT response: %s", response)
	}

	messageCount, err := strconv.Atoi(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid message count: %w", err)
	}

	messages := make([]*types.EmailMessage, 0)

	// Fetch messages
	start := 1
	limit := messageCount

	if request.Sequence > 0 {
		start = request.Sequence
		limit = request.Sequence
	}

	for i := start; i <= limit; i++ {
		message, err := p.fetchMessage(i)
		if err != nil {
			p.logger.WithError(err).WithField("sequence", i).Warn("Failed to fetch message")
			continue
		}
		messages = append(messages, message)
	}

	fetchResponse := &types.FetchResponse{
		Messages: messages,
		Total:    len(messages),
		ProviderData: map[string]interface{}{
			"host":          p.config["host"],
			"port":          p.config["port"],
			"message_count": messageCount,
		},
	}

	return fetchResponse, nil
}

// SearchEmails searches emails on POP3 server
func (p *Provider) SearchEmails(ctx context.Context, request *types.SearchRequest) (*types.SearchResponse, error) {
	if !p.IsConfigured() {
		return nil, fmt.Errorf("pop3 provider not configured")
	}

	if p.conn == nil {
		return nil, fmt.Errorf("not connected to POP3 server")
	}

	// Get all messages first
	fetchRequest := &types.FetchRequest{}
	fetchResponse, err := p.FetchEmails(ctx, fetchRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch messages for search: %w", err)
	}

	// Filter messages based on search criteria
	filteredMessages := make([]*types.EmailMessage, 0)

	for _, message := range fetchResponse.Messages {
		if p.matchesSearchCriteria(message, request) {
			filteredMessages = append(filteredMessages, message)
		}
	}

	searchResponse := &types.SearchResponse{
		Messages: filteredMessages,
		Total:    len(filteredMessages),
		ProviderData: map[string]interface{}{
			"host":  p.config["host"],
			"port":  p.config["port"],
			"query": request.Query,
		},
	}

	return searchResponse, nil
}

// ListFolders is not supported by POP3
func (p *Provider) ListFolders(ctx context.Context, request *types.ListFoldersRequest) (*types.ListFoldersResponse, error) {
	return nil, fmt.Errorf("list folders not supported by POP3 provider")
}

// CreateFolder is not supported by POP3
func (p *Provider) CreateFolder(ctx context.Context, request *types.CreateFolderRequest) error {
	return fmt.Errorf("create folder not supported by POP3 provider")
}

// DeleteFolder is not supported by POP3
func (p *Provider) DeleteFolder(ctx context.Context, request *types.DeleteFolderRequest) error {
	return fmt.Errorf("delete folder not supported by POP3 provider")
}

// MoveMessage is not supported by POP3
func (p *Provider) MoveMessage(ctx context.Context, request *types.MoveMessageRequest) error {
	return fmt.Errorf("move message not supported by POP3 provider")
}

// DeleteMessage deletes a message from POP3 server
func (p *Provider) DeleteMessage(ctx context.Context, request *types.DeleteMessageRequest) error {
	if !p.IsConfigured() {
		return fmt.Errorf("pop3 provider not configured")
	}

	if p.conn == nil {
		return fmt.Errorf("not connected to POP3 server")
	}

	sequence, err := strconv.Atoi(request.UID)
	if err != nil {
		return fmt.Errorf("invalid sequence number: %w", err)
	}

	response, err := p.sendCommand(fmt.Sprintf("DELE %d", sequence))
	if err != nil {
		return fmt.Errorf("failed to delete message: %w", err)
	}

	if !strings.HasPrefix(response, "+OK") {
		return fmt.Errorf("failed to delete message: %s", response)
	}

	p.logger.WithFields(logrus.Fields{
		"sequence": sequence,
	}).Info("Message deleted successfully")

	return nil
}

// CreateTemplate is not supported by POP3
func (p *Provider) CreateTemplate(ctx context.Context, request *types.CreateTemplateRequest) error {
	return fmt.Errorf("create template not supported by POP3 provider")
}

// UpdateTemplate is not supported by POP3
func (p *Provider) UpdateTemplate(ctx context.Context, request *types.UpdateTemplateRequest) error {
	return fmt.Errorf("update template not supported by POP3 provider")
}

// DeleteTemplate is not supported by POP3
func (p *Provider) DeleteTemplate(ctx context.Context, request *types.DeleteTemplateRequest) error {
	return fmt.Errorf("delete template not supported by POP3 provider")
}

// GetTemplate is not supported by POP3
func (p *Provider) GetTemplate(ctx context.Context, request *types.GetTemplateRequest) (*types.Template, error) {
	return nil, fmt.Errorf("get template not supported by POP3 provider")
}

// ListTemplates is not supported by POP3
func (p *Provider) ListTemplates(ctx context.Context, request *types.ListTemplatesRequest) (*types.ListTemplatesResponse, error) {
	return nil, fmt.Errorf("list templates not supported by POP3 provider")
}

// RenderTemplate is not supported by POP3
func (p *Provider) RenderTemplate(ctx context.Context, request *types.RenderTemplateRequest) (*types.RenderTemplateResponse, error) {
	return nil, fmt.Errorf("render template not supported by POP3 provider")
}

// HealthCheck performs a health check on POP3
func (p *Provider) HealthCheck(ctx context.Context) error {
	if !p.IsConfigured() {
		return fmt.Errorf("pop3 provider not configured")
	}

	return p.Ping(ctx)
}

// GetStats returns POP3 statistics
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

// Close closes the POP3 provider
func (p *Provider) Close() error {
	return p.Disconnect(context.Background())
}

// authenticate authenticates with POP3 server
func (p *Provider) authenticate(username, password string) error {
	// Send USER command
	response, err := p.sendCommand(fmt.Sprintf("USER %s", username))
	if err != nil {
		return fmt.Errorf("failed to send USER command: %w", err)
	}

	if !strings.HasPrefix(response, "+OK") {
		return fmt.Errorf("USER command failed: %s", response)
	}

	// Send PASS command
	response, err = p.sendCommand(fmt.Sprintf("PASS %s", password))
	if err != nil {
		return fmt.Errorf("failed to send PASS command: %w", err)
	}

	if !strings.HasPrefix(response, "+OK") {
		return fmt.Errorf("PASS command failed: %s", response)
	}

	return nil
}

// sendCommand sends a command to POP3 server
func (p *Provider) sendCommand(command string) (string, error) {
	if p.conn == nil {
		return "", fmt.Errorf("not connected")
	}

	_, err := p.conn.Write([]byte(command + "\r\n"))
	if err != nil {
		return "", fmt.Errorf("failed to send command: %w", err)
	}

	return p.readResponse()
}

// readResponse reads response from POP3 server
func (p *Provider) readResponse() (string, error) {
	if p.conn == nil {
		return "", fmt.Errorf("not connected")
	}

	response := make([]byte, 1024)
	n, err := p.conn.Read(response)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	return strings.TrimSpace(string(response[:n])), nil
}

// fetchMessage fetches a single message by sequence number
func (p *Provider) fetchMessage(sequence int) (*types.EmailMessage, error) {
	// Get message size first
	response, err := p.sendCommand(fmt.Sprintf("LIST %d", sequence))
	if err != nil {
		return nil, fmt.Errorf("failed to get message size: %w", err)
	}

	parts := strings.Fields(response)
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid LIST response: %s", response)
	}

	// Retrieve message
	response, err = p.sendCommand(fmt.Sprintf("RETR %d", sequence))
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve message: %w", err)
	}

	// Read message data until end marker
	var messageData strings.Builder
	messageData.WriteString(response)
	messageData.WriteString("\r\n")

	for {
		line, err := p.readResponse()
		if err != nil {
			return nil, fmt.Errorf("failed to read message data: %w", err)
		}

		if line == "." {
			break
		}

		// Handle dot stuffing
		if strings.HasPrefix(line, "..") {
			line = line[1:]
		}

		messageData.WriteString(line)
		messageData.WriteString("\r\n")
	}

	// Parse message (simplified parsing)
	message := p.parseMessage(messageData.String(), sequence)

	return message, nil
}

// parseMessage parses a raw email message
func (p *Provider) parseMessage(rawMessage string, sequence int) *types.EmailMessage {
	message := &types.EmailMessage{
		ID:        uuid.New(),
		CreatedAt: time.Now(),
		ProviderData: map[string]interface{}{
			"sequence": sequence,
		},
	}

	lines := strings.Split(rawMessage, "\r\n")
	headerEnd := -1

	// Find header end
	for i, line := range lines {
		if line == "" {
			headerEnd = i
			break
		}
	}

	if headerEnd == -1 {
		headerEnd = len(lines)
	}

	// Parse headers
	for i := 0; i < headerEnd; i++ {
		line := lines[i]
		if strings.Contains(line, ":") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])

				switch strings.ToLower(key) {
				case "from":
					message.From = p.parseAddress(value)
				case "to":
					message.To = p.parseAddresses(value)
				case "cc":
					message.Cc = p.parseAddresses(value)
				case "subject":
					message.Subject = value
				case "date":
					if date, err := time.Parse(time.RFC1123Z, value); err == nil {
						message.CreatedAt = date
					}
				}
			}
		}
	}

	// Parse body
	if headerEnd+1 < len(lines) {
		bodyLines := lines[headerEnd+1:]
		message.Body = strings.Join(bodyLines, "\r\n")
	}

	return message
}

// parseAddress parses a single email address
func (p *Provider) parseAddress(addressStr string) *types.EmailAddress {
	// Simple parsing - in real implementation, use proper email parsing
	addressStr = strings.TrimSpace(addressStr)
	if strings.Contains(addressStr, "<") && strings.Contains(addressStr, ">") {
		// Format: "Name <email@domain.com>"
		start := strings.Index(addressStr, "<")
		end := strings.Index(addressStr, ">")
		if start != -1 && end != -1 && end > start {
			name := strings.TrimSpace(addressStr[:start])
			address := strings.TrimSpace(addressStr[start+1 : end])
			return &types.EmailAddress{
				Name:    name,
				Address: address,
			}
		}
	}

	// Simple email address
	return &types.EmailAddress{
		Address: addressStr,
	}
}

// parseAddresses parses multiple email addresses
func (p *Provider) parseAddresses(addressesStr string) []*types.EmailAddress {
	addresses := strings.Split(addressesStr, ",")
	result := make([]*types.EmailAddress, 0, len(addresses))

	for _, addr := range addresses {
		if parsed := p.parseAddress(addr); parsed != nil {
			result = append(result, parsed)
		}
	}

	return result
}

// matchesSearchCriteria checks if a message matches search criteria
func (p *Provider) matchesSearchCriteria(message *types.EmailMessage, request *types.SearchRequest) bool {
	if request.Query != "" {
		query := strings.ToLower(request.Query)
		if !strings.Contains(strings.ToLower(message.Subject), query) &&
			!strings.Contains(strings.ToLower(message.Body), query) {
			return false
		}
	}

	if request.From != "" {
		if message.From == nil || !strings.Contains(strings.ToLower(message.From.Address), strings.ToLower(request.From)) {
			return false
		}
	}

	if request.To != "" {
		found := false
		for _, to := range message.To {
			if strings.Contains(strings.ToLower(to.Address), strings.ToLower(request.To)) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	if request.Subject != "" {
		if !strings.Contains(strings.ToLower(message.Subject), strings.ToLower(request.Subject)) {
			return false
		}
	}

	if request.Since != nil {
		if message.CreatedAt.Before(*request.Since) {
			return false
		}
	}

	if request.Before != nil {
		if message.CreatedAt.After(*request.Before) {
			return false
		}
	}

	return true
}
