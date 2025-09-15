package imap

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

// Provider implements EmailProvider for IMAP
type Provider struct {
	config map[string]interface{}
	logger *logrus.Logger
	conn   net.Conn
}

// NewProvider creates a new IMAP email provider
func NewProvider(logger *logrus.Logger) *Provider {
	return &Provider{
		config: make(map[string]interface{}),
		logger: logger,
	}
}

// GetName returns the provider name
func (p *Provider) GetName() string {
	return "imap"
}

// GetSupportedFeatures returns supported features
func (p *Provider) GetSupportedFeatures() []types.EmailFeature {
	return []types.EmailFeature{
		types.FeatureIMAP,
		types.FeatureTLS,
		types.FeatureSSL,
		types.FeatureAuthentication,
		types.FeatureHTML,
		types.FeaturePlainText,
		types.FeatureSearching,
		types.FeatureFiltering,
		types.FeatureFolders,
		types.FeatureLabels,
		types.FeatureThreading,
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
		port = 143
	}

	protocol := "imap"
	if useSSL {
		protocol = "imaps"
	}

	return &types.ConnectionInfo{
		Host:     host,
		Port:     port,
		Protocol: protocol,
		Version:  "RFC 3501",
		Secure:   useSSL,
	}
}

// Configure configures the IMAP provider
func (p *Provider) Configure(config map[string]interface{}) error {
	host, ok := config["host"].(string)
	if !ok || host == "" {
		return fmt.Errorf("imap host is required")
	}

	port, ok := config["port"].(int)
	if !ok || port == 0 {
		port = 143
	}

	p.config = config
	p.config["port"] = port

	p.logger.Info("IMAP provider configured successfully")
	return nil
}

// IsConfigured checks if the provider is configured
func (p *Provider) IsConfigured() bool {
	host, ok := p.config["host"].(string)
	return ok && host != ""
}

// Connect connects to IMAP server
func (p *Provider) Connect(ctx context.Context) error {
	if !p.IsConfigured() {
		return fmt.Errorf("imap provider not configured")
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
		return fmt.Errorf("failed to connect to IMAP server: %w", err)
	}

	// Read welcome message
	response, err := p.readResponse()
	if err != nil {
		p.conn.Close()
		return fmt.Errorf("failed to read welcome message: %w", err)
	}

	if !strings.HasPrefix(response, "* OK") {
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

	p.logger.Info("IMAP connected successfully")
	return nil
}

// Disconnect disconnects from IMAP server
func (p *Provider) Disconnect(ctx context.Context) error {
	if p.conn != nil {
		// Send LOGOUT command
		p.sendCommand("LOGOUT")
		p.conn.Close()
		p.conn = nil
	}

	p.logger.Info("IMAP disconnected successfully")
	return nil
}

// Ping checks IMAP connection
func (p *Provider) Ping(ctx context.Context) error {
	if !p.IsConfigured() {
		return fmt.Errorf("imap provider not configured")
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
		return fmt.Errorf("failed to ping IMAP server: %w", err)
	}
	defer conn.Close()

	// Read welcome message
	response := make([]byte, 1024)
	n, err := conn.Read(response)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	if !strings.HasPrefix(string(response[:n]), "* OK") {
		return fmt.Errorf("unexpected response: %s", string(response[:n]))
	}

	return nil
}

// IsConnected checks if IMAP is connected
func (p *Provider) IsConnected() bool {
	return p.conn != nil
}

// SendEmail is not supported by IMAP
func (p *Provider) SendEmail(ctx context.Context, request *types.SendRequest) (*types.SendResponse, error) {
	return nil, fmt.Errorf("send email not supported by IMAP provider")
}

// SendBatch is not supported by IMAP
func (p *Provider) SendBatch(ctx context.Context, request *types.SendBatchRequest) (*types.SendBatchResponse, error) {
	return nil, fmt.Errorf("send batch not supported by IMAP provider")
}

// FetchEmails fetches emails from IMAP server
func (p *Provider) FetchEmails(ctx context.Context, request *types.FetchRequest) (*types.FetchResponse, error) {
	if !p.IsConfigured() {
		return nil, fmt.Errorf("imap provider not configured")
	}

	if p.conn == nil {
		return nil, fmt.Errorf("not connected to IMAP server")
	}

	folder := request.Folder
	if folder == "" {
		folder = "INBOX"
	}

	// Select folder
	if err := p.selectFolder(folder); err != nil {
		return nil, fmt.Errorf("failed to select folder: %w", err)
	}

	// Get message count
	response, err := p.sendCommand("STATUS " + folder + " (MESSAGES)")
	if err != nil {
		return nil, fmt.Errorf("failed to get message count: %w", err)
	}

	// Parse message count from response
	messageCount := p.parseMessageCount(response)

	messages := make([]*types.EmailMessage, 0)

	// Fetch messages
	if request.UID != "" {
		// Fetch specific message by UID
		message, err := p.fetchMessageByUID(request.UID)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch message by UID: %w", err)
		}
		messages = append(messages, message)
	} else {
		// Fetch all messages or range
		start := 1
		limit := messageCount

		if request.Sequence > 0 {
			start = request.Sequence
			limit = request.Sequence
		}

		for i := start; i <= limit; i++ {
			message, err := p.fetchMessageBySequence(i)
			if err != nil {
				p.logger.WithError(err).WithField("sequence", i).Warn("Failed to fetch message")
				continue
			}
			messages = append(messages, message)
		}
	}

	fetchResponse := &types.FetchResponse{
		Messages: messages,
		Total:    len(messages),
		ProviderData: map[string]interface{}{
			"host":          p.config["host"],
			"port":          p.config["port"],
			"folder":        folder,
			"message_count": messageCount,
		},
	}

	return fetchResponse, nil
}

// SearchEmails searches emails on IMAP server
func (p *Provider) SearchEmails(ctx context.Context, request *types.SearchRequest) (*types.SearchResponse, error) {
	if !p.IsConfigured() {
		return nil, fmt.Errorf("imap provider not configured")
	}

	if p.conn == nil {
		return nil, fmt.Errorf("not connected to IMAP server")
	}

	folder := request.Folder
	if folder == "" {
		folder = "INBOX"
	}

	// Select folder
	if err := p.selectFolder(folder); err != nil {
		return nil, fmt.Errorf("failed to select folder: %w", err)
	}

	// Build search criteria
	searchCriteria := p.buildSearchCriteria(request)

	// Execute search
	response, err := p.sendCommand("SEARCH " + searchCriteria)
	if err != nil {
		return nil, fmt.Errorf("failed to search messages: %w", err)
	}

	// Parse search results
	uids := p.parseSearchResults(response)

	messages := make([]*types.EmailMessage, 0)

	// Fetch messages by UID
	for _, uid := range uids {
		message, err := p.fetchMessageByUID(uid)
		if err != nil {
			p.logger.WithError(err).WithField("uid", uid).Warn("Failed to fetch message")
			continue
		}
		messages = append(messages, message)
	}

	searchResponse := &types.SearchResponse{
		Messages: messages,
		Total:    len(messages),
		ProviderData: map[string]interface{}{
			"host":   p.config["host"],
			"port":   p.config["port"],
			"folder": folder,
			"query":  request.Query,
		},
	}

	return searchResponse, nil
}

// ListFolders lists folders on IMAP server
func (p *Provider) ListFolders(ctx context.Context, request *types.ListFoldersRequest) (*types.ListFoldersResponse, error) {
	if !p.IsConfigured() {
		return nil, fmt.Errorf("imap provider not configured")
	}

	if p.conn == nil {
		return nil, fmt.Errorf("not connected to IMAP server")
	}

	// List folders
	response, err := p.sendCommand("LIST \"\" \"*\"")
	if err != nil {
		return nil, fmt.Errorf("failed to list folders: %w", err)
	}

	folders := p.parseFolderList(response)

	listResponse := &types.ListFoldersResponse{
		Folders: folders,
		ProviderData: map[string]interface{}{
			"host": p.config["host"],
			"port": p.config["port"],
		},
	}

	return listResponse, nil
}

// CreateFolder creates a folder on IMAP server
func (p *Provider) CreateFolder(ctx context.Context, request *types.CreateFolderRequest) error {
	if !p.IsConfigured() {
		return fmt.Errorf("imap provider not configured")
	}

	if p.conn == nil {
		return fmt.Errorf("not connected to IMAP server")
	}

	folderName := request.Name
	if request.Path != "" {
		folderName = request.Path + "/" + request.Name
	}

	response, err := p.sendCommand("CREATE \"" + folderName + "\"")
	if err != nil {
		return fmt.Errorf("failed to create folder: %w", err)
	}

	if !strings.HasPrefix(response, "OK") {
		return fmt.Errorf("failed to create folder: %s", response)
	}

	p.logger.WithFields(logrus.Fields{
		"name": request.Name,
		"path": request.Path,
	}).Info("Folder created successfully")

	return nil
}

// DeleteFolder deletes a folder from IMAP server
func (p *Provider) DeleteFolder(ctx context.Context, request *types.DeleteFolderRequest) error {
	if !p.IsConfigured() {
		return fmt.Errorf("imap provider not configured")
	}

	if p.conn == nil {
		return fmt.Errorf("not connected to IMAP server")
	}

	folderName := request.Name
	if request.Path != "" {
		folderName = request.Path + "/" + request.Name
	}

	response, err := p.sendCommand("DELETE \"" + folderName + "\"")
	if err != nil {
		return fmt.Errorf("failed to delete folder: %w", err)
	}

	if !strings.HasPrefix(response, "OK") {
		return fmt.Errorf("failed to delete folder: %s", response)
	}

	p.logger.WithFields(logrus.Fields{
		"name": request.Name,
		"path": request.Path,
	}).Info("Folder deleted successfully")

	return nil
}

// MoveMessage moves a message between folders on IMAP server
func (p *Provider) MoveMessage(ctx context.Context, request *types.MoveMessageRequest) error {
	if !p.IsConfigured() {
		return fmt.Errorf("imap provider not configured")
	}

	if p.conn == nil {
		return fmt.Errorf("not connected to IMAP server")
	}

	// Select source folder
	if err := p.selectFolder(request.FromFolder); err != nil {
		return fmt.Errorf("failed to select source folder: %w", err)
	}

	// Copy message to destination folder
	response, err := p.sendCommand("COPY " + request.UID + " \"" + request.ToFolder + "\"")
	if err != nil {
		return fmt.Errorf("failed to copy message: %w", err)
	}

	if !strings.HasPrefix(response, "OK") {
		return fmt.Errorf("failed to copy message: %s", response)
	}

	// Delete message from source folder
	deleteRequest := &types.DeleteMessageRequest{
		UID:    request.UID,
		Folder: request.FromFolder,
	}

	if err := p.DeleteMessage(ctx, deleteRequest); err != nil {
		return fmt.Errorf("failed to delete message from source folder: %w", err)
	}

	p.logger.WithFields(logrus.Fields{
		"uid":         request.UID,
		"from_folder": request.FromFolder,
		"to_folder":   request.ToFolder,
	}).Info("Message moved successfully")

	return nil
}

// DeleteMessage deletes a message from IMAP server
func (p *Provider) DeleteMessage(ctx context.Context, request *types.DeleteMessageRequest) error {
	if !p.IsConfigured() {
		return fmt.Errorf("imap provider not configured")
	}

	if p.conn == nil {
		return fmt.Errorf("not connected to IMAP server")
	}

	folder := request.Folder
	if folder == "" {
		folder = "INBOX"
	}

	// Select folder
	if err := p.selectFolder(folder); err != nil {
		return fmt.Errorf("failed to select folder: %w", err)
	}

	// Mark message as deleted
	response, err := p.sendCommand("STORE " + request.UID + " +FLAGS (\\Deleted)")
	if err != nil {
		return fmt.Errorf("failed to mark message as deleted: %w", err)
	}

	if !strings.HasPrefix(response, "OK") {
		return fmt.Errorf("failed to mark message as deleted: %s", response)
	}

	// Expunge to permanently delete
	response, err = p.sendCommand("EXPUNGE")
	if err != nil {
		return fmt.Errorf("failed to expunge messages: %w", err)
	}

	if !strings.HasPrefix(response, "OK") {
		return fmt.Errorf("failed to expunge messages: %s", response)
	}

	p.logger.WithFields(logrus.Fields{
		"uid":    request.UID,
		"folder": folder,
	}).Info("Message deleted successfully")

	return nil
}

// CreateTemplate is not supported by IMAP
func (p *Provider) CreateTemplate(ctx context.Context, request *types.CreateTemplateRequest) error {
	return fmt.Errorf("create template not supported by IMAP provider")
}

// UpdateTemplate is not supported by IMAP
func (p *Provider) UpdateTemplate(ctx context.Context, request *types.UpdateTemplateRequest) error {
	return fmt.Errorf("update template not supported by IMAP provider")
}

// DeleteTemplate is not supported by IMAP
func (p *Provider) DeleteTemplate(ctx context.Context, request *types.DeleteTemplateRequest) error {
	return fmt.Errorf("delete template not supported by IMAP provider")
}

// GetTemplate is not supported by IMAP
func (p *Provider) GetTemplate(ctx context.Context, request *types.GetTemplateRequest) (*types.Template, error) {
	return nil, fmt.Errorf("get template not supported by IMAP provider")
}

// ListTemplates is not supported by IMAP
func (p *Provider) ListTemplates(ctx context.Context, request *types.ListTemplatesRequest) (*types.ListTemplatesResponse, error) {
	return nil, fmt.Errorf("list templates not supported by IMAP provider")
}

// RenderTemplate is not supported by IMAP
func (p *Provider) RenderTemplate(ctx context.Context, request *types.RenderTemplateRequest) (*types.RenderTemplateResponse, error) {
	return nil, fmt.Errorf("render template not supported by IMAP provider")
}

// HealthCheck performs a health check on IMAP
func (p *Provider) HealthCheck(ctx context.Context) error {
	if !p.IsConfigured() {
		return fmt.Errorf("imap provider not configured")
	}

	return p.Ping(ctx)
}

// GetStats returns IMAP statistics
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

// Close closes the IMAP provider
func (p *Provider) Close() error {
	return p.Disconnect(context.Background())
}

// authenticate authenticates with IMAP server
func (p *Provider) authenticate(username, password string) error {
	// Send LOGIN command
	response, err := p.sendCommand(fmt.Sprintf("LOGIN \"%s\" \"%s\"", username, password))
	if err != nil {
		return fmt.Errorf("failed to send LOGIN command: %w", err)
	}

	if !strings.HasPrefix(response, "OK") {
		return fmt.Errorf("LOGIN command failed: %s", response)
	}

	return nil
}

// sendCommand sends a command to IMAP server
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

// readResponse reads response from IMAP server
func (p *Provider) readResponse() (string, error) {
	if p.conn == nil {
		return "", fmt.Errorf("not connected")
	}

	response := make([]byte, 4096)
	n, err := p.conn.Read(response)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	return strings.TrimSpace(string(response[:n])), nil
}

// selectFolder selects a folder on IMAP server
func (p *Provider) selectFolder(folder string) error {
	response, err := p.sendCommand("SELECT \"" + folder + "\"")
	if err != nil {
		return fmt.Errorf("failed to select folder: %w", err)
	}

	if !strings.HasPrefix(response, "OK") {
		return fmt.Errorf("failed to select folder: %s", response)
	}

	return nil
}

// parseMessageCount parses message count from STATUS response
func (p *Provider) parseMessageCount(response string) int {
	// Simple parsing - in real implementation, use proper IMAP parsing
	parts := strings.Fields(response)
	for i, part := range parts {
		if part == "MESSAGES" && i+1 < len(parts) {
			if count, err := strconv.Atoi(parts[i+1]); err == nil {
				return count
			}
		}
	}
	return 0
}

// fetchMessageByUID fetches a message by UID
func (p *Provider) fetchMessageByUID(uid string) (*types.EmailMessage, error) {
	response, err := p.sendCommand("FETCH " + uid + " (ENVELOPE BODY[TEXT])")
	if err != nil {
		return nil, fmt.Errorf("failed to fetch message: %w", err)
	}

	// Parse message (simplified parsing)
	message := p.parseMessage(response, uid)

	return message, nil
}

// fetchMessageBySequence fetches a message by sequence number
func (p *Provider) fetchMessageBySequence(sequence int) (*types.EmailMessage, error) {
	response, err := p.sendCommand(fmt.Sprintf("FETCH %d (ENVELOPE BODY[TEXT])", sequence))
	if err != nil {
		return nil, fmt.Errorf("failed to fetch message: %w", err)
	}

	// Parse message (simplified parsing)
	message := p.parseMessage(response, strconv.Itoa(sequence))

	return message, nil
}

// parseMessage parses a raw email message
func (p *Provider) parseMessage(rawMessage string, uid string) *types.EmailMessage {
	message := &types.EmailMessage{
		ID:        uuid.New(),
		CreatedAt: time.Now(),
		ProviderData: map[string]interface{}{
			"uid": uid,
		},
	}

	// Simple parsing - in real implementation, use proper IMAP parsing
	lines := strings.Split(rawMessage, "\r\n")

	for _, line := range lines {
		if strings.Contains(line, "ENVELOPE") {
			// Parse envelope information
			// This is simplified - real implementation would parse IMAP envelope format
			if strings.Contains(line, "Subject:") {
				parts := strings.Split(line, "Subject:")
				if len(parts) > 1 {
					message.Subject = strings.TrimSpace(parts[1])
				}
			}
		}
	}

	return message
}

// buildSearchCriteria builds IMAP search criteria
func (p *Provider) buildSearchCriteria(request *types.SearchRequest) string {
	criteria := make([]string, 0)

	if request.Query != "" {
		criteria = append(criteria, "TEXT \""+request.Query+"\"")
	}

	if request.From != "" {
		criteria = append(criteria, "FROM \""+request.From+"\"")
	}

	if request.To != "" {
		criteria = append(criteria, "TO \""+request.To+"\"")
	}

	if request.Subject != "" {
		criteria = append(criteria, "SUBJECT \""+request.Subject+"\"")
	}

	if request.Since != nil {
		criteria = append(criteria, "SINCE \""+request.Since.Format("02-Jan-2006")+"\"")
	}

	if request.Before != nil {
		criteria = append(criteria, "BEFORE \""+request.Before.Format("02-Jan-2006")+"\"")
	}

	if len(criteria) == 0 {
		return "ALL"
	}

	return strings.Join(criteria, " ")
}

// parseSearchResults parses search results from IMAP response
func (p *Provider) parseSearchResults(response string) []string {
	// Simple parsing - in real implementation, use proper IMAP parsing
	parts := strings.Fields(response)
	uids := make([]string, 0)

	for _, part := range parts {
		if part != "*" && part != "SEARCH" && part != "OK" {
			uids = append(uids, part)
		}
	}

	return uids
}

// parseFolderList parses folder list from IMAP response
func (p *Provider) parseFolderList(response string) []*types.FolderInfo {
	folders := make([]*types.FolderInfo, 0)

	lines := strings.Split(response, "\r\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "* LIST") {
			// Simple parsing - in real implementation, use proper IMAP parsing
			parts := strings.Fields(line)
			if len(parts) >= 4 {
				folderName := strings.Trim(parts[len(parts)-1], "\"")
				folder := &types.FolderInfo{
					Name: folderName,
					Path: folderName,
					ProviderData: map[string]interface{}{
						"raw_line": line,
					},
				}
				folders = append(folders, folder)
			}
		}
	}

	return folders
}
