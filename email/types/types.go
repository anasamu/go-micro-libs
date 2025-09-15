package types

import (
	"time"

	"github.com/google/uuid"
)

// EmailFeature represents an email feature
type EmailFeature string

const (
	FeatureSMTP            EmailFeature = "smtp"
	FeaturePOP3            EmailFeature = "pop3"
	FeatureIMAP            EmailFeature = "imap"
	FeatureTLS             EmailFeature = "tls"
	FeatureSSL             EmailFeature = "ssl"
	FeatureAuthentication  EmailFeature = "authentication"
	FeatureAttachments     EmailFeature = "attachments"
	FeatureHTML            EmailFeature = "html"
	FeaturePlainText       EmailFeature = "plain_text"
	FeatureReadReceipt     EmailFeature = "read_receipt"
	FeatureDeliveryReceipt EmailFeature = "delivery_receipt"
	FeaturePriority        EmailFeature = "priority"
	FeatureScheduling      EmailFeature = "scheduling"
	FeatureTemplates       EmailFeature = "templates"
	FeatureBulkSending     EmailFeature = "bulk_sending"
	FeatureTracking        EmailFeature = "tracking"
	FeatureEncryption      EmailFeature = "encryption"
	FeatureSigning         EmailFeature = "signing"
	FeatureFiltering       EmailFeature = "filtering"
	FeatureSearching       EmailFeature = "searching"
	FeatureFolders         EmailFeature = "folders"
	FeatureLabels          EmailFeature = "labels"
	FeatureThreading       EmailFeature = "threading"
)

// ConnectionInfo represents email connection information
type ConnectionInfo struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Version  string `json:"version"`
	Secure   bool   `json:"secure"`
}

// EmailAddress represents an email address
type EmailAddress struct {
	Name    string `json:"name,omitempty"`
	Address string `json:"address"`
}

// EmailAttachment represents an email attachment
type EmailAttachment struct {
	Filename    string `json:"filename"`
	ContentType string `json:"content_type"`
	Data        []byte `json:"data"`
	Inline      bool   `json:"inline,omitempty"`
	CID         string `json:"cid,omitempty"`
}

// EmailMessage represents an email message
type EmailMessage struct {
	ID           uuid.UUID              `json:"id"`
	From         *EmailAddress          `json:"from"`
	To           []*EmailAddress        `json:"to"`
	Cc           []*EmailAddress        `json:"cc,omitempty"`
	Bcc          []*EmailAddress        `json:"bcc,omitempty"`
	ReplyTo      *EmailAddress          `json:"reply_to,omitempty"`
	Subject      string                 `json:"subject"`
	Body         string                 `json:"body"`
	HTMLBody     string                 `json:"html_body,omitempty"`
	Attachments  []*EmailAttachment     `json:"attachments,omitempty"`
	Headers      map[string]string      `json:"headers,omitempty"`
	Priority     EmailPriority          `json:"priority,omitempty"`
	CreatedAt    time.Time              `json:"created_at"`
	ScheduledAt  *time.Time             `json:"scheduled_at,omitempty"`
	ProviderData map[string]interface{} `json:"provider_data,omitempty"`
}

// EmailPriority represents email priority
type EmailPriority int

const (
	PriorityLow EmailPriority = iota
	PriorityNormal
	PriorityHigh
)

// SendRequest represents a send email request
type SendRequest struct {
	Message *EmailMessage          `json:"message"`
	Options map[string]interface{} `json:"options,omitempty"`
}

// SendResponse represents a send email response
type SendResponse struct {
	MessageID    string                 `json:"message_id"`
	Status       string                 `json:"status"`
	Timestamp    time.Time              `json:"timestamp"`
	ProviderData map[string]interface{} `json:"provider_data,omitempty"`
}

// SendBatchRequest represents a batch send email request
type SendBatchRequest struct {
	Messages []*EmailMessage        `json:"messages"`
	Options  map[string]interface{} `json:"options,omitempty"`
}

// SendBatchResponse represents a batch send email response
type SendBatchResponse struct {
	SentCount      int                    `json:"sent_count"`
	FailedCount    int                    `json:"failed_count"`
	FailedMessages []*EmailMessage        `json:"failed_messages,omitempty"`
	ProviderData   map[string]interface{} `json:"provider_data,omitempty"`
}

// FetchRequest represents a fetch email request
type FetchRequest struct {
	Folder   string                 `json:"folder,omitempty"`
	UID      string                 `json:"uid,omitempty"`
	Sequence int                    `json:"sequence,omitempty"`
	Options  map[string]interface{} `json:"options,omitempty"`
}

// FetchResponse represents a fetch email response
type FetchResponse struct {
	Messages     []*EmailMessage        `json:"messages"`
	Total        int                    `json:"total"`
	ProviderData map[string]interface{} `json:"provider_data,omitempty"`
}

// SearchRequest represents a search email request
type SearchRequest struct {
	Folder  string                 `json:"folder,omitempty"`
	Query   string                 `json:"query,omitempty"`
	From    string                 `json:"from,omitempty"`
	To      string                 `json:"to,omitempty"`
	Subject string                 `json:"subject,omitempty"`
	Since   *time.Time             `json:"since,omitempty"`
	Before  *time.Time             `json:"before,omitempty"`
	Options map[string]interface{} `json:"options,omitempty"`
}

// SearchResponse represents a search email response
type SearchResponse struct {
	Messages     []*EmailMessage        `json:"messages"`
	Total        int                    `json:"total"`
	ProviderData map[string]interface{} `json:"provider_data,omitempty"`
}

// FolderInfo represents folder information
type FolderInfo struct {
	Name         string                 `json:"name"`
	Path         string                 `json:"path"`
	MessageCount int                    `json:"message_count"`
	UnreadCount  int                    `json:"unread_count"`
	ProviderData map[string]interface{} `json:"provider_data,omitempty"`
}

// ListFoldersRequest represents a list folders request
type ListFoldersRequest struct {
	Options map[string]interface{} `json:"options,omitempty"`
}

// ListFoldersResponse represents a list folders response
type ListFoldersResponse struct {
	Folders      []*FolderInfo          `json:"folders"`
	ProviderData map[string]interface{} `json:"provider_data,omitempty"`
}

// CreateFolderRequest represents a create folder request
type CreateFolderRequest struct {
	Name    string                 `json:"name"`
	Path    string                 `json:"path,omitempty"`
	Options map[string]interface{} `json:"options,omitempty"`
}

// DeleteFolderRequest represents a delete folder request
type DeleteFolderRequest struct {
	Name    string                 `json:"name"`
	Path    string                 `json:"path,omitempty"`
	Options map[string]interface{} `json:"options,omitempty"`
}

// MoveMessageRequest represents a move message request
type MoveMessageRequest struct {
	UID        string                 `json:"uid"`
	Sequence   int                    `json:"sequence,omitempty"`
	FromFolder string                 `json:"from_folder"`
	ToFolder   string                 `json:"to_folder"`
	Options    map[string]interface{} `json:"options,omitempty"`
}

// DeleteMessageRequest represents a delete message request
type DeleteMessageRequest struct {
	UID      string                 `json:"uid"`
	Sequence int                    `json:"sequence,omitempty"`
	Folder   string                 `json:"folder,omitempty"`
	Options  map[string]interface{} `json:"options,omitempty"`
}

// EmailStats represents email statistics
type EmailStats struct {
	SentMessages      int64                  `json:"sent_messages"`
	ReceivedMessages  int64                  `json:"received_messages"`
	FailedMessages    int64                  `json:"failed_messages"`
	ActiveConnections int                    `json:"active_connections"`
	ProviderData      map[string]interface{} `json:"provider_data"`
}

// Template represents an email template
type Template struct {
	ID           string                 `json:"id"`
	Name         string                 `json:"name"`
	Subject      string                 `json:"subject"`
	Body         string                 `json:"body"`
	HTMLBody     string                 `json:"html_body,omitempty"`
	Variables    []string               `json:"variables,omitempty"`
	CreatedAt    time.Time              `json:"created_at"`
	UpdatedAt    time.Time              `json:"updated_at"`
	ProviderData map[string]interface{} `json:"provider_data,omitempty"`
}

// CreateTemplateRequest represents a create template request
type CreateTemplateRequest struct {
	Template *Template `json:"template"`
}

// UpdateTemplateRequest represents an update template request
type UpdateTemplateRequest struct {
	ID       string    `json:"id"`
	Template *Template `json:"template"`
}

// DeleteTemplateRequest represents a delete template request
type DeleteTemplateRequest struct {
	ID string `json:"id"`
}

// GetTemplateRequest represents a get template request
type GetTemplateRequest struct {
	ID string `json:"id"`
}

// ListTemplatesRequest represents a list templates request
type ListTemplatesRequest struct {
	Options map[string]interface{} `json:"options,omitempty"`
}

// ListTemplatesResponse represents a list templates response
type ListTemplatesResponse struct {
	Templates    []*Template            `json:"templates"`
	ProviderData map[string]interface{} `json:"provider_data,omitempty"`
}

// RenderTemplateRequest represents a render template request
type RenderTemplateRequest struct {
	TemplateID string                 `json:"template_id"`
	Variables  map[string]interface{} `json:"variables"`
	Options    map[string]interface{} `json:"options,omitempty"`
}

// RenderTemplateResponse represents a render template response
type RenderTemplateResponse struct {
	Subject      string                 `json:"subject"`
	Body         string                 `json:"body"`
	HTMLBody     string                 `json:"html_body,omitempty"`
	ProviderData map[string]interface{} `json:"provider_data,omitempty"`
}

// EmailHandler handles incoming emails
type EmailHandler func(message *EmailMessage) error

// SetPriority sets email priority
func (em *EmailMessage) SetPriority(priority EmailPriority) {
	em.Priority = priority
}

// SetScheduledTime sets email scheduled time
func (em *EmailMessage) SetScheduledTime(scheduledAt time.Time) {
	em.ScheduledAt = &scheduledAt
}

// AddHeader adds a header to the email
func (em *EmailMessage) AddHeader(key, value string) {
	if em.Headers == nil {
		em.Headers = make(map[string]string)
	}
	em.Headers[key] = value
}

// GetHeader retrieves a header from the email
func (em *EmailMessage) GetHeader(key string) (string, bool) {
	if em.Headers == nil {
		return "", false
	}
	value, exists := em.Headers[key]
	return value, exists
}

// AddAttachment adds an attachment to the email
func (em *EmailMessage) AddAttachment(attachment *EmailAttachment) {
	if em.Attachments == nil {
		em.Attachments = make([]*EmailAttachment, 0)
	}
	em.Attachments = append(em.Attachments, attachment)
}

// CreateEmailMessage creates a new email message with default values
func CreateEmailMessage(from *EmailAddress, to []*EmailAddress, subject, body string) *EmailMessage {
	return &EmailMessage{
		ID:        uuid.New(),
		From:      from,
		To:        to,
		Subject:   subject,
		Body:      body,
		Headers:   make(map[string]string),
		Priority:  PriorityNormal,
		CreatedAt: time.Now(),
	}
}

// CreateEmailAddress creates a new email address
func CreateEmailAddress(name, address string) *EmailAddress {
	return &EmailAddress{
		Name:    name,
		Address: address,
	}
}

// CreateEmailAttachment creates a new email attachment
func CreateEmailAttachment(filename, contentType string, data []byte) *EmailAttachment {
	return &EmailAttachment{
		Filename:    filename,
		ContentType: contentType,
		Data:        data,
		Inline:      false,
	}
}
