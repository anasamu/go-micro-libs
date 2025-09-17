# Email Library

The Email library provides a unified interface for email operations across multiple providers including SMTP, POP3, and IMAP. It offers comprehensive email capabilities with support for sending emails, batch operations, email retrieval, folder management, template management, and advanced features like attachments, HTML content, priority handling, scheduling, and comprehensive monitoring.

## Features

- **Multi-Provider Support**: SMTP, POP3, IMAP providers
- **Email Sending**: Single and batch email sending
- **Email Retrieval**: Fetch and search emails
- **Folder Management**: Create, delete, and manage email folders
- **Template Management**: Create, update, and render email templates
- **Attachments**: Support for file attachments
- **HTML Content**: Rich HTML email support
- **Priority Handling**: Email priority levels
- **Scheduling**: Scheduled email sending
- **Message Management**: Move and delete messages
- **Security**: TLS/SSL support and authentication
- **Statistics**: Comprehensive email statistics and monitoring

## Supported Providers

- **SMTP**: Simple Mail Transfer Protocol
- **POP3**: Post Office Protocol version 3
- **IMAP**: Internet Message Access Protocol
- **Custom**: Custom email providers

## Installation

```bash
go get github.com/anasamu/go-micro-libs/email
```

## Quick Start

```go
package main

import (
    "context"
    "fmt"
    "log"
    "time"

    "github.com/anasamu/go-micro-libs/email"
    "github.com/anasamu/go-micro-libs/email/types"
    "github.com/sirupsen/logrus"
)

func main() {
    // Create logger
    logger := logrus.New()

    // Create email manager with default config
    config := email.DefaultManagerConfig()
    manager := email.NewEmailManager(config, logger)

    // Register SMTP provider (example)
    // smtpProvider := smtp.NewSMTPProvider("smtp.gmail.com:587")
    // manager.RegisterProvider(smtpProvider)

    // Create email message
    from := types.CreateEmailAddress("Sender", "sender@example.com")
    to := []*types.EmailAddress{
        types.CreateEmailAddress("Recipient", "recipient@example.com"),
    }

    message := types.CreateEmailMessage(from, to, "Test Email", "Hello, World!")
    message.HTMLBody = "<h1>Hello, World!</h1><p>This is a test email.</p>"

    // Send email
    ctx := context.Background()
    request := &types.SendRequest{
        Message: message,
    }

    response, err := manager.SendEmail(ctx, "smtp", request)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Email sent successfully: %s\n", response.MessageID)
}
```

## API Reference

### EmailManager

The main manager for handling email operations across multiple providers.

#### Methods

##### `NewEmailManager(config *ManagerConfig, logger *logrus.Logger) *EmailManager`
Creates a new email manager with the given configuration and logger.

##### `RegisterProvider(provider EmailProvider) error`
Registers a new email provider.

**Parameters:**
- `provider`: The email provider to register

**Returns:**
- `error`: Any error that occurred during registration

##### `GetProvider(name string) (EmailProvider, error)`
Retrieves a specific provider by name.

##### `GetDefaultProvider() (EmailProvider, error)`
Returns the default email provider.

##### `Connect(ctx context.Context, providerName string) error`
Connects to an email system using the specified provider.

**Parameters:**
- `ctx`: Context for cancellation and timeouts
- `providerName`: Name of the provider to connect

**Returns:**
- `error`: Any error that occurred

##### `Disconnect(ctx context.Context, providerName string) error`
Disconnects from an email system using the specified provider.

##### `Ping(ctx context.Context, providerName string) error`
Pings an email system using the specified provider.

##### `SendEmail(ctx context.Context, providerName string, request *types.SendRequest) (*types.SendResponse, error)`
Sends an email using the specified provider.

**Parameters:**
- `ctx`: Context for cancellation and timeouts
- `providerName`: Name of the provider to use
- `request`: Email send request

**Returns:**
- `*types.SendResponse`: Send response with message ID and status
- `error`: Any error that occurred

##### `SendBatch(ctx context.Context, providerName string, request *types.SendBatchRequest) (*types.SendBatchResponse, error)`
Sends multiple emails using the specified provider.

##### `FetchEmails(ctx context.Context, providerName string, request *types.FetchRequest) (*types.FetchResponse, error)`
Fetches emails using the specified provider.

##### `SearchEmails(ctx context.Context, providerName string, request *types.SearchRequest) (*types.SearchResponse, error)`
Searches emails using the specified provider.

##### `ListFolders(ctx context.Context, providerName string, request *types.ListFoldersRequest) (*types.ListFoldersResponse, error)`
Lists folders using the specified provider.

##### `CreateFolder(ctx context.Context, providerName string, request *types.CreateFolderRequest) error`
Creates a folder using the specified provider.

##### `DeleteFolder(ctx context.Context, providerName string, request *types.DeleteFolderRequest) error`
Deletes a folder using the specified provider.

##### `MoveMessage(ctx context.Context, providerName string, request *types.MoveMessageRequest) error`
Moves a message using the specified provider.

##### `DeleteMessage(ctx context.Context, providerName string, request *types.DeleteMessageRequest) error`
Deletes a message using the specified provider.

##### `CreateTemplate(ctx context.Context, providerName string, request *types.CreateTemplateRequest) error`
Creates a template using the specified provider.

##### `UpdateTemplate(ctx context.Context, providerName string, request *types.UpdateTemplateRequest) error`
Updates a template using the specified provider.

##### `DeleteTemplate(ctx context.Context, providerName string, request *types.DeleteTemplateRequest) error`
Deletes a template using the specified provider.

##### `GetTemplate(ctx context.Context, providerName string, request *types.GetTemplateRequest) (*types.Template, error)`
Gets a template using the specified provider.

##### `ListTemplates(ctx context.Context, providerName string, request *types.ListTemplatesRequest) (*types.ListTemplatesResponse, error)`
Lists templates using the specified provider.

##### `RenderTemplate(ctx context.Context, providerName string, request *types.RenderTemplateRequest) (*types.RenderTemplateResponse, error)`
Renders a template using the specified provider.

##### `HealthCheck(ctx context.Context) map[string]error`
Performs health check on all providers.

##### `GetStats(ctx context.Context, providerName string) (*types.EmailStats, error)`
Gets statistics from a provider.

##### `GetSupportedProviders() []string`
Returns a list of registered providers.

##### `GetProviderCapabilities(providerName string) ([]types.EmailFeature, *types.ConnectionInfo, error)`
Returns capabilities of a provider.

##### `Close() error`
Closes all email connections.

##### `IsProviderConnected(providerName string) bool`
Checks if a provider is connected.

##### `GetConnectedProviders() []string`
Returns a list of connected providers.

### Types

#### ManagerConfig
Configuration for the email manager.

```go
type ManagerConfig struct {
    DefaultProvider string            `json:"default_provider"`
    RetryAttempts   int               `json:"retry_attempts"`
    RetryDelay      time.Duration     `json:"retry_delay"`
    Timeout         time.Duration     `json:"timeout"`
    MaxMessageSize  int64             `json:"max_message_size"`
    Metadata        map[string]string `json:"metadata"`
}
```

#### EmailMessage
Represents an email message.

```go
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
```

#### EmailAddress
Represents an email address.

```go
type EmailAddress struct {
    Name    string `json:"name,omitempty"`
    Address string `json:"address"`
}
```

#### EmailAttachment
Represents an email attachment.

```go
type EmailAttachment struct {
    Filename    string `json:"filename"`
    ContentType string `json:"content_type"`
    Data        []byte `json:"data"`
    Inline      bool   `json:"inline,omitempty"`
    CID         string `json:"cid,omitempty"`
}
```

#### SendRequest
Represents a send email request.

```go
type SendRequest struct {
    Message *EmailMessage          `json:"message"`
    Options map[string]interface{} `json:"options,omitempty"`
}
```

#### SendResponse
Represents a send email response.

```go
type SendResponse struct {
    MessageID    string                 `json:"message_id"`
    Status       string                 `json:"status"`
    Timestamp    time.Time              `json:"timestamp"`
    ProviderData map[string]interface{} `json:"provider_data,omitempty"`
}
```

#### Template
Represents an email template.

```go
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
```

## Advanced Usage

### Basic Email Sending

```go
// Create email addresses
from := types.CreateEmailAddress("John Doe", "john@example.com")
to := []*types.EmailAddress{
    types.CreateEmailAddress("Jane Smith", "jane@example.com"),
}
cc := []*types.EmailAddress{
    types.CreateEmailAddress("Manager", "manager@example.com"),
}

// Create email message
message := types.CreateEmailMessage(from, to, "Meeting Reminder", "Don't forget about our meeting tomorrow at 2 PM.")
message.Cc = cc
message.HTMLBody = `
    <h2>Meeting Reminder</h2>
    <p>Don't forget about our meeting tomorrow at <strong>2 PM</strong>.</p>
    <p>Location: Conference Room A</p>
    <p>Best regards,<br>John</p>
`

// Set priority
message.SetPriority(types.PriorityHigh)

// Add custom headers
message.AddHeader("X-Priority", "1")
message.AddHeader("X-MSMail-Priority", "High")

// Send email
request := &types.SendRequest{
    Message: message,
}

response, err := manager.SendEmail(ctx, "smtp", request)
if err != nil {
    log.Printf("Failed to send email: %v", err)
} else {
    fmt.Printf("Email sent: %s\n", response.MessageID)
}
```

### Email with Attachments

```go
// Create email message
message := types.CreateEmailMessage(from, to, "Document Attached", "Please find the attached document.")

// Add attachment
attachmentData := []byte("This is the content of the document.")
attachment := types.CreateEmailAttachment("document.pdf", "application/pdf", attachmentData)
message.AddAttachment(attachment)

// Add inline image
imageData := []byte("image data...")
inlineImage := &types.EmailAttachment{
    Filename:    "logo.png",
    ContentType: "image/png",
    Data:        imageData,
    Inline:      true,
    CID:         "logo",
}
message.AddAttachment(inlineImage)

// HTML body with inline image
message.HTMLBody = `
    <h1>Document Attached</h1>
    <p>Please find the attached document.</p>
    <img src="cid:logo" alt="Company Logo">
    <p>Best regards,<br>Team</p>
`

// Send email
request := &types.SendRequest{
    Message: message,
}

response, err := manager.SendEmail(ctx, "smtp", request)
```

### Batch Email Sending

```go
// Create multiple email messages
messages := []*types.EmailMessage{
    types.CreateEmailMessage(
        types.CreateEmailAddress("Sender", "sender@example.com"),
        []*types.EmailAddress{types.CreateEmailAddress("User1", "user1@example.com")},
        "Welcome User1",
        "Welcome to our service!",
    ),
    types.CreateEmailMessage(
        types.CreateEmailAddress("Sender", "sender@example.com"),
        []*types.EmailAddress{types.CreateEmailAddress("User2", "user2@example.com")},
        "Welcome User2",
        "Welcome to our service!",
    ),
    types.CreateEmailMessage(
        types.CreateEmailAddress("Sender", "sender@example.com"),
        []*types.EmailAddress{types.CreateEmailAddress("User3", "user3@example.com")},
        "Welcome User3",
        "Welcome to our service!",
    ),
}

// Send batch
batchRequest := &types.SendBatchRequest{
    Messages: messages,
    Options: map[string]interface{}{
        "batch_size": 10,
        "delay":      100, // milliseconds between emails
    },
}

response, err := manager.SendBatch(ctx, "smtp", batchRequest)
if err != nil {
    log.Printf("Failed to send batch: %v", err)
} else {
    fmt.Printf("Batch sent: %d successful, %d failed\n", response.SentCount, response.FailedCount)
    
    if len(response.FailedMessages) > 0 {
        fmt.Println("Failed messages:")
        for _, msg := range response.FailedMessages {
            fmt.Printf("  - %s\n", msg.Subject)
        }
    }
}
```

### Email Templates

```go
// Create email template
template := &types.Template{
    ID:        "welcome-template",
    Name:      "Welcome Email",
    Subject:   "Welcome to {{.ServiceName}}, {{.UserName}}!",
    Body:      "Hello {{.UserName}},\n\nWelcome to {{.ServiceName}}! We're excited to have you on board.",
    HTMLBody:  `
        <h1>Welcome to {{.ServiceName}}, {{.UserName}}!</h1>
        <p>Hello {{.UserName}},</p>
        <p>Welcome to {{.ServiceName}}! We're excited to have you on board.</p>
        <p>Best regards,<br>The {{.ServiceName}} Team</p>
    `,
    Variables: []string{"ServiceName", "UserName"},
}

// Create template
createRequest := &types.CreateTemplateRequest{
    Template: template,
}

err := manager.CreateTemplate(ctx, "smtp", createRequest)
if err != nil {
    log.Printf("Failed to create template: %v", err)
}

// Render template
renderRequest := &types.RenderTemplateRequest{
    TemplateID: "welcome-template",
    Variables: map[string]interface{}{
        "ServiceName": "MyApp",
        "UserName":    "John Doe",
    },
}

renderResponse, err := manager.RenderTemplate(ctx, "smtp", renderRequest)
if err != nil {
    log.Printf("Failed to render template: %v", err)
} else {
    // Use rendered content
    message := types.CreateEmailMessage(from, to, renderResponse.Subject, renderResponse.Body)
    message.HTMLBody = renderResponse.HTMLBody
    
    sendRequest := &types.SendRequest{
        Message: message,
    }
    
    response, err := manager.SendEmail(ctx, "smtp", sendRequest)
    if err != nil {
        log.Printf("Failed to send templated email: %v", err)
    } else {
        fmt.Printf("Templated email sent: %s\n", response.MessageID)
    }
}
```

### Email Retrieval (IMAP/POP3)

```go
// Fetch emails from inbox
fetchRequest := &types.FetchRequest{
    Folder: "INBOX",
    Options: map[string]interface{}{
        "limit": 10,
    },
}

fetchResponse, err := manager.FetchEmails(ctx, "imap", fetchRequest)
if err != nil {
    log.Printf("Failed to fetch emails: %v", err)
} else {
    fmt.Printf("Fetched %d emails\n", fetchResponse.Total)
    
    for _, msg := range fetchResponse.Messages {
        fmt.Printf("From: %s\n", msg.From.Address)
        fmt.Printf("Subject: %s\n", msg.Subject)
        fmt.Printf("Date: %s\n", msg.CreatedAt.Format(time.RFC3339))
        fmt.Println("---")
    }
}

// Search emails
searchRequest := &types.SearchRequest{
    Folder:  "INBOX",
    From:    "important@example.com",
    Subject: "urgent",
    Since:   timePtr(time.Now().Add(-7 * 24 * time.Hour)), // Last 7 days
}

searchResponse, err := manager.SearchEmails(ctx, "imap", searchRequest)
if err != nil {
    log.Printf("Failed to search emails: %v", err)
} else {
    fmt.Printf("Found %d matching emails\n", searchResponse.Total)
}
```

### Folder Management (IMAP)

```go
// List folders
listRequest := &types.ListFoldersRequest{
    Options: map[string]interface{}{
        "include_subscribed": true,
    },
}

listResponse, err := manager.ListFolders(ctx, "imap", listRequest)
if err != nil {
    log.Printf("Failed to list folders: %v", err)
} else {
    fmt.Println("Available folders:")
    for _, folder := range listResponse.Folders {
        fmt.Printf("  %s (%d messages, %d unread)\n", 
            folder.Name, folder.MessageCount, folder.UnreadCount)
    }
}

// Create folder
createFolderRequest := &types.CreateFolderRequest{
    Name: "Important",
    Path: "INBOX.Important",
}

err = manager.CreateFolder(ctx, "imap", createFolderRequest)
if err != nil {
    log.Printf("Failed to create folder: %v", err)
} else {
    fmt.Println("Folder created successfully")
}

// Move message to folder
moveRequest := &types.MoveMessageRequest{
    UID:        "12345",
    FromFolder: "INBOX",
    ToFolder:   "INBOX.Important",
}

err = manager.MoveMessage(ctx, "imap", moveRequest)
if err != nil {
    log.Printf("Failed to move message: %v", err)
} else {
    fmt.Println("Message moved successfully")
}
```

### Scheduled Email Sending

```go
// Schedule email for future sending
scheduledTime := time.Now().Add(1 * time.Hour)
message := types.CreateEmailMessage(from, to, "Scheduled Email", "This email was scheduled.")
message.SetScheduledTime(scheduledTime)

request := &types.SendRequest{
    Message: message,
    Options: map[string]interface{}{
        "scheduled": true,
    },
}

response, err := manager.SendEmail(ctx, "smtp", request)
if err != nil {
    log.Printf("Failed to schedule email: %v", err)
} else {
    fmt.Printf("Email scheduled: %s\n", response.MessageID)
}
```

### Connection Management

```go
// Connect to email provider
err := manager.Connect(ctx, "smtp")
if err != nil {
    log.Printf("Failed to connect: %v", err)
    return
}

// Check connection status
isConnected := manager.IsProviderConnected("smtp")
fmt.Printf("SMTP connected: %t\n", isConnected)

// Get connected providers
connectedProviders := manager.GetConnectedProviders()
fmt.Printf("Connected providers: %v\n", connectedProviders)

// Ping provider
err = manager.Ping(ctx, "smtp")
if err != nil {
    log.Printf("Ping failed: %v", err)
} else {
    fmt.Println("Ping successful")
}

// Disconnect
err = manager.Disconnect(ctx, "smtp")
if err != nil {
    log.Printf("Failed to disconnect: %v", err)
}
```

### Health Monitoring

```go
// Perform health check on all providers
healthResults := manager.HealthCheck(ctx)
for providerName, err := range healthResults {
    if err != nil {
        fmt.Printf("Provider %s: UNHEALTHY - %v\n", providerName, err)
    } else {
        fmt.Printf("Provider %s: HEALTHY\n", providerName)
    }
}

// Get statistics
stats, err := manager.GetStats(ctx, "smtp")
if err != nil {
    log.Printf("Failed to get stats: %v", err)
} else {
    fmt.Printf("Email Statistics:\n")
    fmt.Printf("  Sent Messages: %d\n", stats.SentMessages)
    fmt.Printf("  Received Messages: %d\n", stats.ReceivedMessages)
    fmt.Printf("  Failed Messages: %d\n", stats.FailedMessages)
    fmt.Printf("  Active Connections: %d\n", stats.ActiveConnections)
}
```

### Provider Capabilities

```go
// Get provider capabilities
features, connInfo, err := manager.GetProviderCapabilities("smtp")
if err != nil {
    log.Printf("Failed to get capabilities: %v", err)
    return
}

fmt.Printf("SMTP Provider Features:\n")
for _, feature := range features {
    fmt.Printf("  - %s\n", feature)
}

if connInfo != nil {
    fmt.Printf("Connection Info:\n")
    fmt.Printf("  Host: %s\n", connInfo.Host)
    fmt.Printf("  Port: %d\n", connInfo.Port)
    fmt.Printf("  Protocol: %s\n", connInfo.Protocol)
    fmt.Printf("  Secure: %t\n", connInfo.Secure)
}

// Get all supported providers
providers := manager.GetSupportedProviders()
fmt.Printf("Supported providers: %v\n", providers)
```

### Error Handling

```go
response, err := manager.SendEmail(ctx, "smtp", request)
if err != nil {
    // Handle different types of errors
    switch {
    case strings.Contains(err.Error(), "connection"):
        log.Printf("Email provider connection error: %v", err)
    case strings.Contains(err.Error(), "authentication"):
        log.Printf("Email authentication failed: %v", err)
    case strings.Contains(err.Error(), "message size"):
        log.Printf("Message size exceeds limit: %v", err)
    case strings.Contains(err.Error(), "invalid request"):
        log.Printf("Invalid email request: %v", err)
    default:
        log.Printf("Email sending failed: %v", err)
    }
    return
}

// Handle response
if response.Status == "sent" {
    fmt.Printf("Email sent successfully: %s\n", response.MessageID)
} else {
    fmt.Printf("Email status: %s\n", response.Status)
}
```

### Configuration Management

```go
// Custom configuration
config := &email.ManagerConfig{
    DefaultProvider: "smtp",
    RetryAttempts:   5,
    RetryDelay:      2 * time.Second,
    Timeout:         60 * time.Second,
    MaxMessageSize:  50 * 1024 * 1024, // 50MB
    Metadata: map[string]string{
        "environment": "production",
        "version":     "1.0.0",
    },
}

manager := email.NewEmailManager(config, logger)
```

## Best Practices

1. **Connection Management**: Properly connect and disconnect from email providers
2. **Error Handling**: Implement comprehensive error handling for all operations
3. **Message Validation**: Validate email addresses and message content
4. **Size Limits**: Respect message size limits and attachment restrictions
5. **Security**: Use secure connections (TLS/SSL) for email operations
6. **Templates**: Use templates for consistent email formatting
7. **Batch Operations**: Use batch operations for sending multiple emails
8. **Monitoring**: Monitor email statistics and health status
9. **Testing**: Test email functionality in different scenarios
10. **Compliance**: Ensure compliance with email regulations and best practices

## Contributing

Contributions are welcome! Please read the contributing guidelines and submit pull requests for any improvements.

## License

This library is licensed under the MIT License. See the LICENSE file for details.
