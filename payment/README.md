# Payment Library

The Payment library provides a unified interface for payment processing across multiple payment gateways including Stripe, PayPal, Midtrans, and Xendit. It offers comprehensive payment capabilities with support for various payment methods, currencies, webhooks, refunds, and advanced features like retry logic, validation, and provider management.

## Features

- **Multi-Provider Support**: Stripe, PayPal, Midtrans, Xendit, and more
- **Payment Methods**: Card, Bank Transfer, E-Wallet, QR Code, Virtual Account, Retail
- **Multiple Currencies**: Support for various international currencies
- **Webhook Handling**: Secure webhook validation and processing
- **Refund Management**: Full and partial refund capabilities
- **Customer Management**: Customer information and address handling
- **Retry Logic**: Automatic retry for failed payment operations
- **Validation**: Comprehensive request validation
- **Provider Management**: Easy provider registration and management
- **Metadata Support**: Custom metadata for payments and refunds

## Supported Providers

- **Stripe**: Global payment processing
- **PayPal**: International payment gateway
- **Midtrans**: Indonesian payment gateway
- **Xendit**: Southeast Asian payment gateway
- **Custom**: Custom payment providers

## Installation

```bash
go get github.com/anasamu/go-micro-libs/payment
```

## Quick Start

```go
package main

import (
    "context"
    "fmt"
    "log"
    "time"

    "github.com/anasamu/go-micro-libs/payment"
    "github.com/sirupsen/logrus"
)

func main() {
    // Create logger
    logger := logrus.New()

    // Create payment manager with default config
    config := payment.DefaultManagerConfig()
    manager := payment.NewPaymentManager(config, logger)

    // Register Stripe provider (example)
    // stripeProvider := stripe.NewStripeProvider("sk_test_...")
    // manager.RegisterProvider(stripeProvider)

    // Create payment request
    ctx := context.Background()
    paymentReq := &payment.PaymentRequest{
        Amount:      10000, // $100.00 in cents
        Currency:    "usd",
        Description: "Test payment",
        Customer: &payment.Customer{
            Email: "customer@example.com",
            Name:  "John Doe",
        },
        PaymentMethod: payment.PaymentMethodCard,
        Metadata: map[string]interface{}{
            "order_id": "order_123",
        },
    }

    // Create payment
    response, err := manager.CreatePayment(ctx, "stripe", paymentReq)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Payment created: %s, Status: %s\n", response.ID, response.Status)
}
```

## API Reference

### PaymentManager

The main manager for handling payment operations across multiple providers.

#### Methods

##### `NewPaymentManager(config *ManagerConfig, logger *logrus.Logger) *PaymentManager`
Creates a new payment manager with the given configuration and logger.

##### `RegisterProvider(provider PaymentProvider) error`
Registers a new payment provider.

**Parameters:**
- `provider`: The payment provider to register

**Returns:**
- `error`: Any error that occurred during registration

##### `GetProvider(name string) (PaymentProvider, error)`
Retrieves a specific provider by name.

##### `GetDefaultProvider() (PaymentProvider, error)`
Returns the default payment provider.

##### `CreatePayment(ctx context.Context, providerName string, request *PaymentRequest) (*PaymentResponse, error)`
Creates a payment using the specified provider.

**Parameters:**
- `ctx`: Context for cancellation and timeouts
- `providerName`: Name of the provider to use
- `request`: Payment request with payment details

**Returns:**
- `*PaymentResponse`: Payment response with status and URLs
- `error`: Any error that occurred

##### `GetPayment(ctx context.Context, providerName, paymentID string) (*Payment, error)`
Retrieves a payment from the specified provider.

##### `CancelPayment(ctx context.Context, providerName, paymentID string) error`
Cancels a payment using the specified provider.

##### `RefundPayment(ctx context.Context, providerName string, request *RefundRequest) (*RefundResponse, error)`
Processes a refund using the specified provider.

##### `ProcessWebhook(ctx context.Context, providerName string, payload []byte, signature string) error`
Processes a webhook event from a payment provider.

##### `GetSupportedProviders() []string`
Returns a list of registered providers.

##### `GetProviderCapabilities(providerName string) ([]PaymentMethod, []string, error)`
Returns capabilities of a specific provider.

### Types

#### ManagerConfig
Configuration for the payment manager.

```go
type ManagerConfig struct {
    DefaultProvider string            `json:"default_provider"`
    RetryAttempts   int               `json:"retry_attempts"`
    RetryDelay      time.Duration     `json:"retry_delay"`
    Timeout         time.Duration     `json:"timeout"`
    WebhookSecret   string            `json:"webhook_secret"`
    Metadata        map[string]string `json:"metadata"`
}
```

#### PaymentRequest
Represents a payment request.

```go
type PaymentRequest struct {
    ID            string                 `json:"id"`
    Amount        int64                  `json:"amount"` // Amount in cents
    Currency      string                 `json:"currency"`
    Description   string                 `json:"description"`
    Customer      *Customer              `json:"customer"`
    PaymentMethod PaymentMethod          `json:"payment_method"`
    Metadata      map[string]interface{} `json:"metadata"`
    ReturnURL     string                 `json:"return_url,omitempty"`
    CancelURL     string                 `json:"cancel_url,omitempty"`
    WebhookURL    string                 `json:"webhook_url,omitempty"`
    ExpiresAt     *time.Time             `json:"expires_at,omitempty"`
}
```

#### PaymentResponse
Represents a payment response.

```go
type PaymentResponse struct {
    ID           string                 `json:"id"`
    Status       PaymentStatus          `json:"status"`
    PaymentURL   string                 `json:"payment_url,omitempty"`
    ClientSecret string                 `json:"client_secret,omitempty"`
    ProviderData map[string]interface{} `json:"provider_data"`
    CreatedAt    time.Time              `json:"created_at"`
    ExpiresAt    *time.Time             `json:"expires_at,omitempty"`
}
```

#### Payment
Represents a payment.

```go
type Payment struct {
    ID            string                 `json:"id"`
    Amount        int64                  `json:"amount"`
    Currency      string                 `json:"currency"`
    Status        PaymentStatus          `json:"status"`
    Description   string                 `json:"description"`
    Customer      *Customer              `json:"customer"`
    PaymentMethod PaymentMethod          `json:"payment_method"`
    Metadata      map[string]interface{} `json:"metadata"`
    ProviderData  map[string]interface{} `json:"provider_data"`
    CreatedAt     time.Time              `json:"created_at"`
    UpdatedAt     time.Time              `json:"updated_at"`
    PaidAt        *time.Time             `json:"paid_at,omitempty"`
    ExpiresAt     *time.Time             `json:"expires_at,omitempty"`
}
```

#### Customer
Represents a customer.

```go
type Customer struct {
    ID       string                 `json:"id,omitempty"`
    Email    string                 `json:"email"`
    Name     string                 `json:"name,omitempty"`
    Phone    string                 `json:"phone,omitempty"`
    Address  *Address               `json:"address,omitempty"`
    Metadata map[string]interface{} `json:"metadata,omitempty"`
}
```

#### Address
Represents a customer address.

```go
type Address struct {
    Line1      string `json:"line1"`
    Line2      string `json:"line2,omitempty"`
    City       string `json:"city"`
    State      string `json:"state,omitempty"`
    PostalCode string `json:"postal_code"`
    Country    string `json:"country"`
}
```

#### RefundRequest
Represents a refund request.

```go
type RefundRequest struct {
    PaymentID string                 `json:"payment_id"`
    Amount    *int64                 `json:"amount,omitempty"` // If nil, refund full amount
    Reason    string                 `json:"reason,omitempty"`
    Metadata  map[string]interface{} `json:"metadata"`
}
```

#### RefundResponse
Represents a refund response.

```go
type RefundResponse struct {
    ID           string                 `json:"id"`
    PaymentID    string                 `json:"payment_id"`
    Amount       int64                  `json:"amount"`
    Status       RefundStatus           `json:"status"`
    Reason       string                 `json:"reason,omitempty"`
    ProviderData map[string]interface{} `json:"provider_data"`
    CreatedAt    time.Time              `json:"created_at"`
}
```

#### WebhookEvent
Represents a webhook event.

```go
type WebhookEvent struct {
    ID        string                 `json:"id"`
    Type      string                 `json:"type"`
    PaymentID string                 `json:"payment_id"`
    Data      map[string]interface{} `json:"data"`
    CreatedAt time.Time              `json:"created_at"`
}
```

#### PaymentMethod
Represents supported payment methods.

```go
const (
    PaymentMethodCard           PaymentMethod = "card"
    PaymentMethodBankTransfer   PaymentMethod = "bank_transfer"
    PaymentMethodEWallet        PaymentMethod = "ewallet"
    PaymentMethodQRCode         PaymentMethod = "qr_code"
    PaymentMethodVirtualAccount PaymentMethod = "virtual_account"
    PaymentMethodRetail         PaymentMethod = "retail"
)
```

#### PaymentStatus
Represents payment statuses.

```go
const (
    PaymentStatusPending    PaymentStatus = "pending"
    PaymentStatusProcessing PaymentStatus = "processing"
    PaymentStatusSucceeded  PaymentStatus = "succeeded"
    PaymentStatusFailed     PaymentStatus = "failed"
    PaymentStatusCanceled   PaymentStatus = "canceled"
    PaymentStatusExpired    PaymentStatus = "expired"
)
```

#### RefundStatus
Represents refund statuses.

```go
const (
    RefundStatusPending   RefundStatus = "pending"
    RefundStatusSucceeded RefundStatus = "succeeded"
    RefundStatusFailed    RefundStatus = "failed"
    RefundStatusCanceled  RefundStatus = "canceled"
)
```

## Advanced Usage

### Creating Payments

```go
// Create a card payment
paymentReq := &payment.PaymentRequest{
    Amount:      25000, // $250.00 in cents
    Currency:    "usd",
    Description: "Premium subscription",
    Customer: &payment.Customer{
        Email: "user@example.com",
        Name:  "Jane Smith",
        Phone: "+1234567890",
        Address: &payment.Address{
            Line1:      "123 Main St",
            City:       "New York",
            State:      "NY",
            PostalCode: "10001",
            Country:    "US",
        },
    },
    PaymentMethod: payment.PaymentMethodCard,
    Metadata: map[string]interface{}{
        "subscription_id": "sub_123",
        "plan":           "premium",
    },
    ReturnURL:  "https://example.com/success",
    CancelURL:  "https://example.com/cancel",
    WebhookURL: "https://example.com/webhooks/payment",
    ExpiresAt:  timePtr(time.Now().Add(24 * time.Hour)),
}

response, err := manager.CreatePayment(ctx, "stripe", paymentReq)

// Create an e-wallet payment
paymentReq = &payment.PaymentRequest{
    Amount:      50000, // $500.00 in cents
    Currency:    "idr",
    Description: "Product purchase",
    Customer: &payment.Customer{
        Email: "customer@example.com",
        Name:  "John Doe",
    },
    PaymentMethod: payment.PaymentMethodEWallet,
    Metadata: map[string]interface{}{
        "order_id": "order_456",
        "items":    []string{"item1", "item2"},
    },
}

response, err = manager.CreatePayment(ctx, "midtrans", paymentReq)
```

### Handling Different Payment Methods

```go
// Bank transfer payment
paymentReq := &payment.PaymentRequest{
    Amount:      100000, // $1000.00 in cents
    Currency:    "usd",
    Description: "Large purchase",
    Customer: &payment.Customer{
        Email: "business@example.com",
        Name:  "Business Corp",
    },
    PaymentMethod: payment.PaymentMethodBankTransfer,
    Metadata: map[string]interface{}{
        "invoice_id": "inv_789",
    },
}

response, err := manager.CreatePayment(ctx, "stripe", paymentReq)

// QR code payment
paymentReq = &payment.PaymentRequest{
    Amount:      15000, // $150.00 in cents
    Currency:    "sgd",
    Description: "Mobile payment",
    Customer: &payment.Customer{
        Email: "mobile@example.com",
    },
    PaymentMethod: payment.PaymentMethodQRCode,
}

response, err = manager.CreatePayment(ctx, "xendit", paymentReq)

// Virtual account payment
paymentReq = &payment.PaymentRequest{
    Amount:      75000, // $750.00 in cents
    Currency:    "idr",
    Description: "Bank transfer payment",
    Customer: &payment.Customer{
        Email: "bank@example.com",
        Name:  "Bank Customer",
    },
    PaymentMethod: payment.PaymentMethodVirtualAccount,
}

response, err = manager.CreatePayment(ctx, "midtrans", paymentReq)
```

### Processing Refunds

```go
// Full refund
refundReq := &payment.RefundRequest{
    PaymentID: "pay_1234567890",
    Reason:    "Customer requested refund",
    Metadata: map[string]interface{}{
        "refund_reason": "customer_request",
        "processed_by":  "admin_user",
    },
}

refundResp, err := manager.RefundPayment(ctx, "stripe", refundReq)

// Partial refund
refundReq = &payment.RefundRequest{
    PaymentID: "pay_1234567890",
    Amount:    int64Ptr(5000), // Refund $50.00
    Reason:    "Partial refund for damaged item",
    Metadata: map[string]interface{}{
        "refund_reason": "damaged_item",
        "item_id":       "item_123",
    },
}

refundResp, err = manager.RefundPayment(ctx, "stripe", refundReq)
```

### Webhook Handling

```go
// HTTP handler for webhooks
func webhookHandler(manager *payment.PaymentManager) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        // Read the request body
        body, err := ioutil.ReadAll(r.Body)
        if err != nil {
            http.Error(w, "Failed to read body", http.StatusBadRequest)
            return
        }

        // Get the signature from headers
        signature := r.Header.Get("Stripe-Signature") // or appropriate header for your provider

        // Process the webhook
        err = manager.ProcessWebhook(r.Context(), "stripe", body, signature)
        if err != nil {
            log.Printf("Webhook processing failed: %v", err)
            http.Error(w, "Webhook processing failed", http.StatusBadRequest)
            return
        }

        w.WriteHeader(http.StatusOK)
        w.Write([]byte("Webhook processed successfully"))
    }
}

// Register webhook handler
http.HandleFunc("/webhooks/payment", webhookHandler(manager))
```

### Payment Status Management

```go
// Check payment status
payment, err := manager.GetPayment(ctx, "stripe", "pay_1234567890")
if err != nil {
    log.Printf("Failed to get payment: %v", err)
    return
}

switch payment.Status {
case payment.PaymentStatusSucceeded:
    fmt.Println("Payment completed successfully")
    // Process order fulfillment
case payment.PaymentStatusFailed:
    fmt.Println("Payment failed")
    // Handle failed payment
case payment.PaymentStatusCanceled:
    fmt.Println("Payment was canceled")
    // Handle canceled payment
case payment.PaymentStatusExpired:
    fmt.Println("Payment expired")
    // Handle expired payment
case payment.PaymentStatusPending, payment.PaymentStatusProcessing:
    fmt.Println("Payment is still processing")
    // Continue monitoring
}

// Cancel a pending payment
if payment.Status == payment.PaymentStatusPending {
    err = manager.CancelPayment(ctx, "stripe", payment.ID)
    if err != nil {
        log.Printf("Failed to cancel payment: %v", err)
    }
}
```

### Provider Management

```go
// Get all supported providers
providers := manager.GetSupportedProviders()
fmt.Printf("Supported providers: %v\n", providers)

// Get provider capabilities
methods, currencies, err := manager.GetProviderCapabilities("stripe")
if err != nil {
    log.Printf("Failed to get provider capabilities: %v", err)
    return
}

fmt.Printf("Stripe supports methods: %v\n", methods)
fmt.Printf("Stripe supports currencies: %v\n", currencies)

// Check if provider supports specific payment method
supportsCard := false
for _, method := range methods {
    if method == payment.PaymentMethodCard {
        supportsCard = true
        break
    }
}

if supportsCard {
    fmt.Println("Stripe supports card payments")
}
```

### Error Handling

```go
response, err := manager.CreatePayment(ctx, "stripe", paymentReq)
if err != nil {
    // Handle different types of errors
    switch {
    case strings.Contains(err.Error(), "provider not found"):
        log.Printf("Payment provider not found: %v", err)
    case strings.Contains(err.Error(), "does not support"):
        log.Printf("Provider capability error: %v", err)
    case strings.Contains(err.Error(), "invalid payment request"):
        log.Printf("Validation error: %v", err)
    case strings.Contains(err.Error(), "failed to create payment after"):
        log.Printf("Retry exhausted: %v", err)
    default:
        log.Printf("Payment creation failed: %v", err)
    }
    return
}

// Handle payment response
if response.Status == payment.PaymentStatusFailed {
    log.Printf("Payment failed: %s", response.ID)
    // Handle failed payment
}
```

### Batch Operations

```go
// Process multiple payments
payments := []*payment.PaymentRequest{
    {
        Amount:      1000,
        Currency:    "usd",
        Description: "Payment 1",
        Customer:    &payment.Customer{Email: "user1@example.com"},
        PaymentMethod: payment.PaymentMethodCard,
    },
    {
        Amount:      2000,
        Currency:    "usd",
        Description: "Payment 2",
        Customer:    &payment.Customer{Email: "user2@example.com"},
        PaymentMethod: payment.PaymentMethodCard,
    },
}

var responses []*payment.PaymentResponse
for _, paymentReq := range payments {
    response, err := manager.CreatePayment(ctx, "stripe", paymentReq)
    if err != nil {
        log.Printf("Failed to create payment: %v", err)
        continue
    }
    responses = append(responses, response)
}

fmt.Printf("Created %d payments successfully\n", len(responses))
```

### Configuration Management

```go
// Custom configuration
config := &payment.ManagerConfig{
    DefaultProvider: "stripe",
    RetryAttempts:   5,
    RetryDelay:      10 * time.Second,
    Timeout:         60 * time.Second,
    WebhookSecret:   "whsec_...",
    Metadata: map[string]string{
        "environment": "production",
        "version":     "1.0.0",
    },
}

manager := payment.NewPaymentManager(config, logger)
```

## Best Practices

1. **Amount Handling**: Always store amounts in cents to avoid floating-point precision issues
2. **Currency Validation**: Validate currency codes before processing payments
3. **Webhook Security**: Always validate webhook signatures
4. **Error Handling**: Implement comprehensive error handling for all payment operations
5. **Retry Logic**: Use appropriate retry strategies for transient failures
6. **Idempotency**: Use unique payment IDs to prevent duplicate payments
7. **Logging**: Log all payment operations for audit trails
8. **Testing**: Test with sandbox/test environments before production
9. **Compliance**: Ensure PCI DSS compliance for card payments
10. **Monitoring**: Monitor payment success rates and failure patterns

## Contributing

Contributions are welcome! Please read the contributing guidelines and submit pull requests for any improvements.

## License

This library is licensed under the MIT License. See the LICENSE file for details.
