# File Generation Library

The File Generation library provides a unified interface for generating various file formats including DOCX, Excel, CSV, PDF, and custom formats. It offers comprehensive file generation capabilities with support for templates, data binding, batch processing, and advanced features like styling, formatting, and comprehensive error handling.

## Features

- **Multi-Format Support**: DOCX, Excel, CSV, PDF, and custom formats
- **Template Engine**: Powerful template system for file generation
- **Data Binding**: Dynamic data binding with structured data
- **Batch Processing**: Generate multiple files efficiently
- **Styling Support**: Rich formatting and styling options
- **Template Management**: Create, update, and manage templates
- **Validation**: Comprehensive request validation
- **Error Handling**: Detailed error reporting and handling
- **Streaming**: Support for streaming large files
- **Custom Providers**: Extensible provider system
- **MIME Type Detection**: Automatic MIME type detection
- **File Size Limits**: Configurable file size limits

## Supported Formats

- **DOCX**: Microsoft Word documents with rich formatting
- **Excel**: Microsoft Excel spreadsheets with formulas and charts
- **CSV**: Comma-separated values for data exchange
- **PDF**: Portable Document Format with text and graphics
- **Custom**: Custom file formats through template system

## Installation

```bash
go get github.com/anasamu/go-micro-libs/filegen
```

## Quick Start

```go
package main

import (
    "context"
    "fmt"
    "log"
    "os"

    "github.com/anasamu/go-micro-libs/filegen"
    "github.com/anasamu/go-micro-libs/filegen/types"
)

func main() {
    // Create file generation manager
    config := &filegen.ManagerConfig{
        TemplatePath: "./templates",
        OutputPath:   "./output",
        MaxFileSize:  100 * 1024 * 1024, // 100MB
        AllowedTypes: []types.FileType{
            types.FileTypeDOCX,
            types.FileTypeExcel,
            types.FileTypeCSV,
            types.FileTypePDF,
            types.FileTypeCustom,
        },
    }

    manager, err := filegen.NewManager(config)
    if err != nil {
        log.Fatalf("Failed to create manager: %v", err)
    }
    defer manager.Close()

    ctx := context.Background()

    // Generate a DOCX document
    docxRequest := &types.FileRequest{
        Type:       types.FileTypeDOCX,
        Template:   "invoice",
        OutputPath: "./output/invoice.docx",
        Data: map[string]interface{}{
            "invoice_number": "INV-001",
            "date":          "2024-01-15",
            "customer": map[string]interface{}{
                "name":    "John Doe",
                "email":   "john@example.com",
                "address": "123 Main St, City, State 12345",
            },
            "items": []map[string]interface{}{
                {
                    "description": "Product A",
                    "quantity":    2,
                    "price":       25.00,
                    "total":       50.00,
                },
                {
                    "description": "Product B",
                    "quantity":    1,
                    "price":       15.00,
                    "total":       15.00,
                },
            },
            "subtotal": 65.00,
            "tax":      5.20,
            "total":    70.20,
        },
        Options: map[string]interface{}{
            "format": "professional",
            "color":  "blue",
        },
    }

    response, err := manager.GenerateFile(ctx, docxRequest)
    if err != nil {
        log.Fatalf("Failed to generate DOCX: %v", err)
    }

    fmt.Printf("DOCX generated successfully: %s\n", response.FilePath)
    fmt.Printf("File size: %d bytes\n", response.FileSize)

    // Generate an Excel spreadsheet
    excelRequest := &types.FileRequest{
        Type:       types.FileTypeExcel,
        Template:   "sales_report",
        OutputPath: "./output/sales_report.xlsx",
        Data: map[string]interface{}{
            "report_title": "Monthly Sales Report",
            "period":       "January 2024",
            "sales_data": []map[string]interface{}{
                {
                    "date":        "2024-01-01",
                    "product":     "Product A",
                    "quantity":    10,
                    "revenue":     250.00,
                    "profit":      50.00,
                },
                {
                    "date":        "2024-01-02",
                    "product":     "Product B",
                    "quantity":    5,
                    "revenue":     75.00,
                    "profit":      15.00,
                },
            },
            "summary": map[string]interface{}{
                "total_revenue": 325.00,
                "total_profit":  65.00,
                "total_quantity": 15,
            },
        },
        Options: map[string]interface{}{
            "include_charts": true,
            "format":         "detailed",
        },
    }

    response, err = manager.GenerateFile(ctx, excelRequest)
    if err != nil {
        log.Fatalf("Failed to generate Excel: %v", err)
    }

    fmt.Printf("Excel generated successfully: %s\n", response.FilePath)

    // Generate a CSV file
    csvRequest := &types.FileRequest{
        Type:       types.FileTypeCSV,
        Template:   "user_export",
        OutputPath: "./output/users.csv",
        Data: map[string]interface{}{
            "users": []map[string]interface{}{
                {
                    "id":       1,
                    "name":     "John Doe",
                    "email":    "john@example.com",
                    "role":     "admin",
                    "created":  "2024-01-01",
                },
                {
                    "id":       2,
                    "name":     "Jane Smith",
                    "email":    "jane@example.com",
                    "role":     "user",
                    "created":  "2024-01-02",
                },
            },
        },
        Options: map[string]interface{}{
            "delimiter": ",",
            "headers":   true,
        },
    }

    response, err = manager.GenerateFile(ctx, csvRequest)
    if err != nil {
        log.Fatalf("Failed to generate CSV: %v", err)
    }

    fmt.Printf("CSV generated successfully: %s\n", response.FilePath)

    // Generate a PDF document
    pdfRequest := &types.FileRequest{
        Type:       types.FileTypePDF,
        Template:   "contract",
        OutputPath: "./output/contract.pdf",
        Data: map[string]interface{}{
            "contract_number": "CON-001",
            "parties": map[string]interface{}{
                "client": map[string]interface{}{
                    "name":    "ABC Company",
                    "address": "456 Business Ave, City, State 54321",
                },
                "provider": map[string]interface{}{
                    "name":    "XYZ Services",
                    "address": "789 Service St, City, State 98765",
                },
            },
            "terms": []string{
                "Service will be provided for 12 months",
                "Payment terms: Net 30 days",
                "Termination requires 30 days notice",
            },
            "effective_date": "2024-01-15",
            "expiry_date":    "2025-01-15",
        },
        Options: map[string]interface{}{
            "format": "legal",
            "signature_required": true,
        },
    }

    response, err = manager.GenerateFile(ctx, pdfRequest)
    if err != nil {
        log.Fatalf("Failed to generate PDF: %v", err)
    }

    fmt.Printf("PDF generated successfully: %s\n", response.FilePath)

    // Get supported file types
    supportedTypes := manager.GetSupportedTypes()
    fmt.Printf("Supported file types: %v\n", supportedTypes)

    // Get MIME type for a file type
    mimeType := manager.GetMimeType(types.FileTypeDOCX)
    fmt.Printf("DOCX MIME type: %s\n", mimeType)

    // Get file extension
    extension := manager.GetFileExtension(types.FileTypeExcel)
    fmt.Printf("Excel extension: %s\n", extension)
}
```

## Configuration

### Manager Configuration

```go
type ManagerConfig struct {
    TemplatePath string
    OutputPath   string
    MaxFileSize  int64
    AllowedTypes []types.FileType
}
```

### File Request Structure

```go
type FileRequest struct {
    Type       FileType                `json:"type"`
    Template   string                  `json:"template"`
    OutputPath string                  `json:"output_path,omitempty"`
    Data       map[string]interface{}  `json:"data"`
    Options    map[string]interface{}  `json:"options,omitempty"`
    Metadata   map[string]interface{}  `json:"metadata,omitempty"`
}
```

### File Response Structure

```go
type FileResponse struct {
    Success    bool   `json:"success"`
    FilePath   string `json:"file_path,omitempty"`
    FileSize   int64  `json:"file_size,omitempty"`
    Content    []byte `json:"content,omitempty"`
    MimeType   string `json:"mime_type,omitempty"`
    Error      string `json:"error,omitempty"`
    Metadata   map[string]interface{} `json:"metadata,omitempty"`
}
```

## API Reference

### Core Operations
- `GenerateFile(ctx, request)` - Generate a file from template and data
- `GenerateFileToWriter(ctx, request, writer)` - Generate file to a writer
- `GetSupportedTypes()` - Get all supported file types
- `GetProvider(fileType)` - Get provider for specific file type
- `GetTemplateList(fileType)` - Get available templates for file type
- `GetTemplateInfo(fileType, templateName)` - Get template information

### Utility Functions
- `GetMimeType(fileType)` - Get MIME type for file type
- `GetFileExtension(fileType)` - Get file extension for file type
- `Close()` - Close all providers and cleanup

## File Types

### Supported File Types
- `FileTypeDOCX` - Microsoft Word documents
- `FileTypeExcel` - Microsoft Excel spreadsheets
- `FileTypeCSV` - Comma-separated values
- `FileTypePDF` - Portable Document Format
- `FileTypeCustom` - Custom file formats

## Template System

### Template Structure
Templates are organized by file type in the template directory:

```
templates/
├── docx/
│   ├── invoice.docx
│   ├── report.docx
│   └── contract.docx
├── excel/
│   ├── sales_report.xlsx
│   ├── budget.xlsx
│   └── inventory.xlsx
├── csv/
│   ├── user_export.csv
│   └── data_export.csv
├── pdf/
│   ├── contract.tmpl
│   └── report.tmpl
└── custom/
    └── custom.tmpl
```

### Template Variables
Templates support various variable types:
- Simple variables: `{{.variable_name}}`
- Nested objects: `{{.object.property}}`
- Arrays: `{{range .array}}{{.property}}{{end}}`
- Conditionals: `{{if .condition}}...{{end}}`
- Functions: `{{.function_name .parameter}}`

## Error Handling

The library provides comprehensive error handling with specific error types:

```go
type FileGenerationError struct {
    Type    ErrorType `json:"type"`
    Message string    `json:"message"`
    Code    int       `json:"code"`
    Details map[string]interface{} `json:"details"`
}
```

### Error Types
- `ErrorTypeValidation` - Validation errors
- `ErrorTypeTemplate` - Template-related errors
- `ErrorTypeData` - Data-related errors
- `ErrorTypeIO` - Input/output errors
- `ErrorTypeProvider` - Provider-specific errors
- `ErrorTypeInternal` - Internal server errors

## Best Practices

### Template Design
1. **Consistent Structure**: Use consistent template structure
2. **Variable Naming**: Use descriptive variable names
3. **Error Handling**: Include error handling in templates
4. **Documentation**: Document template variables and usage

### Data Preparation
1. **Data Validation**: Validate data before generation
2. **Data Structure**: Use consistent data structures
3. **Null Handling**: Handle null/empty values gracefully
4. **Type Safety**: Ensure proper data types

### Performance Optimization
1. **Template Caching**: Cache frequently used templates
2. **Batch Processing**: Use batch processing for multiple files
3. **Streaming**: Use streaming for large files
4. **Resource Management**: Properly manage resources

## Examples

### Invoice Generation

```go
// Generate invoice DOCX
invoiceData := map[string]interface{}{
    "invoice_number": "INV-2024-001",
    "date":          time.Now().Format("2006-01-02"),
    "due_date":      time.Now().AddDate(0, 0, 30).Format("2006-01-02"),
    "company": map[string]interface{}{
        "name":    "Your Company",
        "address": "123 Business St",
        "phone":   "+1-555-0123",
        "email":   "billing@yourcompany.com",
    },
    "customer": map[string]interface{}{
        "name":    "Customer Name",
        "address": "456 Customer Ave",
        "email":   "customer@example.com",
    },
    "items": []map[string]interface{}{
        {
            "description": "Web Development",
            "quantity":    40,
            "rate":        75.00,
            "amount":      3000.00,
        },
        {
            "description": "Design Services",
            "quantity":    20,
            "rate":        50.00,
            "amount":      1000.00,
        },
    },
    "subtotal": 4000.00,
    "tax_rate": 0.08,
    "tax":      320.00,
    "total":    4320.00,
}

request := &types.FileRequest{
    Type:       types.FileTypeDOCX,
    Template:   "invoice",
    OutputPath: "./output/invoice.docx",
    Data:       invoiceData,
}
```

### Sales Report Generation

```go
// Generate Excel sales report
salesData := map[string]interface{}{
    "report_title": "Q1 2024 Sales Report",
    "period":       "January - March 2024",
    "generated_at": time.Now().Format("2006-01-02 15:04:05"),
    "sales_by_month": []map[string]interface{}{
        {
            "month":   "January",
            "revenue": 15000.00,
            "orders":  45,
        },
        {
            "month":   "February",
            "revenue": 18000.00,
            "orders":  52,
        },
        {
            "month":   "March",
            "revenue": 22000.00,
            "orders":  68,
        },
    },
    "top_products": []map[string]interface{}{
        {
            "name":     "Product A",
            "sales":    150,
            "revenue":  7500.00,
        },
        {
            "name":     "Product B",
            "sales":    120,
            "revenue":  6000.00,
        },
    },
    "summary": map[string]interface{}{
        "total_revenue": 55000.00,
        "total_orders":  165,
        "avg_order_value": 333.33,
    },
}

request := &types.FileRequest{
    Type:       types.FileTypeExcel,
    Template:   "sales_report",
    OutputPath: "./output/q1_sales_report.xlsx",
    Data:       salesData,
    Options: map[string]interface{}{
        "include_charts": true,
        "format":         "detailed",
    },
}
```

### Data Export

```go
// Generate CSV data export
exportData := map[string]interface{}{
    "export_date": time.Now().Format("2006-01-02"),
    "records": []map[string]interface{}{
        {
            "id":        1,
            "name":      "John Doe",
            "email":     "john@example.com",
            "status":    "active",
            "created":   "2024-01-01",
            "last_login": "2024-01-15",
        },
        {
            "id":        2,
            "name":      "Jane Smith",
            "email":     "jane@example.com",
            "status":    "inactive",
            "created":   "2024-01-02",
            "last_login": "2024-01-10",
        },
    },
}

request := &types.FileRequest{
    Type:       types.FileTypeCSV,
    Template:   "user_export",
    OutputPath: "./output/users_export.csv",
    Data:       exportData,
    Options: map[string]interface{}{
        "delimiter": ",",
        "headers":   true,
        "encoding":  "utf-8",
    },
}
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Submit a pull request

## License

This library is licensed under the MIT License. See the LICENSE file for details.
