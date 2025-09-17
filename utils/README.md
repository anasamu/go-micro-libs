# Utils Library

The Utils library provides a comprehensive collection of utility functions for common operations including string manipulation, validation, cryptography, time handling, UUID generation, logging, and file operations. It offers a clean, consistent API with both instance-based and global convenience functions for maximum flexibility and ease of use.

## Features

- **String Utilities**: String manipulation, formatting, and validation
- **Validation Utilities**: Email, phone, URL, UUID, and password validation
- **Cryptographic Utilities**: Password hashing, verification, and hash generation
- **Time Utilities**: Time manipulation, formatting, and date calculations
- **UUID Utilities**: UUID generation, parsing, and validation
- **Logging Utilities**: Structured logging with context
- **File Utilities**: File extension handling and size formatting
- **Global Functions**: Convenience functions for quick access
- **Type Safety**: Strong typing with comprehensive error handling
- **Performance**: Optimized implementations for common operations

## Installation

```bash
go get github.com/anasamu/go-micro-libs/utils
```

## Quick Start

```go
package main

import (
    "fmt"
    "log"
    "time"

    "github.com/anasamu/go-micro-libs/utils"
    "github.com/sirupsen/logrus"
)

func main() {
    // String utilities
    stringUtils := utils.NewStringUtils()
    
    // Check if string is empty
    if stringUtils.IsEmpty("") {
        fmt.Println("String is empty")
    }
    
    // Capitalize string
    capitalized := stringUtils.Capitalize("hello world")
    fmt.Printf("Capitalized: %s\n", capitalized) // "Hello world"
    
    // Create URL-friendly slug
    slug := stringUtils.Slugify("Hello World! This is a test.")
    fmt.Printf("Slug: %s\n", slug) // "hello-world-this-is-a-test"
    
    // Generate random string
    randomStr := stringUtils.RandomString(10)
    fmt.Printf("Random string: %s\n", randomStr)
    
    // Validation utilities
    validationUtils := utils.NewValidationUtils()
    
    // Validate email
    if validationUtils.IsValidEmail("user@example.com") {
        fmt.Println("Valid email")
    }
    
    // Validate password with details
    isValid, errors := validationUtils.ValidatePasswordWithDetails("MySecure123!")
    if !isValid {
        fmt.Printf("Password validation errors: %v\n", errors)
    } else {
        fmt.Println("Password is valid")
    }
    
    // Cryptographic utilities
    cryptoUtils := utils.NewCryptoUtils()
    
    // Hash password
    hashedPassword, err := cryptoUtils.HashPassword("MySecure123!")
    if err != nil {
        log.Fatalf("Failed to hash password: %v", err)
    }
    fmt.Printf("Hashed password: %s\n", hashedPassword)
    
    // Verify password
    isValidPassword := cryptoUtils.VerifyPassword("MySecure123!", hashedPassword)
    fmt.Printf("Password verification: %v\n", isValidPassword)
    
    // Generate hash
    hash := cryptoUtils.GenerateHash("Hello World")
    fmt.Printf("SHA256 hash: %s\n", hash)
    
    // Time utilities
    timeUtils := utils.NewTimeUtils()
    
    // Get current time
    now := timeUtils.Now()
    fmt.Printf("Current time: %s\n", now.Format(time.RFC3339))
    
    // Check if time is today
    if timeUtils.IsToday(now) {
        fmt.Println("Time is today")
    }
    
    // Get start and end of day
    startOfDay := timeUtils.GetStartOfDay(now)
    endOfDay := timeUtils.GetEndOfDay(now)
    fmt.Printf("Start of day: %s\n", startOfDay.Format(time.RFC3339))
    fmt.Printf("End of day: %s\n", endOfDay.Format(time.RFC3339))
    
    // UUID utilities
    uuidUtils := utils.NewUUIDUtils()
    
    // Generate UUID
    newUUID := uuidUtils.Generate()
    fmt.Printf("Generated UUID: %s\n", newUUID.String())
    
    // Validate UUID
    if uuidUtils.IsValid(newUUID.String()) {
        fmt.Println("UUID is valid")
    }
    
    // File utilities
    fileUtils := utils.NewFileUtils()
    
    // Get file extension
    extension := fileUtils.GetFileExtension("document.pdf")
    fmt.Printf("File extension: %s\n", extension)
    
    // Check if extension is valid image
    if fileUtils.IsValidImageExtension("jpg") {
        fmt.Println("Valid image extension")
    }
    
    // Format file size
    formattedSize := fileUtils.FormatFileSize(1024 * 1024) // 1MB
    fmt.Printf("Formatted size: %s\n", formattedSize)
    
    // Logging utilities
    logger := logrus.New()
    logUtils := utils.NewLogUtils(logger)
    
    // Log with context
    logUtils.LogInfo("Application started", logrus.Fields{
        "version": "1.0.0",
        "port":    8080,
    })
    
    // Log with user context
    logUtils.LogWithUser("User action performed", "user-123", "tenant-1", logrus.Fields{
        "action": "login",
        "ip":     "192.168.1.1",
    })
    
    // Global convenience functions
    fmt.Printf("Is empty: %v\n", utils.IsEmpty(""))
    fmt.Printf("Is valid email: %v\n", utils.IsValidEmail("test@example.com"))
    fmt.Printf("Current time: %s\n", utils.Now().Format(time.RFC3339))
    fmt.Printf("Generated UUID: %s\n", utils.GenerateUUIDString())
}
```

## API Reference

### String Utilities

#### Instance Methods
- `IsEmpty(s string) bool` - Check if string is empty or whitespace only
- `IsNotEmpty(s string) bool` - Check if string is not empty
- `Truncate(s string, length int) string` - Truncate string to specified length
- `Capitalize(s string) string` - Capitalize first letter
- `TitleCase(s string) string` - Convert to title case
- `Slugify(s string) string` - Convert to URL-friendly slug
- `Contains(s, substr string) bool` - Case-insensitive substring check
- `RandomString(length int) string` - Generate random string

#### Global Functions
- `IsEmpty(s string) bool`
- `IsNotEmpty(s string) bool`

### Validation Utilities

#### Instance Methods
- `IsValidEmail(email string) bool` - Validate email address
- `IsValidPhone(phone string) bool` - Validate phone number
- `IsValidURL(url string) bool` - Validate URL
- `IsValidUUID(uuidStr string) bool` - Validate UUID
- `IsValidPassword(password string) bool` - Validate password strength
- `ValidatePasswordWithDetails(password string) (bool, []string)` - Detailed password validation

#### Global Functions
- `IsValidEmail(email string) bool`
- `IsValidPhone(phone string) bool`
- `IsValidURL(url string) bool`
- `IsValidUUID(uuidStr string) bool`
- `IsValidPassword(password string) bool`

### Cryptographic Utilities

#### Instance Methods
- `HashPassword(password string) (string, error)` - Hash password with bcrypt
- `VerifyPassword(password, hash string) bool` - Verify password against hash
- `GenerateHash(input string) string` - Generate SHA256 hash
- `GenerateRandomBytes(length int) ([]byte, error)` - Generate random bytes

#### Global Functions
- `HashPassword(password string) (string, error)`
- `VerifyPassword(password, hash string) bool`
- `GenerateHash(input string) string`

### Time Utilities

#### Instance Methods
- `Now() time.Time` - Get current time
- `NowUTC() time.Time` - Get current UTC time
- `FormatTime(t time.Time, layout string) string` - Format time
- `ParseTime(timeStr, layout string) (time.Time, error)` - Parse time string
- `IsToday(t time.Time) bool` - Check if time is today
- `IsYesterday(t time.Time) bool` - Check if time is yesterday
- `IsThisWeek(t time.Time) bool` - Check if time is this week
- `IsThisMonth(t time.Time) bool` - Check if time is this month
- `IsThisYear(t time.Time) bool` - Check if time is this year
- `AddDays(t time.Time, days int) time.Time` - Add days to time
- `AddMonths(t time.Time, months int) time.Time` - Add months to time
- `AddYears(t time.Time, years int) time.Time` - Add years to time
- `GetStartOfDay(t time.Time) time.Time` - Get start of day
- `GetEndOfDay(t time.Time) time.Time` - Get end of day
- `GetStartOfWeek(t time.Time) time.Time` - Get start of week
- `GetEndOfWeek(t time.Time) time.Time` - Get end of week
- `GetStartOfMonth(t time.Time) time.Time` - Get start of month
- `GetEndOfMonth(t time.Time) time.Time` - Get end of month
- `GetStartOfYear(t time.Time) time.Time` - Get start of year
- `GetEndOfYear(t time.Time) time.Time` - Get end of year

#### Global Functions
- `Now() time.Time`
- `NowUTC() time.Time`

### UUID Utilities

#### Instance Methods
- `Generate() uuid.UUID` - Generate new UUID
- `GenerateString() string` - Generate UUID as string
- `Parse(uuidStr string) (uuid.UUID, error)` - Parse UUID string
- `IsValid(uuidStr string) bool` - Validate UUID string

#### Global Functions
- `GenerateUUID() uuid.UUID`
- `GenerateUUIDString() string`

### Logging Utilities

#### Instance Methods
- `LogError(err error, message string, fields logrus.Fields)` - Log error with context
- `LogInfo(message string, fields logrus.Fields)` - Log info message
- `LogWarning(message string, fields logrus.Fields)` - Log warning message
- `LogDebug(message string, fields logrus.Fields)` - Log debug message
- `LogWithDuration(message string, duration time.Duration, fields logrus.Fields)` - Log with duration
- `LogWithUser(message string, userID, tenantID string, fields logrus.Fields)` - Log with user context
- `LogWithRequest(message string, requestID, method, path string, fields logrus.Fields)` - Log with request context

### File Utilities

#### Instance Methods
- `GetFileExtension(filename string) string` - Get file extension
- `GetFileNameWithoutExtension(filename string) string` - Get filename without extension
- `IsValidImageExtension(extension string) bool` - Check if valid image extension
- `IsValidDocumentExtension(extension string) bool` - Check if valid document extension
- `FormatFileSize(size int64) string` - Format file size in human readable format

## Usage Examples

### String Manipulation

```go
stringUtils := utils.NewStringUtils()

// Basic string operations
fmt.Println(stringUtils.IsEmpty(""))           // true
fmt.Println(stringUtils.IsNotEmpty("hello"))   // true
fmt.Println(stringUtils.Capitalize("hello"))   // "Hello"
fmt.Println(stringUtils.TitleCase("hello world")) // "Hello World"

// URL-friendly slug generation
slug := stringUtils.Slugify("Hello World! This is a test.")
fmt.Println(slug) // "hello-world-this-is-a-test"

// String truncation
truncated := stringUtils.Truncate("This is a very long string", 10)
fmt.Println(truncated) // "This is a ..."

// Random string generation
random := stringUtils.RandomString(8)
fmt.Println(random) // Random 8-character string
```

### Validation

```go
validationUtils := utils.NewValidationUtils()

// Email validation
fmt.Println(validationUtils.IsValidEmail("user@example.com")) // true
fmt.Println(validationUtils.IsValidEmail("invalid-email"))    // false

// Phone validation
fmt.Println(validationUtils.IsValidPhone("+1234567890"))      // true
fmt.Println(validationUtils.IsValidPhone("invalid-phone"))    // false

// URL validation
fmt.Println(validationUtils.IsValidURL("https://example.com")) // true
fmt.Println(validationUtils.IsValidURL("invalid-url"))         // false

// Password validation with details
isValid, errors := validationUtils.ValidatePasswordWithDetails("weak")
if !isValid {
    for _, err := range errors {
        fmt.Println(err)
    }
}
```

### Password Security

```go
cryptoUtils := utils.NewCryptoUtils()

// Hash password
password := "MySecure123!"
hashedPassword, err := cryptoUtils.HashPassword(password)
if err != nil {
    log.Fatal(err)
}

// Verify password
isValid := cryptoUtils.VerifyPassword(password, hashedPassword)
fmt.Printf("Password verification: %v\n", isValid)

// Generate hash for other purposes
hash := cryptoUtils.GenerateHash("Hello World")
fmt.Printf("SHA256 hash: %s\n", hash)
```

### Time Operations

```go
timeUtils := utils.NewTimeUtils()

// Current time
now := timeUtils.Now()
fmt.Printf("Current time: %s\n", now.Format(time.RFC3339))

// Date calculations
startOfDay := timeUtils.GetStartOfDay(now)
endOfDay := timeUtils.GetEndOfDay(now)
fmt.Printf("Start of day: %s\n", startOfDay.Format(time.RFC3339))
fmt.Printf("End of day: %s\n", endOfDay.Format(time.RFC3339))

// Week calculations
startOfWeek := timeUtils.GetStartOfWeek(now)
endOfWeek := timeUtils.GetEndOfWeek(now)
fmt.Printf("Start of week: %s\n", startOfWeek.Format(time.RFC3339))
fmt.Printf("End of week: %s\n", endOfWeek.Format(time.RFC3339))

// Month calculations
startOfMonth := timeUtils.GetStartOfMonth(now)
endOfMonth := timeUtils.GetEndOfMonth(now)
fmt.Printf("Start of month: %s\n", startOfMonth.Format(time.RFC3339))
fmt.Printf("End of month: %s\n", endOfMonth.Format(time.RFC3339))

// Time checks
fmt.Printf("Is today: %v\n", timeUtils.IsToday(now))
fmt.Printf("Is this week: %v\n", timeUtils.IsThisWeek(now))
fmt.Printf("Is this month: %v\n", timeUtils.IsThisMonth(now))
```

### UUID Generation

```go
uuidUtils := utils.NewUUIDUtils()

// Generate UUID
newUUID := uuidUtils.Generate()
fmt.Printf("Generated UUID: %s\n", newUUID.String())

// Generate UUID as string
uuidString := uuidUtils.GenerateString()
fmt.Printf("UUID string: %s\n", uuidString)

// Validate UUID
isValid := uuidUtils.IsValid(uuidString)
fmt.Printf("UUID is valid: %v\n", isValid)

// Parse UUID
parsedUUID, err := uuidUtils.Parse(uuidString)
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Parsed UUID: %s\n", parsedUUID.String())
```

### Structured Logging

```go
logger := logrus.New()
logUtils := utils.NewLogUtils(logger)

// Basic logging
logUtils.LogInfo("Application started", logrus.Fields{
    "version": "1.0.0",
    "port":    8080,
})

// Error logging
err := fmt.Errorf("database connection failed")
logUtils.LogError(err, "Failed to connect to database", logrus.Fields{
    "host": "localhost",
    "port": 5432,
})

// User context logging
logUtils.LogWithUser("User logged in", "user-123", "tenant-1", logrus.Fields{
    "ip_address": "192.168.1.1",
    "user_agent": "Mozilla/5.0",
})

// Request context logging
logUtils.LogWithRequest("API request processed", "req-456", "GET", "/api/users", logrus.Fields{
    "status_code": 200,
    "duration":    "150ms",
})

// Duration logging
start := time.Now()
// ... perform operation ...
duration := time.Since(start)
logUtils.LogWithDuration("Operation completed", duration, logrus.Fields{
    "operation": "data_processing",
})
```

### File Operations

```go
fileUtils := utils.NewFileUtils()

// File extension operations
filename := "document.pdf"
extension := fileUtils.GetFileExtension(filename)
fmt.Printf("File extension: %s\n", extension) // "pdf"

nameWithoutExt := fileUtils.GetFileNameWithoutExtension(filename)
fmt.Printf("Name without extension: %s\n", nameWithoutExt) // "document"

// File type validation
fmt.Printf("Is valid image: %v\n", fileUtils.IsValidImageExtension("jpg"))     // true
fmt.Printf("Is valid image: %v\n", fileUtils.IsValidImageExtension("txt"))     // false
fmt.Printf("Is valid document: %v\n", fileUtils.IsValidDocumentExtension("pdf")) // true
fmt.Printf("Is valid document: %v\n", fileUtils.IsValidDocumentExtension("jpg")) // false

// File size formatting
fmt.Printf("Formatted size: %s\n", fileUtils.FormatFileSize(1024))           // "1.0 KB"
fmt.Printf("Formatted size: %s\n", fileUtils.FormatFileSize(1024*1024))      // "1.0 MB"
fmt.Printf("Formatted size: %s\n", fileUtils.FormatFileSize(1024*1024*1024)) // "1.0 GB"
```

## Best Practices

### Performance
1. **Reuse Instances**: Create utility instances once and reuse them
2. **Global Functions**: Use global functions for simple operations
3. **Error Handling**: Always handle errors appropriately
4. **Validation**: Validate inputs before processing

### Security
1. **Password Hashing**: Always use the provided password hashing functions
2. **Input Validation**: Validate all user inputs
3. **Random Generation**: Use the provided random generation functions
4. **Logging**: Be careful not to log sensitive information

### Code Organization
1. **Consistent Usage**: Use either instance methods or global functions consistently
2. **Error Handling**: Implement proper error handling
3. **Logging**: Use structured logging for better debugging
4. **Documentation**: Document custom utility functions

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Submit a pull request

## License

This library is licensed under the MIT License. See the LICENSE file for details.
