package utils

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

// StringUtils provides string utility functions
type StringUtils struct{}

// NewStringUtils creates a new StringUtils instance
func NewStringUtils() *StringUtils {
	return &StringUtils{}
}

// IsEmpty checks if a string is empty or contains only whitespace
func (su *StringUtils) IsEmpty(s string) bool {
	return strings.TrimSpace(s) == ""
}

// IsNotEmpty checks if a string is not empty
func (su *StringUtils) IsNotEmpty(s string) bool {
	return !su.IsEmpty(s)
}

// Truncate truncates a string to the specified length
func (su *StringUtils) Truncate(s string, length int) string {
	if len(s) <= length {
		return s
	}
	return s[:length] + "..."
}

// Capitalize capitalizes the first letter of a string
func (su *StringUtils) Capitalize(s string) string {
	if su.IsEmpty(s) {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// TitleCase converts a string to title case
func (su *StringUtils) TitleCase(s string) string {
	caser := cases.Title(language.English)
	return caser.String(s)
}

// Slugify converts a string to a URL-friendly slug
func (su *StringUtils) Slugify(s string) string {
	// Convert to lowercase
	s = strings.ToLower(s)

	// Replace spaces with hyphens
	s = strings.ReplaceAll(s, " ", "-")

	// Remove special characters
	reg := regexp.MustCompile(`[^a-z0-9\-]`)
	s = reg.ReplaceAllString(s, "")

	// Remove multiple consecutive hyphens
	reg = regexp.MustCompile(`-+`)
	s = reg.ReplaceAllString(s, "-")

	// Remove leading/trailing hyphens
	s = strings.Trim(s, "-")

	return s
}

// Contains checks if a string contains a substring (case-insensitive)
func (su *StringUtils) Contains(s, substr string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}

// RandomString generates a random string of specified length
func (su *StringUtils) RandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		num, _ := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		b[i] = charset[num.Int64()]
	}
	return string(b)
}

// ValidationUtils provides validation utility functions
type ValidationUtils struct{}

// NewValidationUtils creates a new ValidationUtils instance
func NewValidationUtils() *ValidationUtils {
	return &ValidationUtils{}
}

// IsValidEmail validates an email address
func (vu *ValidationUtils) IsValidEmail(email string) bool {
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	return emailRegex.MatchString(email)
}

// IsValidPhone validates a phone number
func (vu *ValidationUtils) IsValidPhone(phone string) bool {
	phoneRegex := regexp.MustCompile(`^\+?[1-9]\d{1,14}$`)
	return phoneRegex.MatchString(phone)
}

// IsValidURL validates a URL
func (vu *ValidationUtils) IsValidURL(url string) bool {
	urlRegex := regexp.MustCompile(`^https?://[^\s/$.?#].[^\s]*$`)
	return urlRegex.MatchString(url)
}

// IsValidUUID validates a UUID
func (vu *ValidationUtils) IsValidUUID(uuidStr string) bool {
	_, err := uuid.Parse(uuidStr)
	return err == nil
}

// IsValidPassword validates a password with strong requirements
func (vu *ValidationUtils) IsValidPassword(password string) bool {
	// Minimum 12 characters for better security
	if len(password) < 12 {
		return false
	}

	// Maximum length to prevent DoS attacks
	if len(password) > 128 {
		return false
	}

	// Check for at least one lowercase letter
	hasLower := regexp.MustCompile(`[a-z]`).MatchString(password)
	// Check for at least one uppercase letter
	hasUpper := regexp.MustCompile(`[A-Z]`).MatchString(password)
	// Check for at least one number
	hasNumber := regexp.MustCompile(`[0-9]`).MatchString(password)
	// Check for at least one special character
	hasSpecial := regexp.MustCompile(`[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?~` + "`" + `]`).MatchString(password)

	// All requirements must be met
	return hasLower && hasUpper && hasNumber && hasSpecial
}

// ValidatePasswordWithDetails validates a password and returns detailed error messages
func (vu *ValidationUtils) ValidatePasswordWithDetails(password string) (bool, []string) {
	var errors []string

	if len(password) < 12 {
		errors = append(errors, "Password must be at least 12 characters long")
	}

	if len(password) > 128 {
		errors = append(errors, "Password must be no more than 128 characters long")
	}

	if !regexp.MustCompile(`[a-z]`).MatchString(password) {
		errors = append(errors, "Password must contain at least one lowercase letter")
	}

	if !regexp.MustCompile(`[A-Z]`).MatchString(password) {
		errors = append(errors, "Password must contain at least one uppercase letter")
	}

	if !regexp.MustCompile(`[0-9]`).MatchString(password) {
		errors = append(errors, "Password must contain at least one number")
	}

	if !regexp.MustCompile(`[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?~` + "`" + `]`).MatchString(password) {
		errors = append(errors, "Password must contain at least one special character")
	}

	return len(errors) == 0, errors
}

// CryptoUtils provides cryptographic utility functions
type CryptoUtils struct{}

// NewCryptoUtils creates a new CryptoUtils instance
func NewCryptoUtils() *CryptoUtils {
	return &CryptoUtils{}
}

// HashPassword hashes a password using bcrypt
func (cu *CryptoUtils) HashPassword(password string) (string, error) {
	hashedBytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("failed to hash password: %w", err)
	}
	return string(hashedBytes), nil
}

// VerifyPassword verifies a password against its hash
func (cu *CryptoUtils) VerifyPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// GenerateHash generates a SHA256 hash of the input string
func (cu *CryptoUtils) GenerateHash(input string) string {
	hash := sha256.Sum256([]byte(input))
	return hex.EncodeToString(hash[:])
}

// GenerateRandomBytes generates random bytes of specified length
func (cu *CryptoUtils) GenerateRandomBytes(length int) ([]byte, error) {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random bytes: %w", err)
	}
	return bytes, nil
}

// TimeUtils provides time utility functions
type TimeUtils struct{}

// NewTimeUtils creates a new TimeUtils instance
func NewTimeUtils() *TimeUtils {
	return &TimeUtils{}
}

// Now returns the current time
func (tu *TimeUtils) Now() time.Time {
	return time.Now()
}

// NowUTC returns the current time in UTC
func (tu *TimeUtils) NowUTC() time.Time {
	return time.Now().UTC()
}

// FormatTime formats a time using the specified layout
func (tu *TimeUtils) FormatTime(t time.Time, layout string) string {
	return t.Format(layout)
}

// ParseTime parses a time string using the specified layout
func (tu *TimeUtils) ParseTime(timeStr, layout string) (time.Time, error) {
	return time.Parse(layout, timeStr)
}

// IsToday checks if a time is today
func (tu *TimeUtils) IsToday(t time.Time) bool {
	now := time.Now()
	return t.Year() == now.Year() && t.YearDay() == now.YearDay()
}

// IsYesterday checks if a time is yesterday
func (tu *TimeUtils) IsYesterday(t time.Time) bool {
	yesterday := time.Now().AddDate(0, 0, -1)
	return t.Year() == yesterday.Year() && t.YearDay() == yesterday.YearDay()
}

// IsThisWeek checks if a time is this week
func (tu *TimeUtils) IsThisWeek(t time.Time) bool {
	now := time.Now()
	year, week := now.ISOWeek()
	tYear, tWeek := t.ISOWeek()
	return year == tYear && week == tWeek
}

// IsThisMonth checks if a time is this month
func (tu *TimeUtils) IsThisMonth(t time.Time) bool {
	now := time.Now()
	return t.Year() == now.Year() && t.Month() == now.Month()
}

// IsThisYear checks if a time is this year
func (tu *TimeUtils) IsThisYear(t time.Time) bool {
	now := time.Now()
	return t.Year() == now.Year()
}

// AddDays adds days to a time
func (tu *TimeUtils) AddDays(t time.Time, days int) time.Time {
	return t.AddDate(0, 0, days)
}

// AddMonths adds months to a time
func (tu *TimeUtils) AddMonths(t time.Time, months int) time.Time {
	return t.AddDate(0, months, 0)
}

// AddYears adds years to a time
func (tu *TimeUtils) AddYears(t time.Time, years int) time.Time {
	return t.AddDate(years, 0, 0)
}

// GetStartOfDay returns the start of the day for a given time
func (tu *TimeUtils) GetStartOfDay(t time.Time) time.Time {
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, t.Location())
}

// GetEndOfDay returns the end of the day for a given time
func (tu *TimeUtils) GetEndOfDay(t time.Time) time.Time {
	return time.Date(t.Year(), t.Month(), t.Day(), 23, 59, 59, 999999999, t.Location())
}

// GetStartOfWeek returns the start of the week for a given time
func (tu *TimeUtils) GetStartOfWeek(t time.Time) time.Time {
	weekday := int(t.Weekday())
	if weekday == 0 {
		weekday = 7 // Sunday is 0, but we want it to be 7
	}
	return tu.GetStartOfDay(t.AddDate(0, 0, -weekday+1))
}

// GetEndOfWeek returns the end of the week for a given time
func (tu *TimeUtils) GetEndOfWeek(t time.Time) time.Time {
	weekday := int(t.Weekday())
	if weekday == 0 {
		weekday = 7 // Sunday is 0, but we want it to be 7
	}
	return tu.GetEndOfDay(t.AddDate(0, 0, 7-weekday))
}

// GetStartOfMonth returns the start of the month for a given time
func (tu *TimeUtils) GetStartOfMonth(t time.Time) time.Time {
	return time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, t.Location())
}

// GetEndOfMonth returns the end of the month for a given time
func (tu *TimeUtils) GetEndOfMonth(t time.Time) time.Time {
	return tu.GetStartOfMonth(t.AddDate(0, 1, 0)).Add(-time.Nanosecond)
}

// GetStartOfYear returns the start of the year for a given time
func (tu *TimeUtils) GetStartOfYear(t time.Time) time.Time {
	return time.Date(t.Year(), 1, 1, 0, 0, 0, 0, t.Location())
}

// GetEndOfYear returns the end of the year for a given time
func (tu *TimeUtils) GetEndOfYear(t time.Time) time.Time {
	return time.Date(t.Year(), 12, 31, 23, 59, 59, 999999999, t.Location())
}

// UUIDUtils provides UUID utility functions
type UUIDUtils struct{}

// NewUUIDUtils creates a new UUIDUtils instance
func NewUUIDUtils() *UUIDUtils {
	return &UUIDUtils{}
}

// Generate generates a new UUID
func (uu *UUIDUtils) Generate() uuid.UUID {
	return uuid.New()
}

// GenerateString generates a new UUID as a string
func (uu *UUIDUtils) GenerateString() string {
	return uuid.New().String()
}

// Parse parses a UUID string
func (uu *UUIDUtils) Parse(uuidStr string) (uuid.UUID, error) {
	return uuid.Parse(uuidStr)
}

// IsValid checks if a string is a valid UUID
func (uu *UUIDUtils) IsValid(uuidStr string) bool {
	_, err := uuid.Parse(uuidStr)
	return err == nil
}

// LogUtils provides logging utility functions
type LogUtils struct {
	logger *logrus.Logger
}

// NewLogUtils creates a new LogUtils instance
func NewLogUtils(logger *logrus.Logger) *LogUtils {
	return &LogUtils{logger: logger}
}

// LogError logs an error with context
func (lu *LogUtils) LogError(err error, message string, fields logrus.Fields) {
	lu.logger.WithError(err).WithFields(fields).Error(message)
}

// LogInfo logs an info message with context
func (lu *LogUtils) LogInfo(message string, fields logrus.Fields) {
	lu.logger.WithFields(fields).Info(message)
}

// LogWarning logs a warning message with context
func (lu *LogUtils) LogWarning(message string, fields logrus.Fields) {
	lu.logger.WithFields(fields).Warn(message)
}

// LogDebug logs a debug message with context
func (lu *LogUtils) LogDebug(message string, fields logrus.Fields) {
	lu.logger.WithFields(fields).Debug(message)
}

// LogWithDuration logs a message with duration
func (lu *LogUtils) LogWithDuration(message string, duration time.Duration, fields logrus.Fields) {
	fields["duration"] = duration
	lu.logger.WithFields(fields).Info(message)
}

// LogWithUser logs a message with user context
func (lu *LogUtils) LogWithUser(message string, userID, tenantID string, fields logrus.Fields) {
	fields["user_id"] = userID
	fields["tenant_id"] = tenantID
	lu.logger.WithFields(fields).Info(message)
}

// LogWithRequest logs a message with request context
func (lu *LogUtils) LogWithRequest(message string, requestID, method, path string, fields logrus.Fields) {
	fields["request_id"] = requestID
	fields["method"] = method
	fields["path"] = path
	lu.logger.WithFields(fields).Info(message)
}

// FileUtils provides file utility functions
type FileUtils struct{}

// NewFileUtils creates a new FileUtils instance
func NewFileUtils() *FileUtils {
	return &FileUtils{}
}

// GetFileExtension gets the file extension from a filename
func (fu *FileUtils) GetFileExtension(filename string) string {
	parts := strings.Split(filename, ".")
	if len(parts) < 2 {
		return ""
	}
	return strings.ToLower(parts[len(parts)-1])
}

// GetFileNameWithoutExtension gets the filename without extension
func (fu *FileUtils) GetFileNameWithoutExtension(filename string) string {
	parts := strings.Split(filename, ".")
	if len(parts) < 2 {
		return filename
	}
	return strings.Join(parts[:len(parts)-1], ".")
}

// IsValidImageExtension checks if a file extension is a valid image extension
func (fu *FileUtils) IsValidImageExtension(extension string) bool {
	validExtensions := []string{"jpg", "jpeg", "png", "gif", "bmp", "webp", "svg"}
	extension = strings.ToLower(extension)
	for _, validExt := range validExtensions {
		if extension == validExt {
			return true
		}
	}
	return false
}

// IsValidDocumentExtension checks if a file extension is a valid document extension
func (fu *FileUtils) IsValidDocumentExtension(extension string) bool {
	validExtensions := []string{"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf"}
	extension = strings.ToLower(extension)
	for _, validExt := range validExtensions {
		if extension == validExt {
			return true
		}
	}
	return false
}

// FormatFileSize formats a file size in bytes to human readable format
func (fu *FileUtils) FormatFileSize(size int64) string {
	const unit = 1024
	if size < unit {
		return fmt.Sprintf("%d B", size)
	}
	div, exp := int64(unit), 0
	for n := size / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(size)/float64(div), "KMGTPE"[exp])
}

// Global utility instances for backward compatibility
var (
	StringUtilsInstance     = NewStringUtils()
	ValidationUtilsInstance = NewValidationUtils()
	CryptoUtilsInstance     = NewCryptoUtils()
	TimeUtilsInstance       = NewTimeUtils()
	UUIDUtilsInstance       = NewUUIDUtils()
	FileUtilsInstance       = NewFileUtils()
	RetryUtilsInstance      = NewRetryUtils()
	ContextUtilsInstance    = NewContextUtils()
	EnvUtilsInstance        = NewEnvUtils()
	DataUtilsInstance       = NewDataUtils()
	SliceUtilsInstance      = NewSliceUtils()
)

// Convenience functions
func IsEmpty(s string) bool {
	return StringUtilsInstance.IsEmpty(s)
}

func IsNotEmpty(s string) bool {
	return StringUtilsInstance.IsNotEmpty(s)
}

func IsValidEmail(email string) bool {
	return ValidationUtilsInstance.IsValidEmail(email)
}

func IsValidPhone(phone string) bool {
	return ValidationUtilsInstance.IsValidPhone(phone)
}

func IsValidURL(url string) bool {
	return ValidationUtilsInstance.IsValidURL(url)
}

func IsValidUUID(uuidStr string) bool {
	return ValidationUtilsInstance.IsValidUUID(uuidStr)
}

func IsValidPassword(password string) bool {
	return ValidationUtilsInstance.IsValidPassword(password)
}

func HashPassword(password string) (string, error) {
	return CryptoUtilsInstance.HashPassword(password)
}

func VerifyPassword(password, hash string) bool {
	return CryptoUtilsInstance.VerifyPassword(password, hash)
}

func GenerateHash(input string) string {
	return CryptoUtilsInstance.GenerateHash(input)
}

func Now() time.Time {
	return TimeUtilsInstance.Now()
}

func NowUTC() time.Time {
	return TimeUtilsInstance.NowUTC()
}

func GenerateUUID() uuid.UUID {
	return UUIDUtilsInstance.Generate()
}

func GenerateUUIDString() string {
	return UUIDUtilsInstance.GenerateString()
}

// --------------------
// Retry utilities
// --------------------

// RetryUtils provides retry with backoff helpers
type RetryUtils struct{}

// NewRetryUtils creates a new RetryUtils instance
func NewRetryUtils() *RetryUtils { return &RetryUtils{} }

// Retry executes fn up to attempts with exponential backoff and jitter, honoring ctx cancellation
func (ru *RetryUtils) Retry(ctx context.Context, attempts int, initialBackoff, maxBackoff time.Duration, fn func() error) error {
	if attempts <= 0 {
		return fmt.Errorf("attempts must be > 0")
	}
	if initialBackoff <= 0 {
		initialBackoff = 50 * time.Millisecond
	}
	if maxBackoff <= 0 {
		maxBackoff = 5 * time.Second
	}
	var lastErr error
	backoff := initialBackoff
	for i := 0; i < attempts; i++ {
		if err := fn(); err == nil {
			return nil
		} else {
			lastErr = err
		}
		if i == attempts-1 {
			break
		}
		// jitter up to 50% of current backoff
		jitter := ru.jitterDuration(backoff / 2)
		delay := backoff + jitter
		if delay > maxBackoff {
			delay = maxBackoff
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
		// Exponential increase with cap
		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
	return lastErr
}

// RetryWithResult executes fn with retries and returns its result
func RetryWithResult[T any](ctx context.Context, attempts int, initialBackoff, maxBackoff time.Duration, fn func() (T, error)) (T, error) {
	var zero T
	if attempts <= 0 {
		return zero, fmt.Errorf("attempts must be > 0")
	}
	if initialBackoff <= 0 {
		initialBackoff = 50 * time.Millisecond
	}
	if maxBackoff <= 0 {
		maxBackoff = 5 * time.Second
	}
	var lastErr error
	backoff := initialBackoff
	for i := 0; i < attempts; i++ {
		if res, err := fn(); err == nil {
			return res, nil
		} else {
			lastErr = err
		}
		if i == attempts-1 {
			break
		}
		jitter := RetryUtilsInstance.jitterDuration(backoff / 2)
		delay := backoff + jitter
		if delay > maxBackoff {
			delay = maxBackoff
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return zero, ctx.Err()
		case <-timer.C:
		}
		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
	return zero, lastErr
}

func (ru *RetryUtils) jitterDuration(max time.Duration) time.Duration {
	if max <= 0 {
		return 0
	}
	// Use crypto/rand to avoid global state
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return 0
	}
	return time.Duration(n.Int64())
}

// Convenience wrappers
func Retry(ctx context.Context, attempts int, initialBackoff, maxBackoff time.Duration, fn func() error) error {
	return RetryUtilsInstance.Retry(ctx, attempts, initialBackoff, maxBackoff, fn)
}

// (function implemented above)

// --------------------
// Context utilities
// --------------------

// ContextUtils provides helpers for common IDs in context
type ContextUtils struct{}

// NewContextUtils creates a new ContextUtils instance
func NewContextUtils() *ContextUtils { return &ContextUtils{} }

type ctxKey string

const (
	ctxKeyRequestID     ctxKey = "request_id"
	ctxKeyCorrelationID ctxKey = "correlation_id"
)

// WithRequestID attaches a request ID to context
func (cu *ContextUtils) WithRequestID(ctx context.Context, requestID string) context.Context {
	if requestID == "" {
		requestID = uuid.NewString()
	}
	return context.WithValue(ctx, ctxKeyRequestID, requestID)
}

// RequestID gets a request ID from context, empty if missing
func (cu *ContextUtils) RequestID(ctx context.Context) string {
	if v := ctx.Value(ctxKeyRequestID); v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// EnsureRequestID returns a context with request ID set and the ID value
func (cu *ContextUtils) EnsureRequestID(ctx context.Context) (context.Context, string) {
	if id := cu.RequestID(ctx); id != "" {
		return ctx, id
	}
	id := uuid.NewString()
	return context.WithValue(ctx, ctxKeyRequestID, id), id
}

// WithCorrelationID attaches a correlation ID to context
func (cu *ContextUtils) WithCorrelationID(ctx context.Context, correlationID string) context.Context {
	if correlationID == "" {
		correlationID = uuid.NewString()
	}
	return context.WithValue(ctx, ctxKeyCorrelationID, correlationID)
}

// CorrelationID gets a correlation ID from context
func (cu *ContextUtils) CorrelationID(ctx context.Context) string {
	if v := ctx.Value(ctxKeyCorrelationID); v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// EnsureCorrelationID returns a context with correlation ID set and the ID value
func (cu *ContextUtils) EnsureCorrelationID(ctx context.Context) (context.Context, string) {
	if id := cu.CorrelationID(ctx); id != "" {
		return ctx, id
	}
	id := uuid.NewString()
	return context.WithValue(ctx, ctxKeyCorrelationID, id), id
}

// Convenience wrappers
func WithRequestID(ctx context.Context, requestID string) context.Context {
	return ContextUtilsInstance.WithRequestID(ctx, requestID)
}

func RequestID(ctx context.Context) string { return ContextUtilsInstance.RequestID(ctx) }

func EnsureRequestID(ctx context.Context) (context.Context, string) {
	return ContextUtilsInstance.EnsureRequestID(ctx)
}

func WithCorrelationID(ctx context.Context, correlationID string) context.Context {
	return ContextUtilsInstance.WithCorrelationID(ctx, correlationID)
}

func CorrelationID(ctx context.Context) string { return ContextUtilsInstance.CorrelationID(ctx) }

func EnsureCorrelationID(ctx context.Context) (context.Context, string) {
	return ContextUtilsInstance.EnsureCorrelationID(ctx)
}

// --------------------
// Environment utilities
// --------------------

// EnvUtils provides environment variable helpers
type EnvUtils struct{}

// NewEnvUtils creates a new EnvUtils instance
func NewEnvUtils() *EnvUtils { return &EnvUtils{} }

func (eu *EnvUtils) GetString(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return def
}

func (eu *EnvUtils) GetInt(key string, def int) int {
	if v, ok := os.LookupEnv(key); ok {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
			return n
		}
	}
	return def
}

func (eu *EnvUtils) GetBool(key string, def bool) bool {
	if v, ok := os.LookupEnv(key); ok {
		if b, err := strconv.ParseBool(strings.TrimSpace(v)); err == nil {
			return b
		}
	}
	return def
}

func (eu *EnvUtils) GetDuration(key string, def time.Duration) time.Duration {
	if v, ok := os.LookupEnv(key); ok {
		if d, err := time.ParseDuration(strings.TrimSpace(v)); err == nil {
			return d
		}
	}
	return def
}

// Convenience wrappers
func GetEnvString(key, def string) string  { return EnvUtilsInstance.GetString(key, def) }
func GetEnvInt(key string, def int) int    { return EnvUtilsInstance.GetInt(key, def) }
func GetEnvBool(key string, def bool) bool { return EnvUtilsInstance.GetBool(key, def) }
func GetEnvDuration(key string, def time.Duration) time.Duration {
	return EnvUtilsInstance.GetDuration(key, def)
}

// --------------------
// Data utilities (JSON/Base64/Gzip)
// --------------------

// DataUtils provides encoding/decoding helpers
type DataUtils struct{}

// NewDataUtils creates a new DataUtils instance
func NewDataUtils() *DataUtils { return &DataUtils{} }

func (du *DataUtils) JSONEncode(v any) ([]byte, error) {
	return json.Marshal(v)
}

func (du *DataUtils) JSONDecode(data []byte, v any) error {
	return json.Unmarshal(data, v)
}

func (du *DataUtils) JSONPretty(v any) (string, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func (du *DataUtils) Base64URLEncode(data []byte) string {
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(data)
}

func (du *DataUtils) Base64URLDecode(s string) ([]byte, error) {
	return base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(s)
}

func (du *DataUtils) GzipCompress(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	if _, err := gw.Write(data); err != nil {
		gw.Close()
		return nil, err
	}
	if err := gw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (du *DataUtils) GzipDecompress(data []byte) ([]byte, error) {
	gr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer gr.Close()
	var out bytes.Buffer
	if _, err := io.Copy(&out, gr); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// Convenience wrappers
func JSONEncode(v any) ([]byte, error)           { return DataUtilsInstance.JSONEncode(v) }
func JSONDecode(data []byte, v any) error        { return DataUtilsInstance.JSONDecode(data, v) }
func JSONPretty(v any) (string, error)           { return DataUtilsInstance.JSONPretty(v) }
func Base64URLEncode(data []byte) string         { return DataUtilsInstance.Base64URLEncode(data) }
func Base64URLDecode(s string) ([]byte, error)   { return DataUtilsInstance.Base64URLDecode(s) }
func GzipCompress(data []byte) ([]byte, error)   { return DataUtilsInstance.GzipCompress(data) }
func GzipDecompress(data []byte) ([]byte, error) { return DataUtilsInstance.GzipDecompress(data) }

// --------------------
// Crypto extensions
// --------------------

// HMACSHA256 returns HMAC-SHA256 bytes of message with secret key
func (cu *CryptoUtils) HMACSHA256(message, secret []byte) []byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write(message)
	return mac.Sum(nil)
}

// HMACSHA256Hex returns lowercase hex HMAC of message with secret string
func (cu *CryptoUtils) HMACSHA256Hex(message, secret string) string {
	sum := cu.HMACSHA256([]byte(message), []byte(secret))
	return hex.EncodeToString(sum)
}

// ConstantTimeCompare compares two byte slices in constant time
func (cu *CryptoUtils) ConstantTimeCompare(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare(a, b) == 1
}

// RandomHex returns hex string of n random bytes
func (cu *CryptoUtils) RandomHex(n int) (string, error) {
	b, err := cu.GenerateRandomBytes(n)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// Convenience wrappers
func HMACSHA256(message, secret []byte) []byte {
	return CryptoUtilsInstance.HMACSHA256(message, secret)
}
func HMACSHA256Hex(message, secret string) string {
	return CryptoUtilsInstance.HMACSHA256Hex(message, secret)
}
func ConstantTimeCompare(a, b []byte) bool { return CryptoUtilsInstance.ConstantTimeCompare(a, b) }
func RandomHex(n int) (string, error)      { return CryptoUtilsInstance.RandomHex(n) }

// --------------------
// Slice utilities
// --------------------

// SliceUtils provides slice helpers
type SliceUtils struct{}

// NewSliceUtils creates a new SliceUtils instance
func NewSliceUtils() *SliceUtils { return &SliceUtils{} }

func (su2 *SliceUtils) ContainsString(items []string, target string) bool {
	for _, v := range items {
		if v == target {
			return true
		}
	}
	return false
}

func (su2 *SliceUtils) UniqueStrings(items []string) []string {
	seen := make(map[string]struct{}, len(items))
	out := make([]string, 0, len(items))
	for _, v := range items {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

// Convenience wrappers
func ContainsString(items []string, target string) bool {
	return SliceUtilsInstance.ContainsString(items, target)
}
func UniqueStrings(items []string) []string { return SliceUtilsInstance.UniqueStrings(items) }
