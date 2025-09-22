package errors

import (
	stdErrors "errors"
	"fmt"
)

// Code represents a standardized error code across libraries
type Code string

const (
	CodeInternal     Code = "INTERNAL"
	CodeInvalidInput Code = "INVALID_INPUT"
	CodeNotFound     Code = "NOT_FOUND"
	CodeConflict     Code = "CONFLICT"
	CodeUnauthorized Code = "UNAUTHORIZED"
	CodeForbidden    Code = "FORBIDDEN"
	CodeTimeout      Code = "TIMEOUT"
	CodeUnavailable  Code = "UNAVAILABLE"
	CodeDependency   Code = "DEPENDENCY_ERROR"
	CodeValidation   Code = "VALIDATION_ERROR"
)

// AppError is the unified error type used across the repository
type AppError struct {
	Code    Code                   `json:"code"`
	Message string                 `json:"message"`
	Cause   error                  `json:"-"`
	Fields  map[string]interface{} `json:"fields,omitempty"`
}

func (e *AppError) Error() string {
	if e == nil {
		return ""
	}
	if e.Cause != nil {
		return fmt.Sprintf("%s: %s: %v", e.Code, e.Message, e.Cause)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

func (e *AppError) Unwrap() error { return e.Cause }

// New creates a new AppError
func New(code Code, message string) *AppError {
	return &AppError{Code: code, Message: message, Fields: map[string]interface{}{}}
}

// Wrap wraps an error into AppError with a code and message
func Wrap(err error, code Code, message string) *AppError {
	if err == nil {
		return nil
	}
	if ae, ok := err.(*AppError); ok {
		// preserve the original code if it already exists
		if message == "" {
			message = ae.Message
		}
		return &AppError{Code: ae.Code, Message: message, Cause: ae, Fields: ae.Fields}
	}
	return &AppError{Code: code, Message: message, Cause: err, Fields: map[string]interface{}{}}
}

// IsCode checks if error or its chain has the given code
func IsCode(err error, code Code) bool {
	var ae *AppError
	if stdErrors.As(err, &ae) {
		return ae.Code == code
	}
	return false
}

// AddField adds a field to the error metadata
func (e *AppError) AddField(key string, value interface{}) *AppError {
	if e.Fields == nil {
		e.Fields = make(map[string]interface{})
	}
	e.Fields[key] = value
	return e
}

// Helpers for common errors
func Internal(message string, cause error) *AppError { return Wrap(cause, CodeInternal, message) }
func InvalidInput(message string, cause error) *AppError {
	return Wrap(cause, CodeInvalidInput, message)
}
func NotFound(message string, cause error) *AppError { return Wrap(cause, CodeNotFound, message) }
func Conflict(message string, cause error) *AppError { return Wrap(cause, CodeConflict, message) }
func Unauthorized(message string, cause error) *AppError {
	return Wrap(cause, CodeUnauthorized, message)
}
func Forbidden(message string, cause error) *AppError   { return Wrap(cause, CodeForbidden, message) }
func Timeout(message string, cause error) *AppError     { return Wrap(cause, CodeTimeout, message) }
func Unavailable(message string, cause error) *AppError { return Wrap(cause, CodeUnavailable, message) }
func Dependency(message string, cause error) *AppError  { return Wrap(cause, CodeDependency, message) }
func Validation(message string, cause error) *AppError  { return Wrap(cause, CodeValidation, message) }
