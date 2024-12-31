package errors

import "fmt"

// Error represents a custom error type
type Error struct {
	Code    string
	Message string
	Err     error
}

func (e *Error) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %s: %v", e.Code, e.Message, e.Err)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// Define error codes
const (
	ErrCodeConfigInvalid      = "CONFIG_INVALID"
	ErrCodeAuthFailed         = "AUTH_FAILED"
	ErrCodeSecretNotFound     = "SECRET_NOT_FOUND"
	ErrCodeSecretUpdateFailed = "SECRET_UPDATE_FAILED"
	ErrCodeNetworkError       = "NETWORK_ERROR"
)

// NewError creates a new error
func NewError(code string, message string, err error) *Error {
	return &Error{
		Code:    code,
		Message: message,
		Err:     err,
	}
}
