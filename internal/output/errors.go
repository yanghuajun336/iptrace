package output

import (
	"errors"
	"fmt"
	"io"
)

const (
	ExitCodeOK          = 0
	ExitCodeInputError  = 1
	ExitCodeEnvError    = 2
	ExitCodeInternalErr = 3
)

type AppError struct {
	Code    int
	Message string
	Hint    string
}

func (e *AppError) Error() string {
	if e == nil {
		return ""
	}
	return e.Message
}

func NewInputError(message, hint string) *AppError {
	return &AppError{Code: ExitCodeInputError, Message: message, Hint: hint}
}

func NewEnvError(message, hint string) *AppError {
	return &AppError{Code: ExitCodeEnvError, Message: message, Hint: hint}
}

func NewInternalError(message, hint string) *AppError {
	return &AppError{Code: ExitCodeInternalErr, Message: message, Hint: hint}
}

func WriteError(w io.Writer, err error) int {
	if err == nil {
		return ExitCodeOK
	}

	var appErr *AppError
	if errors.As(err, &appErr) {
		fmt.Fprintf(w, "error: %s\n", appErr.Message)
		if appErr.Hint != "" {
			fmt.Fprintf(w, "hint: %s\n", appErr.Hint)
		}
		return appErr.Code
	}

	fmt.Fprintf(w, "error: %v\n", err)
	return ExitCodeInternalErr
}
