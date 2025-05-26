package validation

import (
	"errors"
	"net/mail"
	"regexp"
	"strings"
	"unicode"

	"github.com/o4f6bgpac3/template/cfg"
)

var (
	ErrInvalidEmail           = errors.New("invalid email format")
	ErrPasswordTooShort       = errors.New("password too short")
	ErrPasswordMissingUpper   = errors.New("password must contain uppercase letter")
	ErrPasswordMissingLower   = errors.New("password must contain lowercase letter")
	ErrPasswordMissingNumber  = errors.New("password must contain number")
	ErrPasswordMissingSpecial = errors.New("password must contain special character")
	ErrUsernameTooShort       = errors.New("username too short")
	ErrUsernameTooLong        = errors.New("username too long")
	ErrUsernameInvalidChars   = errors.New("username contains invalid characters")
)

var (
	usernameRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
	specialChars  = "!@#$%^&*()_+-=[]{}|;:,.<>?"
)

func ValidateEmail(email string) error {
	email = strings.TrimSpace(email)
	if email == "" {
		return ErrInvalidEmail
	}

	_, err := mail.ParseAddress(email)
	if err != nil {
		return ErrInvalidEmail
	}

	return nil
}

func ValidatePassword(password string) error {
	config := cfg.Config.Auth

	if len(password) < config.PasswordMinLength {
		return ErrPasswordTooShort
	}

	var (
		hasUpper   = false
		hasLower   = false
		hasNumber  = false
		hasSpecial = false
	)

	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsNumber(char):
			hasNumber = true
		case strings.ContainsRune(specialChars, char):
			hasSpecial = true
		}
	}

	if config.PasswordRequireUpper && !hasUpper {
		return ErrPasswordMissingUpper
	}

	if config.PasswordRequireLower && !hasLower {
		return ErrPasswordMissingLower
	}

	if config.PasswordRequireNumber && !hasNumber {
		return ErrPasswordMissingNumber
	}

	if config.PasswordRequireSpecial && !hasSpecial {
		return ErrPasswordMissingSpecial
	}

	return nil
}

func ValidateUsername(username string) error {
	username = strings.TrimSpace(username)

	if len(username) < 3 {
		return ErrUsernameTooShort
	}

	if len(username) > 30 {
		return ErrUsernameTooLong
	}

	if !usernameRegex.MatchString(username) {
		return ErrUsernameInvalidChars
	}

	return nil
}

func SanitizeInput(input string) string {
	return strings.TrimSpace(input)
}

type ValidationErrors struct {
	Errors map[string]string `json:"errors"`
}

func (v *ValidationErrors) Add(field, message string) {
	if v.Errors == nil {
		v.Errors = make(map[string]string)
	}
	v.Errors[field] = message
}

func (v *ValidationErrors) HasErrors() bool {
	return len(v.Errors) > 0
}

func (v *ValidationErrors) Error() string {
	if len(v.Errors) == 0 {
		return ""
	}

	var messages []string
	for field, msg := range v.Errors {
		messages = append(messages, field+": "+msg)
	}

	return strings.Join(messages, ", ")
}
