package main

import (
	"strconv"
	"strings"
	"sync"
	"unicode"

	"github.com/pquerna/otp/totp"
	"golang.org/x/time/rate"
)

// Rate limit for TOTP validation with individual token buckets per username
type TotpRateLimit struct {
	rate   rate.Limit
	burst  int
	limits map[string]*rate.Limiter
	mu     sync.Mutex
}

func NewTotpRateLimit(r rate.Limit, b int) *TotpRateLimit {
	return &TotpRateLimit{
		rate:  r,
		burst: b,
	}
}

// Check whether TOTP validation is allowed for provided username
func (tr *TotpRateLimit) Allow(name string) bool {
	limit, exists := tr.limits[name]
	if !exists {
		tr.mu.Lock()
		defer tr.mu.Unlock()
		limit = rate.NewLimiter(tr.rate, tr.burst)
		tr.limits[name] = limit
	}
	return limit.Allow()
}

// Rate limited validator for TOTP codes
type TotpValidator struct {
	secret map[string]string
	limit  *TotpRateLimit
}

// Create TotpValidator with default rate limiter settings
func NewTotpValidator(secrets map[string]string) *TotpValidator {
	return &TotpValidator{
		secret: secrets,
		limit:  NewTotpRateLimit(3/30.0, 3),
	}
}

// Check individual TOTP code against known secrets
//
// Return false both when TOTP code is not valid and in case of any errors
func (tv *TotpValidator) Check(username string, input string) bool {
	secret, exists := tv.secret[username]
	if !exists {
		return false
	}
	if !tv.limit.Allow(username) {
		return false
	}
	code, err := parseTotp(input)
	if err != nil {
		return false
	}
	return totp.Validate(code, secret)
}

// Drop any whitespace from input and ensure it contains a valid integer
func parseTotp(raw string) (string, error) {
	var builder strings.Builder
	builder.Grow(len(raw))
	for _, char := range raw {
		if !unicode.IsSpace(char) {
			builder.WriteRune(char)
		}
	}
	out := builder.String()
	_, err := strconv.Atoi(out)
	return out, err
}
