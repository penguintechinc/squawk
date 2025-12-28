package license

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/penguintechinc/squawk/squawk-client-go/pkg/config"
)

// ValidationResponse represents the response from license validation
type ValidationResponse struct {
	Valid         bool      `json:"valid"`
	Message       string    `json:"message"`
	ExpiresAt     *string   `json:"expires_at,omitempty"`
	TokensUsed    *int      `json:"tokens_used,omitempty"`
	MaxTokens     *int      `json:"max_tokens,omitempty"`
	UserEmail     *string   `json:"user_email,omitempty"`
	LicenseExpiry *string   `json:"license_expires,omitempty"`
}

// Validator handles license validation with caching
type Validator struct {
	config         *config.LicenseConfig
	client         *http.Client
	cache          map[string]*cacheEntry
	cacheMutex     sync.RWMutex
	lastValidate   time.Time
	validatedToday string // Date string YYYY-MM-DD
}

type cacheEntry struct {
	valid     bool
	expiresAt time.Time
	message   string
	validated time.Time
}

// NewValidator creates a new license validator
func NewValidator(cfg *config.LicenseConfig) *Validator {
	return &Validator{
		config: cfg,
		client: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					MinVersion: tls.VersionTLS12,
				},
			},
		},
		cache: make(map[string]*cacheEntry),
	}
}

// ValidateLicense validates a license key with the license server
func (v *Validator) ValidateLicense(ctx context.Context) (*ValidationResponse, error) {
	if v.config == nil {
		return &ValidationResponse{
			Valid:   false,
			Message: "License configuration not provided",
		}, fmt.Errorf("license configuration is required")
	}

	today := time.Now().Format("2006-01-02")
	
	// Check if we've already validated today
	v.cacheMutex.RLock()
	if v.validatedToday == today {
		if entry, exists := v.cache["license_validation"]; exists {
			v.cacheMutex.RUnlock()
			return &ValidationResponse{
				Valid:   entry.valid,
				Message: entry.message,
			}, nil
		}
	}
	v.cacheMutex.RUnlock()

	// Check cache first - use cache if less than cache time minutes old
	if !v.config.ValidateOnline {
		v.cacheMutex.RLock()
		if entry, exists := v.cache["license_validation"]; exists {
			if time.Since(entry.validated) < time.Duration(v.config.CacheTime)*time.Minute {
				v.cacheMutex.RUnlock()
				return &ValidationResponse{
					Valid:   entry.valid,
					Message: entry.message,
				}, nil
			}
		}
		v.cacheMutex.RUnlock()
	}

	// Prefer user token over license key for validation
	if v.config.UserToken != "" {
		return v.validateUserToken(ctx)
	}

	if v.config.LicenseKey != "" {
		return v.validateLicenseKey(ctx)
	}

	return &ValidationResponse{
		Valid:   false,
		Message: "No license key or user token provided",
	}, fmt.Errorf("license key or user token is required")
}

// validateLicenseKey validates using license key
func (v *Validator) validateLicenseKey(ctx context.Context) (*ValidationResponse, error) {
	payload := map[string]string{
		"license_key": v.config.LicenseKey,
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", v.config.ServerURL+"/api/validate", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Squawk-DNS-Client/2.0")

	resp, err := v.client.Do(req)
	if err != nil {
		return &ValidationResponse{
			Valid:   false,
			Message: fmt.Sprintf("License server unreachable: %v", err),
		}, err
	}
	defer func() { _ = resp.Body.Close() }()

	var validationResp ValidationResponse
	if err := json.NewDecoder(resp.Body).Decode(&validationResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	v.cacheValidation("license_validation", validationResp.Valid, validationResp.Message)
	v.lastValidate = time.Now()
	
	// Mark as validated today
	v.cacheMutex.Lock()
	v.validatedToday = time.Now().Format("2006-01-02")
	v.cacheMutex.Unlock()

	return &validationResp, nil
}

// validateUserToken validates using user token
func (v *Validator) validateUserToken(ctx context.Context) (*ValidationResponse, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", v.config.ServerURL+"/api/validate_token", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+v.config.UserToken)
	req.Header.Set("User-Agent", "Squawk-DNS-Client/2.0")

	resp, err := v.client.Do(req)
	if err != nil {
		return &ValidationResponse{
			Valid:   false,
			Message: fmt.Sprintf("License server unreachable: %v", err),
		}, err
	}
	defer func() { _ = resp.Body.Close() }()

	var validationResp ValidationResponse
	if err := json.NewDecoder(resp.Body).Decode(&validationResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	v.cacheValidation("token_validation", validationResp.Valid, validationResp.Message)
	v.lastValidate = time.Now()
	
	// Mark as validated today
	v.cacheMutex.Lock()
	v.validatedToday = time.Now().Format("2006-01-02")
	v.cacheMutex.Unlock()

	return &validationResp, nil
}

// cacheValidation caches validation results
func (v *Validator) cacheValidation(key string, valid bool, message string) {
	v.cacheMutex.Lock()
	defer v.cacheMutex.Unlock()

	v.cache[key] = &cacheEntry{
		valid:     valid,
		expiresAt: time.Now().Add(time.Duration(v.config.CacheTime) * time.Minute),
		message:   message,
		validated: time.Now(),
	}
}

// IsValid returns true if the current license/token is valid
func (v *Validator) IsValid(ctx context.Context) (bool, error) {
	today := time.Now().Format("2006-01-02")
	
	// Check if we've already validated today - use that result
	v.cacheMutex.RLock()
	if v.validatedToday == today {
		for _, entry := range v.cache {
			if entry.valid {
				v.cacheMutex.RUnlock()
				return true, nil
			}
		}
	}
	v.cacheMutex.RUnlock()

	response, err := v.ValidateLicense(ctx)
	if err != nil {
		// In case of network errors, check if we have a cached valid response from today or recent
		v.cacheMutex.RLock()
		for _, entry := range v.cache {
			// Allow using cache if validated within last 24 hours or still within expiry
			if entry.valid && (time.Since(entry.validated) < 24*time.Hour || time.Now().Before(entry.expiresAt)) {
				v.cacheMutex.RUnlock()
				return true, nil
			}
		}
		v.cacheMutex.RUnlock()
		return false, err
	}

	return response.Valid, nil
}

// GetStatus returns detailed license status
func (v *Validator) GetStatus(ctx context.Context) (*ValidationResponse, error) {
	return v.ValidateLicense(ctx)
}

// ClearCache clears the validation cache
func (v *Validator) ClearCache() {
	v.cacheMutex.Lock()
	defer v.cacheMutex.Unlock()
	v.cache = make(map[string]*cacheEntry)
}

// GetLicenseInfo returns formatted license information
func (v *Validator) GetLicenseInfo(ctx context.Context) (string, error) {
	status, err := v.GetStatus(ctx)
	if err != nil {
		return "", err
	}

	info := fmt.Sprintf("License Status: %s\n", func() string {
		if status.Valid {
			return "✓ Valid"
		}
		return "✗ Invalid"
	}())

	if status.Message != "" {
		info += fmt.Sprintf("Message: %s\n", status.Message)
	}

	if status.ExpiresAt != nil {
		info += fmt.Sprintf("License Expires: %s\n", *status.ExpiresAt)
	}

	if status.UserEmail != nil {
		info += fmt.Sprintf("User: %s\n", *status.UserEmail)
	}

	if status.TokensUsed != nil && status.MaxTokens != nil {
		info += fmt.Sprintf("Tokens: %d/%d used\n", *status.TokensUsed, *status.MaxTokens)
	}

	return info, nil
}