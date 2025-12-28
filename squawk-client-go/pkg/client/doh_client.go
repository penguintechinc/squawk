package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

var (
	// DNS label validation regex (RFC 1035)
	// - Labels must start with a letter or digit
	// - Can contain letters, digits, and hyphens
	// - Cannot end with a hyphen
	// - Max 63 characters per label
	dnsLabelRegex = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$`)
	
	// Valid DNS record types
	validRecordTypes = map[string]bool{
		"A":     true,
		"AAAA":  true,
		"CNAME": true,
		"MX":    true,
		"TXT":   true,
		"NS":    true,
		"SOA":   true,
		"PTR":   true,
		"SRV":   true,
		"CAA":   true,
		"DNSKEY": true,
		"DS":    true,
		"NAPTR": true,
		"SSHFP": true,
		"TLSA":  true,
		"ANY":   true,
	}
)

// validateDNSName validates a DNS domain name according to RFC 1035
func validateDNSName(domain string) error {
	// Check overall length (max 253 characters)
	if len(domain) == 0 {
		return fmt.Errorf("DNS name cannot be empty")
	}
	if len(domain) > 253 {
		return fmt.Errorf("DNS name too long: %d characters (max 253)", len(domain))
	}
	
	// Remove trailing dot if present (valid in DNS but we'll validate without it)
	domain = strings.TrimSuffix(domain, ".")
	
	// Check for invalid characters at the domain level
	if strings.ContainsAny(domain, " !@#$%^&*()+={}[]|\\:;\"'<>,?/`~") {
		return fmt.Errorf("DNS name contains invalid characters")
	}
	
	// Split into labels and validate each
	labels := strings.Split(domain, ".")
	if len(labels) == 0 {
		return fmt.Errorf("DNS name has no labels")
	}
	
	for i, label := range labels {
		// Check label length (max 63 characters)
		if len(label) == 0 {
			return fmt.Errorf("DNS name contains empty label at position %d", i)
		}
		if len(label) > 63 {
			return fmt.Errorf("DNS label '%s' too long: %d characters (max 63)", label, len(label))
		}
		
		// Special case: TLD can be all numeric for reverse DNS (e.g., "1.0.0.127.in-addr.arpa")
		if i == len(labels)-1 && label == "arpa" {
			continue // Skip validation for .arpa TLD
		}
		
		// Check label format
		if !dnsLabelRegex.MatchString(label) {
			// Special case for IDN/punycode domains
			if strings.HasPrefix(label, "xn--") {
				continue // Skip validation for punycode labels
			}
			return fmt.Errorf("invalid DNS label '%s': must start/end with alphanumeric and contain only letters, digits, and hyphens", label)
		}
		
		// Check for consecutive hyphens (sometimes indicates typos)
		if strings.Contains(label, "--") && !strings.HasPrefix(label, "xn--") {
			// Allow -- only in punycode domains
			return fmt.Errorf("invalid DNS label '%s': contains consecutive hyphens", label)
		}
	}
	
	return nil
}

// validateRecordType validates DNS record type
func validateRecordType(recordType string) error {
	recordType = strings.ToUpper(recordType)
	if !validRecordTypes[recordType] {
		validTypes := make([]string, 0, len(validRecordTypes))
		for t := range validRecordTypes {
			validTypes = append(validTypes, t)
		}
		return fmt.Errorf("invalid DNS record type '%s': must be one of %v", recordType, validTypes)
	}
	return nil
}

// DoHClient represents a DNS-over-HTTPS client with mTLS support
type DoHClient struct {
	serverURLs   []string
	authToken    string
	clientCert   string
	clientKey    string
	caCert       string
	verifySSL    bool
	httpClient   *http.Client
	timeout      time.Duration
	maxRetries   int
	retryDelay   time.Duration
	currentIndex int // Track which server we're currently using
}

// Config holds the configuration for the DoH client
type Config struct {
	ServerURL   string   `yaml:"server_url" json:"server_url"`
	ServerURLs  []string `yaml:"server_urls" json:"server_urls"`
	AuthToken   string   `yaml:"auth_token" json:"auth_token"`
	ClientCert  string   `yaml:"client_cert" json:"client_cert"`
	ClientKey   string   `yaml:"client_key" json:"client_key"`
	CaCert      string   `yaml:"ca_cert" json:"ca_cert"`
	VerifySSL   bool     `yaml:"verify_ssl" json:"verify_ssl"`
	MaxRetries  int      `yaml:"max_retries" json:"max_retries"`
	RetryDelay  int      `yaml:"retry_delay" json:"retry_delay"` // seconds
}

// DNSResponse represents a DNS-over-HTTPS JSON response
type DNSResponse struct {
	Status   int         `json:"Status"`
	TC       bool        `json:"TC"`
	RD       bool        `json:"RD"`
	RA       bool        `json:"RA"`
	AD       bool        `json:"AD"`
	CD       bool        `json:"CD"`
	Question []DNSRecord `json:"Question,omitempty"`
	Answer   []DNSRecord `json:"Answer,omitempty"`
	Comment  string      `json:"Comment,omitempty"`
	TTL      int         `json:"TTL,omitempty"`
}

// DNSRecord represents a DNS record in the JSON response
type DNSRecord struct {
	Name string `json:"name"`
	Type int    `json:"type"`
	TTL  int    `json:"TTL,omitempty"`
	Data string `json:"data"`
}

// validateServerURL ensures the server URL uses an IP address to prevent DNS loops
func validateServerURL(serverURL string) error {
	if serverURL == "" {
		return fmt.Errorf("server URL cannot be empty")
	}

	parsedURL, err := url.Parse(serverURL)
	if err != nil {
		return fmt.Errorf("invalid server URL format: %w", err)
	}

	if parsedURL.Scheme != "https" && parsedURL.Scheme != "http" {
		return fmt.Errorf("server URL must use http or https scheme, got: %s", parsedURL.Scheme)
	}

	host := parsedURL.Hostname()
	if host == "" {
		return fmt.Errorf("server URL must include a host")
	}

	// Check if the host is an IP address (IPv4 or IPv6)
	if net.ParseIP(host) == nil {
		// Special case: allow localhost for development
		if strings.ToLower(host) == "localhost" {
			return nil
		}
		
		// Special case: allow well-known public DNS providers to prevent breaking existing configs
		allowedHosts := []string{
			"dns.google",
			"dns.google.com", // Legacy Google DNS domain
			"cloudflare-dns.com",
			"1.1.1.1", // Cloudflare primary
			"1.0.0.1", // Cloudflare secondary
			"dns.quad9.net",
			"dns.opendns.com",
			"doh.opendns.com",
			"dns.nextdns.io",
			"doh.cleanbrowsing.org",
		}
		
		hostLower := strings.ToLower(host)
		for _, allowed := range allowedHosts {
			if hostLower == allowed || strings.HasPrefix(hostLower, allowed + ".") {
				// Don't show warning for public DNS providers
				if !strings.Contains(hostLower, "google") && !strings.Contains(hostLower, "cloudflare") &&
				   !strings.Contains(hostLower, "1.1.1.1") && !strings.Contains(hostLower, "1.0.0.1") {
					fmt.Printf("INFO: Using public DNS provider '%s'\n", host)
				}
				return nil
			}
		}
		
		return fmt.Errorf("server URL must use an IP address (not hostname '%s') to prevent DNS resolution loops. Use the IP address of your DNS server instead", host)
	}

	return nil
}

// NewDoHClient creates a new DNS-over-HTTPS client
func NewDoHClient(config *Config) (*DoHClient, error) {
	if config == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}

	// Build server URLs list (prioritize ServerURLs over ServerURL)
	var serverURLs []string
	if len(config.ServerURLs) > 0 {
		serverURLs = config.ServerURLs
	} else if config.ServerURL != "" {
		serverURLs = []string{config.ServerURL}
	} else {
		return nil, fmt.Errorf("no server URLs provided")
	}

	// Validate and normalize all server URLs
	for i, serverURL := range serverURLs {
		if err := validateServerURL(serverURL); err != nil {
			return nil, fmt.Errorf("invalid server URL at index %d: %w", i, err)
		}
		// Normalize URLs for known public DNS providers
		serverURLs[i] = normalizeServerURL(serverURL)
	}

	// Set defaults
	maxRetries := config.MaxRetries
	if maxRetries <= 0 {
		maxRetries = len(serverURLs) * 2 // Default: try each server twice
	}

	retryDelay := time.Duration(config.RetryDelay) * time.Second
	if retryDelay <= 0 {
		retryDelay = 2 * time.Second // Default: 2 second delay between retries
	}

	client := &DoHClient{
		serverURLs:   serverURLs,
		authToken:    config.AuthToken,
		clientCert:   config.ClientCert,
		clientKey:    config.ClientKey,
		caCert:       config.CaCert,
		verifySSL:    config.VerifySSL,
		timeout:      30 * time.Second,
		maxRetries:   maxRetries,
		retryDelay:   retryDelay,
		currentIndex: 0,
	}

	if err := client.setupHTTPClient(); err != nil {
		return nil, fmt.Errorf("failed to setup HTTP client: %w", err)
	}

	return client, nil
}

// setupHTTPClient configures the HTTP client with mTLS support
func (c *DoHClient) setupHTTPClient() error {
	tlsConfig := &tls.Config{
		// #nosec G402 - InsecureSkipVerify is controlled by verifySSL config option
		// When verifySSL is true (default), this becomes false (secure)  
		// When verifySSL is false (user choice), this becomes true (for testing only)
		InsecureSkipVerify: !c.verifySSL,
	}

	// Load CA certificate for server verification
	if c.caCert != "" && c.verifySSL {
		caCertData, err := os.ReadFile(c.caCert)
		if err != nil {
			return fmt.Errorf("failed to read CA certificate: %w", err)
		}

		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCertData) {
			return fmt.Errorf("failed to parse CA certificate")
		}
		tlsConfig.RootCAs = caCertPool
	}

	// Load client certificate for mTLS
	if c.clientCert != "" && c.clientKey != "" {
		if _, err := os.Stat(c.clientCert); err != nil {
			return fmt.Errorf("client certificate not found: %w", err)
		}
		if _, err := os.Stat(c.clientKey); err != nil {
			return fmt.Errorf("client key not found: %w", err)
		}

		cert, err := tls.LoadX509KeyPair(c.clientCert, c.clientKey)
		if err != nil {
			return fmt.Errorf("failed to load client certificate: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
		MaxIdleConns:    10,
		IdleConnTimeout: 30 * time.Second,
	}

	c.httpClient = &http.Client{
		Transport: transport,
		Timeout:   c.timeout,
	}

	return nil
}

// Query performs a DNS query using DNS-over-HTTPS with automatic failover
func (c *DoHClient) Query(ctx context.Context, domain, recordType string) (*DNSResponse, error) {
	// Validate DNS name
	if err := validateDNSName(domain); err != nil {
		return nil, fmt.Errorf("invalid domain name: %w", err)
	}
	
	// Validate and normalize record type
	if recordType == "" {
		recordType = "A"
	}
	recordType = strings.ToUpper(recordType)
	if err := validateRecordType(recordType); err != nil {
		return nil, err
	}

	var lastErr error
	var errors []string

	// Try each server with retry logic
	for attempt := 0; attempt < c.maxRetries; attempt++ {
		serverURL := c.serverURLs[c.currentIndex]
		
		// Build request URL with query parameters
		req, err := http.NewRequestWithContext(ctx, "GET", serverURL, nil)
		if err != nil {
			lastErr = fmt.Errorf("failed to create request for %s: %w", serverURL, err)
			errors = append(errors, lastErr.Error())
			c.nextServer()
			continue
		}

		// Add query parameters
		q := req.URL.Query()
		q.Add("name", domain)
		q.Add("type", recordType)
		req.URL.RawQuery = q.Encode()

		// Set headers
		req.Header.Set("Accept", "application/dns-json")
		req.Header.Set("User-Agent", "Squawk DNS Client (Go/1.0)")

		// Add authentication header if token is provided
		if c.authToken != "" {
			req.Header.Set("Authorization", "Bearer "+c.authToken)
		}

		// Execute request
		resp, err := c.httpClient.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("HTTP request failed for %s: %w", serverURL, err)
			errors = append(errors, lastErr.Error())
			c.nextServer()
			
			// Add delay before next attempt
			if attempt < c.maxRetries-1 {
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-time.After(c.retryDelay):
				}
			}
			continue
		}
		defer func() {
			if err := resp.Body.Close(); err != nil {
				log.Printf("Warning: failed to close response body: %v", err)
			}
		}()

		// Read response body
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			lastErr = fmt.Errorf("failed to read response body from %s: %w", serverURL, err)
			errors = append(errors, lastErr.Error())
			c.nextServer()
			continue
		}

		// Check status code
		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("HTTP %d from %s: %s", resp.StatusCode, serverURL, string(body))
			errors = append(errors, lastErr.Error())
			c.nextServer()
			continue
		}

		// Parse JSON response
		var dnsResp DNSResponse
		if err := json.Unmarshal(body, &dnsResp); err != nil {
			lastErr = fmt.Errorf("failed to parse DNS response from %s: %w", serverURL, err)
			errors = append(errors, lastErr.Error())
			c.nextServer()
			continue
		}

		// Success! Return the response
		return &dnsResp, nil
	}

	// All servers failed, return combined error
	if len(errors) > 1 {
		return nil, fmt.Errorf("all DNS servers failed after %d attempts: %s", c.maxRetries, strings.Join(errors, "; "))
	}
	
	return nil, fmt.Errorf("DNS query failed: %w", lastErr)
}

// nextServer advances to the next server in the list (round-robin)
func (c *DoHClient) nextServer() {
	c.currentIndex = (c.currentIndex + 1) % len(c.serverURLs)
}

// normalizeServerURL ensures the server URL has the correct path for known providers
func normalizeServerURL(serverURL string) string {
	parsedURL, err := url.Parse(serverURL)
	if err != nil {
		return serverURL
	}
	
	host := strings.ToLower(parsedURL.Hostname())
	
	// Google DNS - ensure correct path
	if strings.Contains(host, "dns.google") {
		if parsedURL.Path == "" || parsedURL.Path == "/" {
			parsedURL.Path = "/resolve"
		}
	}
	
	// Cloudflare DNS - ensure correct path
	if strings.Contains(host, "cloudflare") || host == "1.1.1.1" || host == "1.0.0.1" {
		if parsedURL.Path == "" || parsedURL.Path == "/" {
			parsedURL.Path = "/dns-query"
		}
	}
	
	// Quad9 DNS
	if strings.Contains(host, "dns.quad9.net") {
		if parsedURL.Path == "" || parsedURL.Path == "/" {
			parsedURL.Path = "/dns-query"
		}
	}
	
	return parsedURL.String()
}

// QueryWithJSON performs a DNS query using POST with JSON payload
func (c *DoHClient) QueryWithJSON(ctx context.Context, domain, recordType string) (*DNSResponse, error) {
	// Validate DNS name
	if err := validateDNSName(domain); err != nil {
		return nil, fmt.Errorf("invalid domain name: %w", err)
	}
	
	// Validate and normalize record type
	if recordType == "" {
		recordType = "A"
	}
	recordType = strings.ToUpper(recordType)
	if err := validateRecordType(recordType); err != nil {
		return nil, err
	}

	// Create JSON payload
	payload := map[string]interface{}{
		"name": domain,
		"type": recordType,
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal JSON: %w", err)
	}

	// Create POST request
	// Use the current server URL (same as Query method)
	if len(c.serverURLs) == 0 {
		return nil, fmt.Errorf("no server URLs configured")
	}
	serverURL := c.serverURLs[c.currentIndex]
	req, err := http.NewRequestWithContext(ctx, "POST", serverURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/dns-json")
	req.Header.Set("User-Agent", "Squawk DNS Client (Go/1.0)")

	// Add authentication header if token is provided
	if c.authToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.authToken)
	}

	// Execute request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Printf("Warning: failed to close response body: %v", err)
		}
	}()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Check status code
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	// Parse JSON response
	var dnsResp DNSResponse
	if err := json.Unmarshal(body, &dnsResp); err != nil {
		return nil, fmt.Errorf("failed to parse DNS response: %w", err)
	}

	return &dnsResp, nil
}

// SetTimeout sets the HTTP client timeout
func (c *DoHClient) SetTimeout(timeout time.Duration) {
	c.timeout = timeout
	if c.httpClient != nil {
		c.httpClient.Timeout = timeout
	}
}

// Close cleans up the HTTP client resources
func (c *DoHClient) Close() error {
	if c.httpClient != nil {
		c.httpClient.CloseIdleConnections()
	}
	return nil
}