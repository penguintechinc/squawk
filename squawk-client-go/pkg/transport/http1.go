package transport

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// HTTP1Transport implements Transport using HTTP/1.1 REST API.
type HTTP1Transport struct {
	config     *Config
	httpClient *http.Client
}

// NewHTTP1Transport creates a new HTTP/1.1 REST transport.
func NewHTTP1Transport(cfg *Config) (*HTTP1Transport, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	t := &HTTP1Transport{
		config: cfg,
	}

	if err := t.setupHTTPClient(); err != nil {
		return nil, fmt.Errorf("failed to setup HTTP client: %w", err)
	}

	return t, nil
}

// setupHTTPClient configures the HTTP client with TLS/mTLS support.
func (t *HTTP1Transport) setupHTTPClient() error {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	// Handle SSL verification
	if !t.config.VerifySSL {
		// #nosec G402 - InsecureSkipVerify controlled by user config for testing
		tlsConfig.InsecureSkipVerify = true
	}

	// Load CA certificate for server verification
	if t.config.CACert != "" && t.config.VerifySSL {
		caCertData, err := os.ReadFile(t.config.CACert)
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
	if t.config.ClientCert != "" && t.config.ClientKey != "" {
		cert, err := tls.LoadX509KeyPair(t.config.ClientCert, t.config.ClientKey)
		if err != nil {
			return fmt.Errorf("failed to load client certificate: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	// Use provided TLS config if available
	if t.config.TLSConfig != nil {
		tlsConfig = t.config.TLSConfig
	}

	transport := &http.Transport{
		TLSClientConfig:     tlsConfig,
		MaxIdleConns:        t.config.MaxIdleConns,
		MaxConnsPerHost:     t.config.MaxConnsPerHost,
		IdleConnTimeout:     t.config.IdleTimeout,
		TLSHandshakeTimeout: t.config.ConnectTimeout,
		ForceAttemptHTTP2:   false, // HTTP/1.1 only
	}

	t.httpClient = &http.Client{
		Transport: transport,
		Timeout:   t.config.RequestTimeout,
	}

	return nil
}

// doRequest performs an HTTP request with authentication.
func (t *HTTP1Transport) doRequest(ctx context.Context, method, url string, body interface{}) ([]byte, error) {
	var reqBody io.Reader
	if body != nil {
		jsonData, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		reqBody = bytes.NewBuffer(jsonData)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "Squawk Client (Go/HTTP1)")

	if t.config.AuthToken != "" {
		req.Header.Set("Authorization", "Bearer "+t.config.AuthToken)
	}

	resp, err := t.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	return respBody, nil
}

// DNSQuery performs a DNS query using REST API.
func (t *HTTP1Transport) DNSQuery(ctx context.Context, req *DNSRequest) (*DNSResponse, error) {
	if t.config.DNSServerURL == "" {
		return nil, fmt.Errorf("DNS server URL not configured")
	}

	// Build query URL
	url := strings.TrimSuffix(t.config.DNSServerURL, "/")
	if !strings.Contains(url, "/dns-query") && !strings.Contains(url, "/resolve") {
		url += "/dns-query"
	}
	url += fmt.Sprintf("?name=%s&type=%s", req.Domain, req.RecordType)

	// Create GET request for DNS
	httpReq, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create DNS request: %w", err)
	}

	httpReq.Header.Set("Accept", "application/dns-json")
	httpReq.Header.Set("User-Agent", "Squawk Client (Go/HTTP1)")
	if t.config.AuthToken != "" {
		httpReq.Header.Set("Authorization", "Bearer "+t.config.AuthToken)
	}

	resp, err := t.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("DNS request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read DNS response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DNS query failed with HTTP %d: %s", resp.StatusCode, string(body))
	}

	var dnsResp DNSResponse
	if err := json.Unmarshal(body, &dnsResp); err != nil {
		return nil, fmt.Errorf("failed to parse DNS response: %w", err)
	}

	return &dnsResp, nil
}

// DHCPDiscover performs a DHCP Discover request.
func (t *HTTP1Transport) DHCPDiscover(ctx context.Context, req *DHCPDiscoverRequest) (*DHCPOfferResponse, error) {
	if t.config.DHCPServerURL == "" {
		return nil, fmt.Errorf("DHCP server URL not configured")
	}

	url := strings.TrimSuffix(t.config.DHCPServerURL, "/") + "/dhcp/discover"

	body, err := t.doRequest(ctx, "POST", url, req)
	if err != nil {
		return nil, fmt.Errorf("DHCP discover failed: %w", err)
	}

	var resp DHCPOfferResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse DHCP offer: %w", err)
	}

	return &resp, nil
}

// DHCPRequest performs a DHCP Request message.
func (t *HTTP1Transport) DHCPRequest(ctx context.Context, req *DHCPRequestMessage) (*DHCPAckResponse, error) {
	if t.config.DHCPServerURL == "" {
		return nil, fmt.Errorf("DHCP server URL not configured")
	}

	url := strings.TrimSuffix(t.config.DHCPServerURL, "/") + "/dhcp/request"

	body, err := t.doRequest(ctx, "POST", url, req)
	if err != nil {
		return nil, fmt.Errorf("DHCP request failed: %w", err)
	}

	var resp DHCPAckResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse DHCP ack: %w", err)
	}

	return &resp, nil
}

// DHCPRelease performs a DHCP Release request.
func (t *HTTP1Transport) DHCPRelease(ctx context.Context, req *DHCPReleaseRequest) (*DHCPReleaseResponse, error) {
	if t.config.DHCPServerURL == "" {
		return nil, fmt.Errorf("DHCP server URL not configured")
	}

	url := strings.TrimSuffix(t.config.DHCPServerURL, "/") + "/dhcp/release"

	body, err := t.doRequest(ctx, "POST", url, req)
	if err != nil {
		return nil, fmt.Errorf("DHCP release failed: %w", err)
	}

	var resp DHCPReleaseResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse DHCP release response: %w", err)
	}

	return &resp, nil
}

// DHCPGetConfig retrieves DHCP configuration via REST API.
func (t *HTTP1Transport) DHCPGetConfig(ctx context.Context, macAddress string) (*DHCPConfigResponse, error) {
	if t.config.DHCPServerURL == "" {
		return nil, fmt.Errorf("DHCP server URL not configured")
	}

	url := strings.TrimSuffix(t.config.DHCPServerURL, "/") + "/dhcp/config?mac=" + macAddress

	body, err := t.doRequest(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("DHCP config request failed: %w", err)
	}

	var resp DHCPConfigResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse DHCP config: %w", err)
	}

	return &resp, nil
}

// NTSKeyEstablishment performs NTS Key Establishment.
func (t *HTTP1Transport) NTSKeyEstablishment(ctx context.Context, req *NTSKERequest) (*NTSKEResponse, error) {
	if t.config.NTPServerURL == "" {
		return nil, fmt.Errorf("NTP server URL not configured")
	}

	url := strings.TrimSuffix(t.config.NTPServerURL, "/") + "/nts/ke"

	body, err := t.doRequest(ctx, "POST", url, req)
	if err != nil {
		return nil, fmt.Errorf("NTS-KE request failed: %w", err)
	}

	var resp NTSKEResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse NTS-KE response: %w", err)
	}

	return &resp, nil
}

// NTPQuery performs an NTS-authenticated NTP query.
func (t *HTTP1Transport) NTPQuery(ctx context.Context, req *NTPRequest) (*NTPResponse, error) {
	if t.config.NTPServerURL == "" {
		return nil, fmt.Errorf("NTP server URL not configured")
	}

	url := strings.TrimSuffix(t.config.NTPServerURL, "/") + "/ntp/query"

	body, err := t.doRequest(ctx, "POST", url, req)
	if err != nil {
		return nil, fmt.Errorf("NTP query failed: %w", err)
	}

	var resp NTPResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse NTP response: %w", err)
	}

	return &resp, nil
}

// NTPGetTime performs a simple time query.
func (t *HTTP1Transport) NTPGetTime(ctx context.Context) (*TimeResponse, error) {
	if t.config.NTPServerURL == "" {
		return nil, fmt.Errorf("NTP server URL not configured")
	}

	url := strings.TrimSuffix(t.config.NTPServerURL, "/") + "/ntp/time"

	body, err := t.doRequest(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("NTP time request failed: %w", err)
	}

	var resp TimeResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse time response: %w", err)
	}

	return &resp, nil
}

// HealthCheck performs a health check for the specified service.
func (t *HTTP1Transport) HealthCheck(ctx context.Context, service Service) error {
	var serverURL string
	switch service {
	case ServiceDNS:
		serverURL = t.config.DNSServerURL
	case ServiceDHCP:
		serverURL = t.config.DHCPServerURL
	case ServiceNTP:
		serverURL = t.config.NTPServerURL
	default:
		return fmt.Errorf("unknown service: %s", service)
	}

	if serverURL == "" {
		return fmt.Errorf("%s server URL not configured", service)
	}

	url := strings.TrimSuffix(serverURL, "/") + "/health"

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	_, err := t.doRequest(ctx, "GET", url, nil)
	return err
}

// Close cleans up the HTTP client resources.
func (t *HTTP1Transport) Close() error {
	if t.httpClient != nil {
		t.httpClient.CloseIdleConnections()
	}
	return nil
}
