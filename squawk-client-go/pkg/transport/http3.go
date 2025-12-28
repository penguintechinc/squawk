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

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// HTTP3Transport implements Transport using HTTP/3 QUIC.
type HTTP3Transport struct {
	config        *Config
	httpClient    *http.Client
	roundTripper  *http3.RoundTripper
}

// NewHTTP3Transport creates a new HTTP/3 QUIC transport.
func NewHTTP3Transport(cfg *Config) (*HTTP3Transport, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	t := &HTTP3Transport{
		config: cfg,
	}

	if err := t.setupHTTP3Client(); err != nil {
		return nil, fmt.Errorf("failed to setup HTTP/3 client: %w", err)
	}

	return t, nil
}

// setupHTTP3Client configures the HTTP/3 client with QUIC and TLS.
func (t *HTTP3Transport) setupHTTP3Client() error {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13, // QUIC requires TLS 1.3
		NextProtos: []string{"h3"},   // ALPN for HTTP/3
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
		// Ensure TLS 1.3 for QUIC
		if tlsConfig.MinVersion < tls.VersionTLS13 {
			tlsConfig.MinVersion = tls.VersionTLS13
		}
		// Ensure h3 ALPN
		hasH3 := false
		for _, proto := range tlsConfig.NextProtos {
			if proto == "h3" {
				hasH3 = true
				break
			}
		}
		if !hasH3 {
			tlsConfig.NextProtos = append(tlsConfig.NextProtos, "h3")
		}
	}

	// Configure QUIC
	quicConfig := &quic.Config{
		MaxIdleTimeout:        t.config.IdleTimeout,
		KeepAlivePeriod:       t.config.QUICKeepAlive,
		MaxIncomingStreams:    t.config.QUICMaxStreams,
		MaxIncomingUniStreams: t.config.QUICMaxStreams,
		EnableDatagrams:       true, // Enable QUIC datagrams for better performance
	}

	// Create HTTP/3 round tripper
	t.roundTripper = &http3.RoundTripper{
		TLSClientConfig: tlsConfig,
		QUICConfig:      quicConfig,
	}

	t.httpClient = &http.Client{
		Transport: t.roundTripper,
		Timeout:   t.config.RequestTimeout,
	}

	return nil
}

// doRequest performs an HTTP/3 request with authentication.
func (t *HTTP3Transport) doRequest(ctx context.Context, method, url string, body interface{}) ([]byte, error) {
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
	req.Header.Set("User-Agent", "Squawk Client (Go/HTTP3-QUIC)")

	if t.config.AuthToken != "" {
		req.Header.Set("Authorization", "Bearer "+t.config.AuthToken)
	}

	resp, err := t.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP/3 request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	return respBody, nil
}

// DNSQuery performs a DNS query using HTTP/3.
func (t *HTTP3Transport) DNSQuery(ctx context.Context, req *DNSRequest) (*DNSResponse, error) {
	if t.config.DNSServerURL == "" {
		return nil, fmt.Errorf("DNS server URL not configured")
	}

	// Build query URL - ensure https scheme for HTTP/3
	url := ensureHTTPS(t.config.DNSServerURL)
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
	httpReq.Header.Set("User-Agent", "Squawk Client (Go/HTTP3-QUIC)")
	if t.config.AuthToken != "" {
		httpReq.Header.Set("Authorization", "Bearer "+t.config.AuthToken)
	}

	resp, err := t.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("DNS request failed: %w", err)
	}
	defer resp.Body.Close()

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

// DHCPDiscover performs a DHCP Discover request using HTTP/3.
func (t *HTTP3Transport) DHCPDiscover(ctx context.Context, req *DHCPDiscoverRequest) (*DHCPOfferResponse, error) {
	if t.config.DHCPServerURL == "" {
		return nil, fmt.Errorf("DHCP server URL not configured")
	}

	url := ensureHTTPS(t.config.DHCPServerURL) + "/dhcp/discover"

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

// DHCPRequest performs a DHCP Request message using HTTP/3.
func (t *HTTP3Transport) DHCPRequest(ctx context.Context, req *DHCPRequestMessage) (*DHCPAckResponse, error) {
	if t.config.DHCPServerURL == "" {
		return nil, fmt.Errorf("DHCP server URL not configured")
	}

	url := ensureHTTPS(t.config.DHCPServerURL) + "/dhcp/request"

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

// DHCPRelease performs a DHCP Release request using HTTP/3.
func (t *HTTP3Transport) DHCPRelease(ctx context.Context, req *DHCPReleaseRequest) (*DHCPReleaseResponse, error) {
	if t.config.DHCPServerURL == "" {
		return nil, fmt.Errorf("DHCP server URL not configured")
	}

	url := ensureHTTPS(t.config.DHCPServerURL) + "/dhcp/release"

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

// DHCPGetConfig retrieves DHCP configuration via HTTP/3.
func (t *HTTP3Transport) DHCPGetConfig(ctx context.Context, macAddress string) (*DHCPConfigResponse, error) {
	if t.config.DHCPServerURL == "" {
		return nil, fmt.Errorf("DHCP server URL not configured")
	}

	url := ensureHTTPS(t.config.DHCPServerURL) + "/dhcp/config?mac=" + macAddress

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

// NTSKeyEstablishment performs NTS Key Establishment using HTTP/3.
func (t *HTTP3Transport) NTSKeyEstablishment(ctx context.Context, req *NTSKERequest) (*NTSKEResponse, error) {
	if t.config.NTPServerURL == "" {
		return nil, fmt.Errorf("NTP server URL not configured")
	}

	url := ensureHTTPS(t.config.NTPServerURL) + "/nts/ke"

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

// NTPQuery performs an NTS-authenticated NTP query using HTTP/3.
func (t *HTTP3Transport) NTPQuery(ctx context.Context, req *NTPRequest) (*NTPResponse, error) {
	if t.config.NTPServerURL == "" {
		return nil, fmt.Errorf("NTP server URL not configured")
	}

	url := ensureHTTPS(t.config.NTPServerURL) + "/ntp/query"

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

// NTPGetTime performs a simple time query using HTTP/3.
func (t *HTTP3Transport) NTPGetTime(ctx context.Context) (*TimeResponse, error) {
	if t.config.NTPServerURL == "" {
		return nil, fmt.Errorf("NTP server URL not configured")
	}

	url := ensureHTTPS(t.config.NTPServerURL) + "/ntp/time"

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

// HealthCheck performs a health check for the specified service using HTTP/3.
func (t *HTTP3Transport) HealthCheck(ctx context.Context, service Service) error {
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

	url := ensureHTTPS(serverURL) + "/health"

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	_, err := t.doRequest(ctx, "GET", url, nil)
	return err
}

// Close cleans up the HTTP/3 client resources.
func (t *HTTP3Transport) Close() error {
	if t.roundTripper != nil {
		if err := t.roundTripper.Close(); err != nil {
			return fmt.Errorf("failed to close HTTP/3 transport: %w", err)
		}
	}
	return nil
}

// ensureHTTPS ensures the URL uses https scheme (required for HTTP/3).
func ensureHTTPS(url string) string {
	url = strings.TrimSuffix(url, "/")
	if strings.HasPrefix(url, "http://") {
		return "https://" + strings.TrimPrefix(url, "http://")
	}
	if !strings.HasPrefix(url, "https://") {
		return "https://" + url
	}
	return url
}
