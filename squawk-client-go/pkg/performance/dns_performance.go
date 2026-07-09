package performance

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/penguintechinc/squawk/squawk-client-go/pkg/client"
	"github.com/penguintechinc/squawk/squawk-client-go/pkg/logger"
)

// DNSPerformanceStats represents comprehensive DNS over HTTP performance metrics
type DNSPerformanceStats struct {
	// Request Information
	Timestamp         time.Time `json:"timestamp"`
	ClientID          string    `json:"client_id"`
	ServerURL         string    `json:"server_url"`
	TestDomain        string    `json:"test_domain"`
	QueryType         string    `json:"query_type"`
	
	// Network Timing (similar to http-traceroute)
	DNSLookup         Duration  `json:"dns_lookup"`          // DNS resolution time
	TCPConnection     Duration  `json:"tcp_connection"`      // TCP connect time  
	TLSHandshake      Duration  `json:"tls_handshake"`       // TLS handshake time
	ServerProcessing  Duration  `json:"server_processing"`   // Time to first byte
	ContentTransfer   Duration  `json:"content_transfer"`    // Content download time
	
	// Total Times
	TotalTime         Duration  `json:"total_time"`          // End-to-end total time
	NameLookup        Duration  `json:"name_lookup"`         // DNS + TCP + TLS
	Connect           Duration  `json:"connect"`             // TCP + TLS
	
	// HTTP Details
	HTTPStatus        int       `json:"http_status"`
	HTTPHeaders       int       `json:"http_headers_size"`
	ResponseSize      int64     `json:"response_size"`
	
	// DNS Response Details
	DNSStatus         string    `json:"dns_status"`          // NOERROR, NXDOMAIN, etc.
	DNSAnswerCount    int       `json:"dns_answer_count"`
	DNSResponseCode   int       `json:"dns_response_code"`
	CacheHit          bool      `json:"cache_hit"`
	
	// Network Information
	LocalAddr         string    `json:"local_addr"`
	RemoteAddr        string    `json:"remote_addr"`
	Protocol          string    `json:"protocol"`            // HTTP/1.1, HTTP/2, etc.
	TLSVersion        string    `json:"tls_version"`
	TLSCipherSuite    string    `json:"tls_cipher_suite"`
	
	// Error Information
	ErrorType         string    `json:"error_type,omitempty"`
	ErrorMessage      string    `json:"error_message,omitempty"`
	Successful        bool      `json:"successful"`
	
	// Performance Metrics
	Jitter            Duration  `json:"jitter,omitempty"`           // Compared to baseline
	PacketLoss        float64   `json:"packet_loss,omitempty"`     // If detectable
	Retries           int       `json:"retries"`
}

// Duration wraps time.Duration for better JSON marshaling
type Duration struct {
	time.Duration
}

func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"nanoseconds":  d.Nanoseconds(),
		"milliseconds": float64(d.Nanoseconds()) / 1e6,
		"human":        d.String(),
	})
}

func (d *Duration) UnmarshalJSON(data []byte) error {
	var temp map[string]interface{}
	if err := json.Unmarshal(data, &temp); err != nil {
		return err
	}
	
	if ns, ok := temp["nanoseconds"].(float64); ok {
		d.Duration = time.Duration(int64(ns))
	}
	
	return nil
}

// DNSPerformanceMonitor handles DNS over HTTP performance monitoring
type DNSPerformanceMonitor struct {
	config           *client.Config
	client           *http.Client
	logger           logger.Logger
	stopChan         chan struct{}
	wg               sync.WaitGroup
	
	// Performance tracking
	baseline         map[string]Duration  // Baseline response times per domain
	recentStats      []DNSPerformanceStats
	statsMutex       sync.RWMutex
	
	// Test domains for performance monitoring
	testDomains      []string
	
	// Upload configuration
	uploadURL        string
	uploadInterval   time.Duration
	uploadBatchSize  int
}

// NewDNSPerformanceMonitor creates a new performance monitor
func NewDNSPerformanceMonitor(cfg *client.Config, log logger.Logger) *DNSPerformanceMonitor {
	// Create HTTP client with tracing capabilities
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			// #nosec G402 - InsecureSkipVerify is controlled by user configuration for self-signed certs
			InsecureSkipVerify: !cfg.VerifySSL,
		},
		DisableKeepAlives: false, // Keep connections alive for better performance
		MaxIdleConns:      10,
		IdleConnTimeout:   30 * time.Second,
	}
	
	// Load client certificates if provided
	if cfg.ClientCert != "" && cfg.ClientKey != "" {
		cert, err := tls.LoadX509KeyPair(cfg.ClientCert, cfg.ClientKey)
		if err == nil {
			transport.TLSClientConfig.Certificates = []tls.Certificate{cert}
		}
	}
	
	// Load CA certificate if provided
	if cfg.CaCert != "" {
		caCert, err := os.ReadFile(cfg.CaCert)
		if err == nil {
			caCertPool := x509.NewCertPool()
			caCertPool.AppendCertsFromPEM(caCert)
			transport.TLSClientConfig.RootCAs = caCertPool
		}
	}
	
	client := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second, // Default timeout
	}
	
	// Default test domains for performance monitoring
	testDomains := []string{
		"google.com",
		"cloudflare.com", 
		"example.com",
		"github.com",
		cfg.ServerURL, // Include the DNS server itself
	}
	
	uploadURL := cfg.ServerURL
	if !strings.HasSuffix(uploadURL, "/") {
		uploadURL += "/"
	}
	uploadURL += "api/performance/upload"
	
	return &DNSPerformanceMonitor{
		config:          cfg,
		client:          client,
		logger:          log,
		stopChan:        make(chan struct{}),
		baseline:        make(map[string]Duration),
		recentStats:     make([]DNSPerformanceStats, 0, 100),
		testDomains:     testDomains,
		uploadURL:       uploadURL,
		uploadInterval:  5 * time.Minute,  // Upload every 5 minutes
		uploadBatchSize: 50,               // Upload up to 50 stats at once
	}
}

// Start begins performance monitoring
func (pm *DNSPerformanceMonitor) Start() error {
	pm.logger.Info("Starting DNS performance monitoring")
	
	pm.wg.Add(2)
	
	// Start performance testing goroutine
	go pm.performanceTestLoop()
	
	// Start upload goroutine  
	go pm.uploadLoop()
	
	return nil
}

// Stop stops performance monitoring
func (pm *DNSPerformanceMonitor) Stop() error {
	pm.logger.Info("Stopping DNS performance monitoring")
	
	close(pm.stopChan)
	pm.wg.Wait()
	
	// Upload any remaining stats
	pm.uploadStats()
	
	return nil
}

// performanceTestLoop runs performance tests at random intervals
func (pm *DNSPerformanceMonitor) performanceTestLoop() {
	defer pm.wg.Done()
	
	ticker := time.NewTicker(time.Minute) // Check every minute if we should test
	defer ticker.Stop()
	
	for {
		select {
		case <-pm.stopChan:
			return
			
		case <-ticker.C:
			// Random interval between 5 and 10 minutes
			// #nosec G404 - Using math/rand is acceptable for test scheduling (non-security context)
			nextTest := rand.Intn(5*60) + 5*60 // 5-10 minutes in seconds
			
			timer := time.NewTimer(time.Duration(nextTest) * time.Second)
			
			select {
			case <-pm.stopChan:
				timer.Stop()
				return
				
			case <-timer.C:
				pm.runPerformanceTest()
			}
		}
	}
}

// runPerformanceTest performs a comprehensive DNS over HTTP performance test
func (pm *DNSPerformanceMonitor) runPerformanceTest() {
	// Select random test domain
	// #nosec G404 - Using math/rand is acceptable for domain selection (non-security context)
	domain := pm.testDomains[rand.Intn(len(pm.testDomains))]
	
	pm.logger.Debug("Running performance test for domain: %s", domain)
	
	stats := pm.performDNSOverHTTPTest(domain, "A")
	
	pm.statsMutex.Lock()
	pm.recentStats = append(pm.recentStats, stats)
	
	// Keep only recent stats (last 100)
	if len(pm.recentStats) > 100 {
		pm.recentStats = pm.recentStats[len(pm.recentStats)-100:]
	}
	pm.statsMutex.Unlock()
	
	// Update baseline if successful
	if stats.Successful {
		pm.updateBaseline(domain, stats.TotalTime)
	}
	
	pm.logger.Debug("Performance test completed: %s in %v", domain, stats.TotalTime.Duration)
}

// performDNSOverHTTPTest performs detailed DNS over HTTP test with timing breakdown
func (pm *DNSPerformanceMonitor) performDNSOverHTTPTest(domain, queryType string) DNSPerformanceStats {
	stats := DNSPerformanceStats{
		Timestamp:    time.Now(),
		ClientID:     pm.generateClientID(),
		ServerURL:    pm.config.ServerURL,
		TestDomain:   domain,
		QueryType:    queryType,
		Protocol:     "HTTP/1.1", // Will be updated based on actual connection
		Successful:   false,
	}
	
	// Create DNS over HTTP request URL
	dnsURL, err := url.Parse(pm.config.ServerURL)
	if err != nil {
		stats.ErrorType = "url_parse_error"
		stats.ErrorMessage = err.Error()
		return stats
	}
	
	// Add DNS query parameters
	params := url.Values{}
	params.Set("name", domain)
	params.Set("type", queryType)
	dnsURL.RawQuery = params.Encode()
	
	// Create request with tracing
	req, err := http.NewRequest("GET", dnsURL.String(), nil)
	if err != nil {
		stats.ErrorType = "request_creation_error"
		stats.ErrorMessage = err.Error()
		return stats
	}
	
	// Set headers
	req.Header.Set("Accept", "application/dns-json")
	req.Header.Set("User-Agent", "Squawk-DNS-Client/2.0 Performance-Monitor")
	
	if pm.config.AuthToken != "" {
		req.Header.Set("Authorization", "Bearer "+pm.config.AuthToken)
	}
	
	// Setup request tracing
	var (
		dnsStart, dnsEnd         time.Time
		connectStart, connectEnd time.Time
		tlsStart, tlsEnd         time.Time
		reqStart, reqEnd         time.Time
		firstByteTime            time.Time
		localAddr, remoteAddr    string
	)
	
	trace := &httptrace.ClientTrace{
		DNSStart: func(info httptrace.DNSStartInfo) {
			dnsStart = time.Now()
		},
		DNSDone: func(info httptrace.DNSDoneInfo) {
			dnsEnd = time.Now()
			stats.DNSLookup = Duration{dnsEnd.Sub(dnsStart)}
		},
		ConnectStart: func(network, addr string) {
			connectStart = time.Now()
		},
		ConnectDone: func(network, addr string, err error) {
			connectEnd = time.Now()
			stats.TCPConnection = Duration{connectEnd.Sub(connectStart)}
			remoteAddr = addr
		},
		TLSHandshakeStart: func() {
			tlsStart = time.Now()
		},
		TLSHandshakeDone: func(state tls.ConnectionState, err error) {
			tlsEnd = time.Now()
			stats.TLSHandshake = Duration{tlsEnd.Sub(tlsStart)}
			
			if err == nil {
				stats.TLSVersion = pm.tlsVersionString(state.Version)
				stats.TLSCipherSuite = tls.CipherSuiteName(state.CipherSuite)
				stats.Protocol = state.NegotiatedProtocol
				if stats.Protocol == "" {
					stats.Protocol = "HTTP/1.1"
				}
			}
		},
		GotFirstResponseByte: func() {
			firstByteTime = time.Now()
		},
		GotConn: func(info httptrace.GotConnInfo) {
			if info.Conn != nil {
				localAddr = info.Conn.LocalAddr().String()
				if remoteAddr == "" {
					remoteAddr = info.Conn.RemoteAddr().String()
				}
			}
		},
	}
	
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))
	
	// Perform the request
	reqStart = time.Now()
	resp, err := pm.client.Do(req)
	reqEnd = time.Now()
	
	stats.LocalAddr = localAddr
	stats.RemoteAddr = remoteAddr
	
	if err != nil {
		stats.ErrorType = "http_request_error"
		stats.ErrorMessage = err.Error()
		stats.TotalTime = Duration{reqEnd.Sub(reqStart)}
		return stats
	}
	defer func() { _ = resp.Body.Close() }()
	
	// Read response
	body, err := io.ReadAll(resp.Body)
	contentEnd := time.Now()
	
	stats.HTTPStatus = resp.StatusCode
	stats.ResponseSize = int64(len(body))
	stats.HTTPHeaders = pm.calculateHeadersSize(resp.Header)
	
	// Calculate timing metrics
	stats.TotalTime = Duration{contentEnd.Sub(reqStart)}
	
	if !firstByteTime.IsZero() {
		stats.ServerProcessing = Duration{firstByteTime.Sub(reqStart)}
		stats.ContentTransfer = Duration{contentEnd.Sub(firstByteTime)}
	}
	
	stats.NameLookup = Duration{stats.DNSLookup.Duration + stats.TCPConnection.Duration + stats.TLSHandshake.Duration}
	stats.Connect = Duration{stats.TCPConnection.Duration + stats.TLSHandshake.Duration}
	
	if err != nil {
		stats.ErrorType = "response_read_error"
		stats.ErrorMessage = err.Error()
		return stats
	}
	
	// Parse DNS response if successful
	if resp.StatusCode == 200 {
		pm.parseDNSResponse(body, &stats)
		stats.Successful = true
	} else {
		stats.ErrorType = "http_error"
		stats.ErrorMessage = fmt.Sprintf("HTTP %d", resp.StatusCode)
	}
	
	// Calculate jitter if we have baseline
	if baseline, exists := pm.baseline[domain]; exists {
		jitter := stats.TotalTime.Duration - baseline.Duration
		if jitter < 0 {
			jitter = -jitter
		}
		stats.Jitter = Duration{jitter}
	}
	
	return stats
}

// parseDNSResponse parses the DNS over HTTP JSON response
func (pm *DNSPerformanceMonitor) parseDNSResponse(body []byte, stats *DNSPerformanceStats) {
	var response map[string]interface{}
	if err := json.Unmarshal(body, &response); err != nil {
		stats.DNSStatus = "PARSE_ERROR"
		return
	}
	
	// Extract DNS response code
	if status, ok := response["Status"].(float64); ok {
		stats.DNSResponseCode = int(status)
		switch int(status) {
		case 0:
			stats.DNSStatus = "NOERROR"
		case 3:
			stats.DNSStatus = "NXDOMAIN"
		default:
			stats.DNSStatus = fmt.Sprintf("RCODE_%d", int(status))
		}
	}
	
	// Extract answer count
	if answers, ok := response["Answer"].([]interface{}); ok {
		stats.DNSAnswerCount = len(answers)
	}
	
	// Check for cache hit indicator
	if comment, ok := response["Comment"].(string); ok {
		stats.CacheHit = strings.Contains(strings.ToLower(comment), "cache")
	}
}

// updateBaseline updates the baseline response time for a domain
func (pm *DNSPerformanceMonitor) updateBaseline(domain string, responseTime Duration) {
	pm.statsMutex.Lock()
	defer pm.statsMutex.Unlock()
	
	if existing, exists := pm.baseline[domain]; exists {
		// Use exponential moving average: new_baseline = 0.8 * old + 0.2 * new
		newTime := time.Duration(float64(existing.Duration)*0.8 + float64(responseTime.Duration)*0.2)
		pm.baseline[domain] = Duration{newTime}
	} else {
		pm.baseline[domain] = responseTime
	}
}

// uploadLoop handles periodic upload of performance stats
func (pm *DNSPerformanceMonitor) uploadLoop() {
	defer pm.wg.Done()
	
	ticker := time.NewTicker(pm.uploadInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-pm.stopChan:
			return
			
		case <-ticker.C:
			pm.uploadStats()
		}
	}
}

// uploadStats uploads collected performance statistics to the server
func (pm *DNSPerformanceMonitor) uploadStats() {
	pm.statsMutex.Lock()
	if len(pm.recentStats) == 0 {
		pm.statsMutex.Unlock()
		return
	}
	
	// Take up to uploadBatchSize stats
	batchSize := len(pm.recentStats)
	if batchSize > pm.uploadBatchSize {
		batchSize = pm.uploadBatchSize
	}
	
	statsToUpload := make([]DNSPerformanceStats, batchSize)
	copy(statsToUpload, pm.recentStats[:batchSize])
	
	// Remove uploaded stats
	pm.recentStats = pm.recentStats[batchSize:]
	pm.statsMutex.Unlock()
	
	pm.logger.Debug("Uploading %d performance statistics", len(statsToUpload))
	
	// Create upload payload
	payload := map[string]interface{}{
		"client_id":    pm.generateClientID(),
		"timestamp":    time.Now(),
		"stats_count":  len(statsToUpload),
		"statistics":   statsToUpload,
	}
	
	jsonData, err := json.Marshal(payload)
	if err != nil {
		pm.logger.Error("Failed to marshal performance stats: %v", err)
		return
	}
	
	// Create upload request
	req, err := http.NewRequest("POST", pm.uploadURL, strings.NewReader(string(jsonData)))
	if err != nil {
		pm.logger.Error("Failed to create upload request: %v", err)
		return
	}
	
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Squawk-DNS-Client/2.0 Performance-Monitor")
	
	if pm.config.AuthToken != "" {
		req.Header.Set("Authorization", "Bearer "+pm.config.AuthToken)
	}
	
	// Perform upload
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	
	req = req.WithContext(ctx)
	
	resp, err := pm.client.Do(req)
	if err != nil {
		pm.logger.Error("Failed to upload performance stats: %v", err)
		return
	}
	defer func() { _ = resp.Body.Close() }()
	
	if resp.StatusCode != 200 {
		pm.logger.Error("Performance stats upload failed with status: %d", resp.StatusCode)
		return
	}
	
	pm.logger.Debug("Successfully uploaded %d performance statistics", len(statsToUpload))
}

// generateClientID generates a unique client identifier
func (pm *DNSPerformanceMonitor) generateClientID() string {
	hostname, err := os.Hostname()
	if err != nil || hostname == "" {
		hostname = "unknown"
	}
	
	// Include hostname and a hash of server URL for uniqueness
	h := sha256.Sum256([]byte(pm.config.ServerURL + hostname))
	return fmt.Sprintf("%s-%x", hostname, h[:8])
}

// tlsVersionString converts TLS version number to string
func (pm *DNSPerformanceMonitor) tlsVersionString(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("TLS 0x%04x", version)
	}
}

// calculateHeadersSize calculates the size of HTTP headers
func (pm *DNSPerformanceMonitor) calculateHeadersSize(headers http.Header) int {
	size := 0
	for key, values := range headers {
		for _, value := range values {
			size += len(key) + len(value) + 4 // +4 for ": " and "\r\n"
		}
	}
	return size
}

// GetRecentStats returns recent performance statistics
func (pm *DNSPerformanceMonitor) GetRecentStats() []DNSPerformanceStats {
	pm.statsMutex.RLock()
	defer pm.statsMutex.RUnlock()
	
	// Return a copy to avoid race conditions
	stats := make([]DNSPerformanceStats, len(pm.recentStats))
	copy(stats, pm.recentStats)
	
	return stats
}

// GetBaselines returns current performance baselines
func (pm *DNSPerformanceMonitor) GetBaselines() map[string]Duration {
	pm.statsMutex.RLock()
	defer pm.statsMutex.RUnlock()
	
	// Return a copy
	baselines := make(map[string]Duration)
	for k, v := range pm.baseline {
		baselines[k] = v
	}
	
	return baselines
}