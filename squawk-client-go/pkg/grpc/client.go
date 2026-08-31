package grpc

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net/url"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

// DNSClient represents a gRPC DNS Query client
type DNSClient struct {
	conn       *grpc.ClientConn
	client     DNSQueryServiceClient
	token      string
	serverAddr string
	timeout    time.Duration
}

// QueryResult represents the result of a DNS query
type QueryResult struct {
	Status    int32
	Answers   []*Answer
	Authority []*Answer
	Additional []*Answer
	Metadata  *QueryMetadata
}

// NewDNSClient creates a new gRPC DNS client. TLS certificate verification is
// enabled by default (matching the other transports' VerifySSL=true default);
// use NewDNSClientWithTLS to disable it explicitly. See NewDNSClientWithTLS
// for the grpc:// vs grpcs:// scheme semantics.
func NewDNSClient(serverAddr string, token string) (*DNSClient, error) {
	return NewDNSClientWithTLS(serverAddr, token, true, 30*time.Second)
}

// NewDNSClientWithTimeout creates a new gRPC DNS client with a custom timeout,
// using the same default TLS behavior as NewDNSClient.
func NewDNSClientWithTimeout(serverAddr string, token string, timeout time.Duration) (*DNSClient, error) {
	return NewDNSClientWithTLS(serverAddr, token, true, timeout)
}

// NewDNSClientWithTLS creates a new gRPC DNS client, honoring verifySSL the
// same way the HTTP/1, HTTP/2, and HTTP/3 transports do.
//
// grpcs:// establishes a real TLS channel; verifySSL=false only skips
// certificate verification on top of that already-encrypted channel (an
// explicit, logged opt-in), it never downgrades to plaintext.
//
// grpc:// (or a bare host:port, kept for backward compatibility) stays
// plaintext and always logs a warning, since the bearer/license token then
// crosses the wire unencrypted — this scheme should only be used for local
// development against a loopback server.
func NewDNSClientWithTLS(serverAddr, token string, verifySSL bool, timeout time.Duration) (*DNSClient, error) {
	if serverAddr == "" {
		return nil, fmt.Errorf("server address cannot be empty")
	}

	// Parse and validate server address
	addr, useTLS, err := parseServerAddress(serverAddr)
	if err != nil {
		return nil, err
	}

	var creds grpc.DialOption
	if useTLS {
		tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
		if !verifySSL {
			// #nosec G402 -- InsecureSkipVerify only applies on top of an already-TLS
			// (grpcs://) channel, and only when the caller explicitly set verifySSL=false.
			tlsConfig.InsecureSkipVerify = true
			log.Printf("WARNING: TLS certificate verification disabled for gRPC connection to %s", addr)
		}
		creds = grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig))
	} else {
		log.Printf("WARNING: using plaintext gRPC (grpc://) to %s - the bearer/license token crosses the wire unencrypted; use grpcs:// in production", addr)
		creds = grpc.WithTransportCredentials(insecure.NewCredentials())
	}

	// Create gRPC channel using NewClient
	conn, err := grpc.NewClient(addr, creds)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to DNS server at %s: %w", addr, err)
	}

	client := &DNSClient{
		conn:       conn,
		client:     NewDNSQueryServiceClient(conn),
		token:      token,
		serverAddr: addr,
		timeout:    timeout,
	}

	return client, nil
}

// Query performs a single DNS query
func (c *DNSClient) Query(ctx context.Context, domain string, recordType string) (*QueryResult, error) {
	if domain == "" {
		return nil, fmt.Errorf("domain cannot be empty")
	}

	if recordType == "" {
		recordType = "A"
	}

	// Ensure context has a timeout
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.timeout)
		defer cancel()
	}

	req := &QueryRequest{
		Name:  domain,
		Type:  recordType,
		Token: c.token,
	}

	resp, err := c.client.Query(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("DNS query failed for %s: %w", domain, err)
	}

	return convertGrpcResponse(resp), nil
}

// BatchQuery performs multiple DNS queries in parallel
func (c *DNSClient) BatchQuery(ctx context.Context, domains []string, recordType string) ([]*QueryResult, error) {
	if len(domains) == 0 {
		return nil, fmt.Errorf("domains list cannot be empty")
	}

	if recordType == "" {
		recordType = "A"
	}

	// Ensure context has a timeout
	if _, ok := ctx.Deadline(); !ok {
		timeout := c.timeout * time.Duration(len(domains)) / 10
		if timeout < c.timeout {
			timeout = c.timeout * 3
		}
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	// Build query requests
	queries := make([]*QueryRequest, len(domains))
	for i, domain := range domains {
		queries[i] = &QueryRequest{
			Name:  domain,
			Type:  recordType,
			Token: c.token,
		}
	}

	req := &BatchQueryRequest{
		Queries:       queries,
		MaxConcurrent: 10,
	}

	resp, err := c.client.BatchQuery(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("batch DNS query failed: %w", err)
	}

	// Convert responses
	results := make([]*QueryResult, len(resp.Responses))
	for i, grpcResp := range resp.Responses {
		results[i] = convertGrpcResponse(grpcResp)
	}

	return results, nil
}

// HealthCheck performs a health check on the DNS server
func (c *DNSClient) HealthCheck(ctx context.Context) (bool, error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.timeout)
		defer cancel()
	}

	req := &HealthCheckRequest{
		Service: "dns",
	}

	resp, err := c.client.HealthCheck(ctx, req)
	if err != nil {
		return false, fmt.Errorf("health check failed: %w", err)
	}

	// Status: 0=UNKNOWN, 1=SERVING, 2=NOT_SERVING, 3=SERVICE_UNKNOWN
	return resp.Status == 1, nil
}

// Close closes the gRPC connection
func (c *DNSClient) Close() error {
	if c.conn != nil {
		if err := c.conn.Close(); err != nil {
			log.Printf("Warning: failed to close gRPC connection: %v", err)
			return err
		}
	}
	return nil
}

// Helper functions

// parseServerAddress parses and validates the server address, returning the
// host:port to dial and whether the caller requested a TLS (grpcs://) channel.
func parseServerAddress(serverAddr string) (string, bool, error) {
	useTLS := false

	// Handle grpc:// and grpcs:// schemes
	switch {
	case strings.HasPrefix(serverAddr, "grpcs://"):
		serverAddr = strings.TrimPrefix(serverAddr, "grpcs://")
		useTLS = true
	case strings.HasPrefix(serverAddr, "grpc://"):
		serverAddr = strings.TrimPrefix(serverAddr, "grpc://")
	}

	// If no port specified, use default gRPC port
	if !strings.Contains(serverAddr, ":") {
		serverAddr = serverAddr + ":50052"
	}

	// Validate as URL to ensure proper format
	if !strings.Contains(serverAddr, "://") {
		serverAddr = "grpc://" + serverAddr
	}

	parsed, err := url.Parse(serverAddr)
	if err != nil {
		return "", false, fmt.Errorf("invalid server address: %w", err)
	}

	// Extract host:port
	host := parsed.Hostname()
	port := parsed.Port()

	if host == "" {
		return "", false, fmt.Errorf("server address must include a hostname")
	}

	if port == "" {
		port = "50052"
	}

	return host + ":" + port, useTLS, nil
}

// convertGrpcResponse converts a gRPC response to a QueryResult
func convertGrpcResponse(grpcResp *QueryResponse) *QueryResult {
	result := &QueryResult{
		Status:     grpcResp.Status,
		Answers:    grpcResp.Answers,
		Authority:  grpcResp.Authority,
		Additional: grpcResp.Additional,
		Metadata:   grpcResp.Metadata,
	}

	return result
}
