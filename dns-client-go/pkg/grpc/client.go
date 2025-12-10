package grpc

import (
	"context"
	"fmt"
	"log"
	"net/url"
	"strings"
	"time"

	"google.golang.org/grpc"
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

// NewDNSClient creates a new gRPC DNS client
func NewDNSClient(serverAddr string, token string) (*DNSClient, error) {
	return NewDNSClientWithTimeout(serverAddr, token, 30*time.Second)
}

// NewDNSClientWithTimeout creates a new gRPC DNS client with custom timeout
func NewDNSClientWithTimeout(serverAddr string, token string, timeout time.Duration) (*DNSClient, error) {
	if serverAddr == "" {
		return nil, fmt.Errorf("server address cannot be empty")
	}

	// Parse and validate server address
	addr, err := parseServerAddress(serverAddr)
	if err != nil {
		return nil, err
	}

	// Create gRPC channel with insecure connection
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	conn, err := grpc.DialContext(
		ctx,
		addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
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

// parseServerAddress parses and validates the server address
func parseServerAddress(serverAddr string) (string, error) {
	// Handle grpc:// and grpcs:// schemes
	if strings.HasPrefix(serverAddr, "grpc://") {
		serverAddr = strings.TrimPrefix(serverAddr, "grpc://")
	} else if strings.HasPrefix(serverAddr, "grpcs://") {
		return "", fmt.Errorf("secure gRPC (grpcs://) not yet supported")
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
		return "", fmt.Errorf("invalid server address: %w", err)
	}

	// Extract host:port
	host := parsed.Hostname()
	port := parsed.Port()

	if host == "" {
		return "", fmt.Errorf("server address must include a hostname")
	}

	if port == "" {
		port = "50052"
	}

	return host + ":" + port, nil
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
