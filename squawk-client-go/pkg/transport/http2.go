package transport

import (
	"context"
	"crypto/tls"
	"fmt"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// HTTP2Transport implements Transport using HTTP/2 gRPC.
type HTTP2Transport struct {
	config *Config

	// DNS gRPC connection
	dnsConn *grpc.ClientConn

	// DHCP gRPC connection
	dhcpConn *grpc.ClientConn

	// NTP gRPC connection
	ntpConn *grpc.ClientConn
}

// DNSServiceClient defines the gRPC DNS service client interface.
type DNSServiceClient interface {
	Query(ctx context.Context, req *GRPCDNSRequest, opts ...grpc.CallOption) (*GRPCDNSResponse, error)
}

// DHCPServiceClient defines the gRPC DHCP service client interface.
type DHCPServiceClient interface {
	Discover(ctx context.Context, req *GRPCDHCPDiscoverRequest, opts ...grpc.CallOption) (*GRPCDHCPOfferResponse, error)
	Request(ctx context.Context, req *GRPCDHCPRequestMessage, opts ...grpc.CallOption) (*GRPCDHCPAckResponse, error)
	Release(ctx context.Context, req *GRPCDHCPReleaseRequest, opts ...grpc.CallOption) (*GRPCDHCPReleaseResponse, error)
	GetConfig(ctx context.Context, req *GRPCDHCPConfigRequest, opts ...grpc.CallOption) (*GRPCDHCPConfigResponse, error)
}

// NTPServiceClient defines the gRPC NTP service client interface.
type NTPServiceClient interface {
	KeyEstablishment(ctx context.Context, req *GRPCNTSKERequest, opts ...grpc.CallOption) (*GRPCNTSKEResponse, error)
	Query(ctx context.Context, req *GRPCNTPRequest, opts ...grpc.CallOption) (*GRPCNTPResponse, error)
	GetTime(ctx context.Context, req *GRPCTimeRequest, opts ...grpc.CallOption) (*GRPCTimeResponse, error)
}

// gRPC message types - these will be generated from protobuf
// For now, define them as placeholder types

type GRPCDNSRequest struct {
	Name  string
	Type  string
	Token string
}

type GRPCDNSResponse struct {
	Status   int32
	Answers  []*GRPCDNSRecord
	Comment  string
}

type GRPCDNSRecord struct {
	Name string
	Type int32
	TTL  int32
	Data string
}

type GRPCDHCPDiscoverRequest struct {
	MacAddress  string
	Hostname    string
	RequestedIp string
	ClientId    string
	Token       string
}

type GRPCDHCPOfferResponse struct {
	Status        string
	OfferedIp     string
	SubnetMask    string
	Gateway       string
	DnsServers    []string
	LeaseTime     int32
	ServerId      string
	TransactionId string
}

type GRPCDHCPRequestMessage struct {
	MacAddress    string
	TransactionId string
	RequestedIp   string
	ServerId      string
	Token         string
}

type GRPCDHCPAckResponse struct {
	Status        string
	AssignedIp    string
	SubnetMask    string
	Gateway       string
	DnsServers    []string
	LeaseTime     int32
	RenewalTime   int32
	RebindingTime int32
	ErrorMessage  string
}

type GRPCDHCPReleaseRequest struct {
	MacAddress string
	ClientIp   string
	Token      string
}

type GRPCDHCPReleaseResponse struct {
	Success bool
	Message string
}

type GRPCDHCPConfigRequest struct {
	MacAddress string
	Token      string
}

type GRPCDHCPConfigResponse struct {
	AssignedIp  string
	SubnetMask  string
	Gateway     string
	DnsServers  []string
	LeaseTime   int32
	RenewalTime int32
	LeaseStart  int64
	LeaseEnd    int64
	Status      string
}

type GRPCNTSKERequest struct {
	SupportedAlgorithms []uint32
	NextProtocol        string
	Token               string
}

type GRPCNTSKEResponse struct {
	Success       bool
	C2SKey        []byte
	S2CKey        []byte
	Cookies       [][]byte
	NtpServer     string
	NtpPort       int32
	AeadAlgorithm uint32
	ExpiresAt     int64
	ErrorMessage  string
}

type GRPCNTPRequest struct {
	Cookie         []byte
	UniqueId       []byte
	ClientTransmit int64
	Authenticator  []byte
	Token          string
}

type GRPCNTPResponse struct {
	LeapIndicator      int32
	Stratum            int32
	Precision          int32
	ReferenceTimestamp int64
	OriginTimestamp    int64
	ReceiveTimestamp   int64
	TransmitTimestamp  int64
	Cookie             []byte
	Authenticator      []byte
}

type GRPCTimeRequest struct {
	Token string
}

type GRPCTimeResponse struct {
	Timestamp  int64
	Stratum    int32
	AccuracyNs float64
}

// NewHTTP2Transport creates a new HTTP/2 gRPC transport.
func NewHTTP2Transport(cfg *Config) (*HTTP2Transport, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	t := &HTTP2Transport{
		config: cfg,
	}

	return t, nil
}

// getGRPCCredentials returns appropriate gRPC credentials based on config.
func (t *HTTP2Transport) getGRPCCredentials() grpc.DialOption {
	if t.config.TLSConfig != nil {
		return grpc.WithTransportCredentials(credentials.NewTLS(t.config.TLSConfig))
	}
	if !t.config.VerifySSL {
		// Keep the channel encrypted and only skip certificate verification
		// (parity with the HTTP transports' verify=false). Never fall through to
		// plaintext gRPC — that would leak the bearer token on the wire.
		//nolint:gosec // G402: intentional opt-in InsecureSkipVerify when VerifySSL=false
		return grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{InsecureSkipVerify: true}))
	}
	// Default to system certificates
	return grpc.WithTransportCredentials(credentials.NewClientTLSFromCert(nil, ""))
}

// connectDNS establishes connection to DNS gRPC server.
func (t *HTTP2Transport) connectDNS() error {
	if t.dnsConn != nil {
		return nil
	}

	if t.config.DNSServerURL == "" {
		return fmt.Errorf("DNS server URL not configured")
	}

	addr := parseGRPCAddress(t.config.DNSServerURL)
	conn, err := grpc.NewClient(
		addr,
		t.getGRPCCredentials(),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(10*1024*1024)),
	)
	if err != nil {
		return fmt.Errorf("failed to connect to DNS gRPC server: %w", err)
	}

	t.dnsConn = conn
	// Note: In production, this would use the generated client from protobuf
	// t.dnsClient = NewDNSServiceClient(conn)
	return nil
}

// connectDHCP establishes connection to DHCP gRPC server.
func (t *HTTP2Transport) connectDHCP() error {
	if t.dhcpConn != nil {
		return nil
	}

	if t.config.DHCPServerURL == "" {
		return fmt.Errorf("DHCP server URL not configured")
	}

	addr := parseGRPCAddress(t.config.DHCPServerURL)
	conn, err := grpc.NewClient(
		addr,
		t.getGRPCCredentials(),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(10*1024*1024)),
	)
	if err != nil {
		return fmt.Errorf("failed to connect to DHCP gRPC server: %w", err)
	}

	t.dhcpConn = conn
	// Note: In production, this would use the generated client from protobuf
	// t.dhcpClient = NewDHCPServiceClient(conn)
	return nil
}

// connectNTP establishes connection to NTP gRPC server.
func (t *HTTP2Transport) connectNTP() error {
	if t.ntpConn != nil {
		return nil
	}

	if t.config.NTPServerURL == "" {
		return fmt.Errorf("NTP server URL not configured")
	}

	addr := parseGRPCAddress(t.config.NTPServerURL)
	conn, err := grpc.NewClient(
		addr,
		t.getGRPCCredentials(),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(10*1024*1024)),
	)
	if err != nil {
		return fmt.Errorf("failed to connect to NTP gRPC server: %w", err)
	}

	t.ntpConn = conn
	// Note: In production, this would use the generated client from protobuf
	// t.ntpClient = NewNTPServiceClient(conn)
	return nil
}

// parseGRPCAddress extracts host:port from URL for gRPC connection.
func parseGRPCAddress(serverURL string) string {
	// Remove scheme prefix
	addr := serverURL
	for _, prefix := range []string{"grpc://", "grpcs://", "https://", "http://"} {
		addr = strings.TrimPrefix(addr, prefix)
	}

	// Remove path
	if idx := strings.Index(addr, "/"); idx > 0 {
		addr = addr[:idx]
	}

	// Add default port if not present
	if !strings.Contains(addr, ":") {
		addr = addr + ":50052"
	}

	return addr
}

// DNSQuery performs a DNS query using gRPC.
func (t *HTTP2Transport) DNSQuery(ctx context.Context, req *DNSRequest) (*DNSResponse, error) {
	if err := t.connectDNS(); err != nil {
		return nil, err
	}

	// TODO: Use actual gRPC client when protobuf is generated
	// For now, return a placeholder error indicating gRPC needs protobuf setup
	return nil, fmt.Errorf("gRPC DNS client not yet implemented - awaiting protobuf generation for DHCP/NTP services")
}

// DHCPDiscover performs a DHCP Discover request using gRPC.
func (t *HTTP2Transport) DHCPDiscover(ctx context.Context, req *DHCPDiscoverRequest) (*DHCPOfferResponse, error) {
	if err := t.connectDHCP(); err != nil {
		return nil, err
	}

	// TODO: Use actual gRPC client when protobuf is generated
	return nil, fmt.Errorf("gRPC DHCP client not yet implemented - awaiting protobuf generation")
}

// DHCPRequest performs a DHCP Request using gRPC.
func (t *HTTP2Transport) DHCPRequest(ctx context.Context, req *DHCPRequestMessage) (*DHCPAckResponse, error) {
	if err := t.connectDHCP(); err != nil {
		return nil, err
	}

	// TODO: Use actual gRPC client when protobuf is generated
	return nil, fmt.Errorf("gRPC DHCP client not yet implemented - awaiting protobuf generation")
}

// DHCPRelease performs a DHCP Release using gRPC.
func (t *HTTP2Transport) DHCPRelease(ctx context.Context, req *DHCPReleaseRequest) (*DHCPReleaseResponse, error) {
	if err := t.connectDHCP(); err != nil {
		return nil, err
	}

	// TODO: Use actual gRPC client when protobuf is generated
	return nil, fmt.Errorf("gRPC DHCP client not yet implemented - awaiting protobuf generation")
}

// DHCPGetConfig retrieves DHCP configuration using gRPC.
func (t *HTTP2Transport) DHCPGetConfig(ctx context.Context, macAddress string) (*DHCPConfigResponse, error) {
	if err := t.connectDHCP(); err != nil {
		return nil, err
	}

	// TODO: Use actual gRPC client when protobuf is generated
	return nil, fmt.Errorf("gRPC DHCP client not yet implemented - awaiting protobuf generation")
}

// NTSKeyEstablishment performs NTS Key Establishment using gRPC.
func (t *HTTP2Transport) NTSKeyEstablishment(ctx context.Context, req *NTSKERequest) (*NTSKEResponse, error) {
	if err := t.connectNTP(); err != nil {
		return nil, err
	}

	// TODO: Use actual gRPC client when protobuf is generated
	return nil, fmt.Errorf("gRPC NTP client not yet implemented - awaiting protobuf generation")
}

// NTPQuery performs an NTS-authenticated NTP query using gRPC.
func (t *HTTP2Transport) NTPQuery(ctx context.Context, req *NTPRequest) (*NTPResponse, error) {
	if err := t.connectNTP(); err != nil {
		return nil, err
	}

	// TODO: Use actual gRPC client when protobuf is generated
	return nil, fmt.Errorf("gRPC NTP client not yet implemented - awaiting protobuf generation")
}

// NTPGetTime performs a simple time query using gRPC.
func (t *HTTP2Transport) NTPGetTime(ctx context.Context) (*TimeResponse, error) {
	if err := t.connectNTP(); err != nil {
		return nil, err
	}

	// TODO: Use actual gRPC client when protobuf is generated
	return nil, fmt.Errorf("gRPC NTP client not yet implemented - awaiting protobuf generation")
}

// HealthCheck performs a health check for the specified service using gRPC.
func (t *HTTP2Transport) HealthCheck(ctx context.Context, service Service) error {
	switch service {
	case ServiceDNS:
		if err := t.connectDNS(); err != nil {
			return err
		}
		// TODO: Use gRPC health check when implemented
		return nil
	case ServiceDHCP:
		if err := t.connectDHCP(); err != nil {
			return err
		}
		return nil
	case ServiceNTP:
		if err := t.connectNTP(); err != nil {
			return err
		}
		return nil
	default:
		return fmt.Errorf("unknown service: %s", service)
	}
}

// Close closes all gRPC connections.
func (t *HTTP2Transport) Close() error {
	var errs []string

	if t.dnsConn != nil {
		if err := t.dnsConn.Close(); err != nil {
			errs = append(errs, fmt.Sprintf("DNS: %v", err))
		}
		t.dnsConn = nil
	}

	if t.dhcpConn != nil {
		if err := t.dhcpConn.Close(); err != nil {
			errs = append(errs, fmt.Sprintf("DHCP: %v", err))
		}
		t.dhcpConn = nil
	}

	if t.ntpConn != nil {
		if err := t.ntpConn.Close(); err != nil {
			errs = append(errs, fmt.Sprintf("NTP: %v", err))
		}
		t.ntpConn = nil
	}

	if len(errs) > 0 {
		return fmt.Errorf("errors closing gRPC connections: %s", strings.Join(errs, "; "))
	}

	return nil
}
