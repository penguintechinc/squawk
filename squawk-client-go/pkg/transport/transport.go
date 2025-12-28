// Package transport provides a unified interface for different communication protocols.
// It abstracts HTTP/1.1 (REST), HTTP/2 (gRPC), and HTTP/3 (QUIC) transports.
package transport

import (
	"context"
	"crypto/tls"
	"fmt"
	"time"
)

// Mode represents the communication protocol mode.
type Mode string

const (
	// ModeHTTP1 uses HTTP/1.1 REST API
	ModeHTTP1 Mode = "http1"
	// ModeHTTP2 uses HTTP/2 gRPC
	ModeHTTP2 Mode = "http2"
	// ModeHTTP3 uses HTTP/3 QUIC
	ModeHTTP3 Mode = "http3"
)

// Service represents a backend service type.
type Service string

const (
	// ServiceDNS is the DNS service
	ServiceDNS Service = "dns"
	// ServiceDHCP is the DHCP service
	ServiceDHCP Service = "dhcp"
	// ServiceNTP is the NTP service
	ServiceNTP Service = "ntp"
)

// Config holds the transport configuration.
type Config struct {
	// Mode is the communication protocol (http1, http2, http3)
	Mode Mode `yaml:"mode" json:"mode"`

	// Service URLs for each backend service
	DNSServerURL  string `yaml:"dns_server_url" json:"dns_server_url"`
	DHCPServerURL string `yaml:"dhcp_server_url" json:"dhcp_server_url"`
	NTPServerURL  string `yaml:"ntp_server_url" json:"ntp_server_url"`

	// Authentication
	AuthToken string `yaml:"auth_token" json:"auth_token"`

	// TLS Configuration
	TLSConfig  *tls.Config `yaml:"-" json:"-"`
	ClientCert string      `yaml:"client_cert" json:"client_cert"`
	ClientKey  string      `yaml:"client_key" json:"client_key"`
	CACert     string      `yaml:"ca_cert" json:"ca_cert"`
	VerifySSL  bool        `yaml:"verify_ssl" json:"verify_ssl"`

	// Timeouts
	ConnectTimeout time.Duration `yaml:"connect_timeout" json:"connect_timeout"`
	RequestTimeout time.Duration `yaml:"request_timeout" json:"request_timeout"`
	IdleTimeout    time.Duration `yaml:"idle_timeout" json:"idle_timeout"`

	// Connection settings
	MaxRetries      int `yaml:"max_retries" json:"max_retries"`
	MaxIdleConns    int `yaml:"max_idle_conns" json:"max_idle_conns"`
	MaxConnsPerHost int `yaml:"max_conns_per_host" json:"max_conns_per_host"`

	// QUIC-specific settings (HTTP/3)
	QUICKeepAlive time.Duration `yaml:"quic_keep_alive" json:"quic_keep_alive"`
	QUICMaxStreams int64        `yaml:"quic_max_streams" json:"quic_max_streams"`
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		Mode:           ModeHTTP2, // Default to gRPC
		VerifySSL:      true,
		ConnectTimeout: 10 * time.Second,
		RequestTimeout: 30 * time.Second,
		IdleTimeout:    90 * time.Second,
		MaxRetries:     3,
		MaxIdleConns:   100,
		MaxConnsPerHost: 10,
		QUICKeepAlive:  15 * time.Second,
		QUICMaxStreams: 100,
	}
}

// DNSRequest represents a DNS query request.
type DNSRequest struct {
	Domain     string `json:"name"`
	RecordType string `json:"type"`
}

// DNSResponse represents a DNS query response.
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
}

// DNSRecord represents a DNS resource record.
type DNSRecord struct {
	Name string `json:"name"`
	Type int    `json:"type"`
	TTL  int    `json:"TTL"`
	Data string `json:"data"`
}

// DHCPDiscoverRequest represents a DHCP discover request.
type DHCPDiscoverRequest struct {
	MACAddress  string `json:"mac_address"`
	Hostname    string `json:"hostname,omitempty"`
	RequestedIP string `json:"requested_ip,omitempty"`
	ClientID    string `json:"client_id,omitempty"`
}

// DHCPOfferResponse represents a DHCP offer response.
type DHCPOfferResponse struct {
	Status        string   `json:"status"`
	OfferedIP     string   `json:"offered_ip"`
	SubnetMask    string   `json:"subnet_mask"`
	Gateway       string   `json:"gateway"`
	DNSServers    []string `json:"dns_servers"`
	LeaseTime     int      `json:"lease_time"`
	ServerID      string   `json:"server_id"`
	TransactionID string   `json:"transaction_id"`
}

// DHCPRequestMessage represents a DHCP request message.
type DHCPRequestMessage struct {
	MACAddress    string `json:"mac_address"`
	TransactionID string `json:"transaction_id"`
	RequestedIP   string `json:"requested_ip"`
	ServerID      string `json:"server_id"`
}

// DHCPAckResponse represents a DHCP ACK/NAK response.
type DHCPAckResponse struct {
	Status        string   `json:"status"` // "ack" or "nak"
	AssignedIP    string   `json:"assigned_ip"`
	SubnetMask    string   `json:"subnet_mask"`
	Gateway       string   `json:"gateway"`
	DNSServers    []string `json:"dns_servers"`
	LeaseTime     int      `json:"lease_time"`
	RenewalTime   int      `json:"renewal_time"`
	RebindingTime int      `json:"rebinding_time"`
	ErrorMessage  string   `json:"error_message,omitempty"`
}

// DHCPReleaseRequest represents a DHCP release request.
type DHCPReleaseRequest struct {
	MACAddress string `json:"mac_address"`
	ClientIP   string `json:"client_ip"`
}

// DHCPReleaseResponse represents a DHCP release response.
type DHCPReleaseResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// DHCPConfigResponse represents the DHCP configuration for REST API config pull.
type DHCPConfigResponse struct {
	AssignedIP    string   `json:"assigned_ip"`
	SubnetMask    string   `json:"subnet_mask"`
	Gateway       string   `json:"gateway"`
	DNSServers    []string `json:"dns_servers"`
	LeaseTime     int      `json:"lease_time"`
	RenewalTime   int      `json:"renewal_time"`
	LeaseStart    int64    `json:"lease_start"`
	LeaseEnd      int64    `json:"lease_end"`
	Status        string   `json:"status"`
}

// NTSKERequest represents an NTS Key Establishment request.
type NTSKERequest struct {
	SupportedAlgorithms []uint16 `json:"supported_algorithms"`
	NextProtocol        string   `json:"next_protocol"` // "ntske/1"
}

// NTSKEResponse represents an NTS Key Establishment response.
type NTSKEResponse struct {
	Success       bool     `json:"success"`
	C2SKey        []byte   `json:"c2s_key"`
	S2CKey        []byte   `json:"s2c_key"`
	Cookies       [][]byte `json:"cookies"`
	NTPServer     string   `json:"ntp_server"`
	NTPPort       int      `json:"ntp_port"`
	AEADAlgorithm uint16   `json:"aead_algorithm"`
	ExpiresAt     int64    `json:"expires_at"`
	ErrorMessage  string   `json:"error_message,omitempty"`
}

// NTPRequest represents an NTP query request.
type NTPRequest struct {
	Cookie          []byte `json:"cookie"`
	UniqueID        []byte `json:"unique_id"`
	ClientTransmit  int64  `json:"client_transmit"`
	Authenticator   []byte `json:"authenticator,omitempty"`
}

// NTPResponse represents an NTP query response.
type NTPResponse struct {
	LeapIndicator      int    `json:"leap_indicator"`
	Stratum            int    `json:"stratum"`
	Precision          int    `json:"precision"`
	ReferenceTimestamp int64  `json:"reference_timestamp"`
	OriginTimestamp    int64  `json:"origin_timestamp"`
	ReceiveTimestamp   int64  `json:"receive_timestamp"`
	TransmitTimestamp  int64  `json:"transmit_timestamp"`
	Cookie             []byte `json:"cookie,omitempty"`
	Authenticator      []byte `json:"authenticator,omitempty"`
}

// TimeResponse represents a simple time response.
type TimeResponse struct {
	Timestamp  int64   `json:"timestamp"` // Unix timestamp in nanoseconds
	Stratum    int     `json:"stratum"`
	AccuracyNS float64 `json:"accuracy_ns"`
}

// Transport defines the interface for all transport implementations.
type Transport interface {
	// DNS operations
	DNSQuery(ctx context.Context, req *DNSRequest) (*DNSResponse, error)

	// DHCP operations
	DHCPDiscover(ctx context.Context, req *DHCPDiscoverRequest) (*DHCPOfferResponse, error)
	DHCPRequest(ctx context.Context, req *DHCPRequestMessage) (*DHCPAckResponse, error)
	DHCPRelease(ctx context.Context, req *DHCPReleaseRequest) (*DHCPReleaseResponse, error)
	DHCPGetConfig(ctx context.Context, macAddress string) (*DHCPConfigResponse, error)

	// NTP operations
	NTSKeyEstablishment(ctx context.Context, req *NTSKERequest) (*NTSKEResponse, error)
	NTPQuery(ctx context.Context, req *NTPRequest) (*NTPResponse, error)
	NTPGetTime(ctx context.Context) (*TimeResponse, error)

	// Health check
	HealthCheck(ctx context.Context, service Service) error

	// Connection management
	Close() error
}

// New creates a new Transport based on the configuration mode.
func New(cfg *Config) (Transport, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	switch cfg.Mode {
	case ModeHTTP1:
		return NewHTTP1Transport(cfg)
	case ModeHTTP2:
		return NewHTTP2Transport(cfg)
	case ModeHTTP3:
		return NewHTTP3Transport(cfg)
	default:
		return nil, fmt.Errorf("unsupported transport mode: %s", cfg.Mode)
	}
}

// ParseMode parses a string into a Mode.
func ParseMode(s string) (Mode, error) {
	switch s {
	case "http1", "rest", "HTTP1", "REST":
		return ModeHTTP1, nil
	case "http2", "grpc", "HTTP2", "GRPC", "gRPC":
		return ModeHTTP2, nil
	case "http3", "quic", "HTTP3", "QUIC":
		return ModeHTTP3, nil
	default:
		return "", fmt.Errorf("unknown transport mode: %s (valid: http1, http2, http3)", s)
	}
}
