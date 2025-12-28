// Package dhcp provides DHCP-over-HTTPS client functionality with local intercept support.
package dhcp

import "time"

// Config holds the DHCP client configuration.
type Config struct {
	// ServerURL is the DHCP server URL (e.g., https://dhcp.example.com:8081)
	ServerURL string `yaml:"server_url" json:"server_url"`

	// Interface is the network interface for DHCP intercept
	Interface string `yaml:"interface" json:"interface"`

	// EnableIntercept enables local DHCP port interception
	EnableIntercept bool `yaml:"enable_intercept" json:"enable_intercept"`

	// LeaseFile is the path to store persistent lease information
	LeaseFile string `yaml:"lease_file" json:"lease_file"`

	// ListenPort is the DHCP client port (default: 68)
	ListenPort int `yaml:"listen_port" json:"listen_port"`

	// AuthToken is the authentication token for the DHCP server
	AuthToken string `yaml:"auth_token" json:"auth_token"`

	// TLS configuration
	ClientCert string `yaml:"client_cert" json:"client_cert"`
	ClientKey  string `yaml:"client_key" json:"client_key"`
	CACert     string `yaml:"ca_cert" json:"ca_cert"`
	VerifySSL  bool   `yaml:"verify_ssl" json:"verify_ssl"`

	// Timeouts
	RequestTimeout time.Duration `yaml:"request_timeout" json:"request_timeout"`
	RenewalBuffer  time.Duration `yaml:"renewal_buffer" json:"renewal_buffer"` // Time before lease expires to start renewal
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		ListenPort:     68,
		LeaseFile:      "/var/lib/squawk/dhcp.leases",
		EnableIntercept: false,
		VerifySSL:      true,
		RequestTimeout: 30 * time.Second,
		RenewalBuffer:  60 * time.Second, // Start renewal 1 minute before expiry
	}
}

// Lease represents a DHCP lease.
type Lease struct {
	MACAddress    string    `json:"mac_address"`
	ClientIP      string    `json:"client_ip"`
	SubnetMask    string    `json:"subnet_mask"`
	Gateway       string    `json:"gateway"`
	DNSServers    []string  `json:"dns_servers"`
	Hostname      string    `json:"hostname"`
	LeaseTime     int       `json:"lease_time"`     // seconds
	RenewalTime   int       `json:"renewal_time"`   // seconds
	RebindingTime int       `json:"rebinding_time"` // seconds
	ServerID      string    `json:"server_id"`
	ObtainedAt    time.Time `json:"obtained_at"`
	ExpiresAt     time.Time `json:"expires_at"`
	Status        string    `json:"status"` // "active", "expired", "releasing"
}

// IsExpired returns true if the lease has expired.
func (l *Lease) IsExpired() bool {
	return time.Now().After(l.ExpiresAt)
}

// NeedsRenewal returns true if the lease should be renewed.
func (l *Lease) NeedsRenewal() bool {
	renewalTime := l.ObtainedAt.Add(time.Duration(l.RenewalTime) * time.Second)
	return time.Now().After(renewalTime)
}

// NeedsRebinding returns true if the lease should be rebound.
func (l *Lease) NeedsRebinding() bool {
	rebindTime := l.ObtainedAt.Add(time.Duration(l.RebindingTime) * time.Second)
	return time.Now().After(rebindTime)
}

// TimeRemaining returns the time remaining until lease expiration.
func (l *Lease) TimeRemaining() time.Duration {
	return time.Until(l.ExpiresAt)
}

// DHCPOption represents a DHCP option.
type DHCPOption struct {
	Code  int    `json:"code"`
	Name  string `json:"name"`
	Value string `json:"value"`
}
