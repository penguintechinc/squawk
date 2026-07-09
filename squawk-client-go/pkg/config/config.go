package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/penguintechinc/squawk/squawk-client-go/pkg/client"
	"github.com/penguintechinc/squawk/squawk-client-go/pkg/forwarder"
	timeservice "github.com/penguintechinc/squawk/squawk-client-go/pkg/time"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

// LicenseConfig holds license validation configuration
type LicenseConfig struct {
	ServerURL      string `yaml:"server_url" json:"server_url"`
	LicenseKey     string `yaml:"license_key" json:"license_key"`
	UserToken      string `yaml:"user_token" json:"user_token"`
	ValidateOnline bool   `yaml:"validate_online" json:"validate_online"`
	CacheTime      int    `yaml:"cache_time" json:"cache_time"` // minutes
}

// TimeConfig holds NTP client and forwarder configuration
type TimeConfig struct {
	Enabled       bool                         `yaml:"enabled" json:"enabled"`
	Client        *timeservice.ClientConfig    `yaml:"client" json:"client"`
	Forwarder     *timeservice.ForwarderConfig `yaml:"forwarder" json:"forwarder"`
}

// FeaturesConfig holds the enabled features configuration
type FeaturesConfig struct {
	DNS  bool `yaml:"dns" json:"dns"`
	DHCP bool `yaml:"dhcp" json:"dhcp"`
	NTP  bool `yaml:"ntp" json:"ntp"`
}

// TransportConfig holds the transport/communication mode configuration
type TransportConfig struct {
	Mode string `yaml:"mode" json:"mode"` // http1, http2, http3
}

// DHCPConfig holds the DHCP client configuration
type DHCPConfig struct {
	ServerURL       string `yaml:"server_url" json:"server_url"`
	Interface       string `yaml:"interface" json:"interface"`
	EnableIntercept bool   `yaml:"enable_intercept" json:"enable_intercept"`
	LeaseFile       string `yaml:"lease_file" json:"lease_file"`
	ListenPort      int    `yaml:"listen_port" json:"listen_port"`
}

// NTPConfig holds the NTP/NTS client configuration
type NTPConfig struct {
	ServerURL       string `yaml:"server_url" json:"server_url"`
	ListenPort      int    `yaml:"listen_port" json:"listen_port"`
	SyncInterval    int    `yaml:"sync_interval" json:"sync_interval"` // seconds
	EnableIntercept bool   `yaml:"enable_intercept" json:"enable_intercept"`
	NTSKEPort       int    `yaml:"nts_ke_port" json:"nts_ke_port"` // NTS Key Establishment port
}

// AppConfig holds the complete application configuration
type AppConfig struct {
	Domain       string           `yaml:"domain" json:"domain"`
	RecordType   string           `yaml:"record_type" json:"record_type"`
	Client       *client.Config   `yaml:"client" json:"client"`
	Forwarder    *forwarder.Config `yaml:"forwarder" json:"forwarder"`
	License      *LicenseConfig   `yaml:"license" json:"license"`
	Time         *TimeConfig      `yaml:"time" json:"time"`
	LogLevel     string           `yaml:"log_level" json:"log_level"`
	Features     *FeaturesConfig  `yaml:"features" json:"features"`
	Transport    *TransportConfig `yaml:"transport" json:"transport"`
	DHCP         *DHCPConfig      `yaml:"dhcp" json:"dhcp"`
	NTP          *NTPConfig       `yaml:"ntp" json:"ntp"`
}

// DefaultConfig returns a configuration with sensible defaults
func DefaultConfig() *AppConfig {
	return &AppConfig{
		Domain:     "",
		RecordType: "A",
		LogLevel:   "INFO",
		Client: &client.Config{
			ServerURL:   "https://dns.google/resolve",
			ServerURLs:  []string{},
			AuthToken:   "",
			ClientCert:  "",
			ClientKey:   "",
			CaCert:      "",
			VerifySSL:   true,
			MaxRetries:  0, // Will be set to len(servers) * 2 by default
			RetryDelay:  2, // seconds
		},
		Forwarder: &forwarder.Config{
			UDPAddress: "127.0.0.1:53",
			TCPAddress: "127.0.0.1:53",
			ListenUDP:  false,
			ListenTCP:  false,
		},
		License: &LicenseConfig{
			ServerURL:      "https://license.squawkdns.com",
			LicenseKey:     "",
			UserToken:      "",
			ValidateOnline: true,
			CacheTime:      1440, // 24 hours (daily validation)
		},
		Time: &TimeConfig{
			Enabled: false,
			Client: &timeservice.ClientConfig{
				ServerURLs: []string{
					"pool.ntp.org:123",
					"time.google.com:123",
					"time.cloudflare.com:123",
				},
				Timeout:    5,
				MaxRetries: 6,
				RetryDelay: 1,
			},
			Forwarder: &timeservice.ForwarderConfig{
				ListenAddress: "127.0.0.1:123",
				CacheTTL:      60,
			},
		},
		Features: &FeaturesConfig{
			DNS:  true,  // DNS enabled by default
			DHCP: false, // DHCP disabled by default
			NTP:  false, // NTP disabled by default
		},
		Transport: &TransportConfig{
			Mode: "http2", // Default to http2
		},
		DHCP: &DHCPConfig{
			ServerURL:       "",
			Interface:       "",
			EnableIntercept: false,
			LeaseFile:       "/var/lib/squawk/dhcp.leases",
			ListenPort:      68,
		},
		NTP: &NTPConfig{
			ServerURL:       "",
			ListenPort:      123,
			SyncInterval:    3600, // 1 hour
			EnableIntercept: false,
			NTSKEPort:       4460,
		},
	}
}

// LoadConfig loads configuration from file, environment variables, and defaults
func LoadConfig(configFile string) (*AppConfig, error) {
	config := DefaultConfig()

	// Load from config file if provided
	if configFile != "" {
		if err := loadFromFile(configFile, config); err != nil {
			return nil, fmt.Errorf("failed to load config file: %w", err)
		}
	}

	// Override with environment variables
	loadFromEnv(config)

	// Validate configuration
	if err := validateConfig(config); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return config, nil
}

// loadFromFile loads configuration from a YAML file
func loadFromFile(filename string, config *AppConfig) error {
	// Validate filename to prevent directory traversal attacks
	if strings.Contains(filename, "..") {
		return fmt.Errorf("invalid filename: directory traversal not allowed")
	}
	
	// #nosec G304 - This reads user-specified config files, validated against directory traversal
	data, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	if err := yaml.Unmarshal(data, config); err != nil {
		return fmt.Errorf("failed to parse config file: %w", err)
	}

	return nil
}

// loadFromEnv loads configuration from environment variables
func loadFromEnv(config *AppConfig) {
	// Initialize viper for environment variable handling
	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	// Main configuration
	if domain := os.Getenv("SQUAWK_DOMAIN"); domain != "" {
		config.Domain = domain
	}
	if recordType := os.Getenv("SQUAWK_RECORD_TYPE"); recordType != "" {
		config.RecordType = recordType
	}
	if logLevel := os.Getenv("LOG_LEVEL"); logLevel != "" {
		config.LogLevel = logLevel
	}

	// Client configuration
	if serverURL := os.Getenv("SQUAWK_SERVER_URL"); serverURL != "" {
		config.Client.ServerURL = serverURL
	}
	
	// Multiple server URLs (comma-separated)
	if serverURLs := os.Getenv("SQUAWK_SERVER_URLS"); serverURLs != "" {
		urls := strings.Split(serverURLs, ",")
		for i, url := range urls {
			urls[i] = strings.TrimSpace(url)
		}
		config.Client.ServerURLs = urls
	}
	
	// Retry configuration
	if maxRetries := os.Getenv("SQUAWK_MAX_RETRIES"); maxRetries != "" {
		if retries, err := strconv.Atoi(maxRetries); err == nil && retries > 0 {
			config.Client.MaxRetries = retries
		}
	}
	
	if retryDelay := os.Getenv("SQUAWK_RETRY_DELAY"); retryDelay != "" {
		if delay, err := strconv.Atoi(retryDelay); err == nil && delay > 0 {
			config.Client.RetryDelay = delay
		}
	}
	if authToken := os.Getenv("SQUAWK_AUTH_TOKEN"); authToken != "" {
		config.Client.AuthToken = authToken
	}
	if clientCert := os.Getenv("SQUAWK_CLIENT_CERT"); clientCert != "" {
		config.Client.ClientCert = clientCert
	}
	// Support legacy environment variable names
	if clientCert := os.Getenv("CLIENT_CERT_PATH"); clientCert != "" {
		config.Client.ClientCert = clientCert
	}
	
	if clientKey := os.Getenv("SQUAWK_CLIENT_KEY"); clientKey != "" {
		config.Client.ClientKey = clientKey
	}
	// Support legacy environment variable names
	if clientKey := os.Getenv("CLIENT_KEY_PATH"); clientKey != "" {
		config.Client.ClientKey = clientKey
	}
	
	if caCert := os.Getenv("SQUAWK_CA_CERT"); caCert != "" {
		config.Client.CaCert = caCert
	}
	// Support legacy environment variable names
	if caCert := os.Getenv("CA_CERT_PATH"); caCert != "" {
		config.Client.CaCert = caCert
	}
	
	if verifySSL := os.Getenv("SQUAWK_VERIFY_SSL"); verifySSL != "" {
		if val, err := strconv.ParseBool(verifySSL); err == nil {
			config.Client.VerifySSL = val
		}
	}

	// Forwarder configuration
	if udpAddr := os.Getenv("SQUAWK_UDP_ADDRESS"); udpAddr != "" {
		config.Forwarder.UDPAddress = udpAddr
	}
	if tcpAddr := os.Getenv("SQUAWK_TCP_ADDRESS"); tcpAddr != "" {
		config.Forwarder.TCPAddress = tcpAddr
	}
	if listenUDP := os.Getenv("SQUAWK_LISTEN_UDP"); listenUDP != "" {
		if val, err := strconv.ParseBool(listenUDP); err == nil {
			config.Forwarder.ListenUDP = val
		}
	}
	if listenTCP := os.Getenv("SQUAWK_LISTEN_TCP"); listenTCP != "" {
		if val, err := strconv.ParseBool(listenTCP); err == nil {
			config.Forwarder.ListenTCP = val
		}
	}

	// License configuration
	if licenseServerURL := os.Getenv("SQUAWK_LICENSE_SERVER_URL"); licenseServerURL != "" {
		config.License.ServerURL = licenseServerURL
	}
	if licenseKey := os.Getenv("SQUAWK_LICENSE_KEY"); licenseKey != "" {
		config.License.LicenseKey = licenseKey
	}
	if userToken := os.Getenv("SQUAWK_USER_TOKEN"); userToken != "" {
		config.License.UserToken = userToken
	}
	if validateOnline := os.Getenv("SQUAWK_VALIDATE_ONLINE"); validateOnline != "" {
		if val, err := strconv.ParseBool(validateOnline); err == nil {
			config.License.ValidateOnline = val
		}
	}
	if cacheTime := os.Getenv("SQUAWK_LICENSE_CACHE_TIME"); cacheTime != "" {
		if val, err := strconv.Atoi(cacheTime); err == nil && val > 0 {
			config.License.CacheTime = val
		}
	}

	// Time/NTP configuration
	if timeEnabled := os.Getenv("SQUAWK_TIME_ENABLED"); timeEnabled != "" {
		if val, err := strconv.ParseBool(timeEnabled); err == nil {
			config.Time.Enabled = val
		}
	}
	if ntpServers := os.Getenv("SQUAWK_NTP_SERVERS"); ntpServers != "" {
		servers := strings.Split(ntpServers, ",")
		for i, server := range servers {
			servers[i] = strings.TrimSpace(server)
		}
		config.Time.Client.ServerURLs = servers
	}
	if ntpTimeout := os.Getenv("SQUAWK_NTP_TIMEOUT"); ntpTimeout != "" {
		if val, err := strconv.Atoi(ntpTimeout); err == nil && val > 0 {
			config.Time.Client.Timeout = val
		}
	}
	if ntpListenAddr := os.Getenv("SQUAWK_NTP_LISTEN_ADDRESS"); ntpListenAddr != "" {
		config.Time.Forwarder.ListenAddress = ntpListenAddr
	}
	if ntpCacheTTL := os.Getenv("SQUAWK_NTP_CACHE_TTL"); ntpCacheTTL != "" {
		if val, err := strconv.Atoi(ntpCacheTTL); err == nil && val > 0 {
			config.Time.Forwarder.CacheTTL = val
		}
	}

	// Features configuration
	if features := os.Getenv("SQUAWK_FEATURES"); features != "" {
		// Reset features to false first
		config.Features.DNS = false
		config.Features.DHCP = false
		config.Features.NTP = false
		// Parse comma-separated features
		for _, feature := range strings.Split(features, ",") {
			feature = strings.TrimSpace(strings.ToLower(feature))
			switch feature {
			case "dns":
				config.Features.DNS = true
			case "dhcp":
				config.Features.DHCP = true
			case "ntp":
				config.Features.NTP = true
			}
		}
	}

	// Transport/Communication mode configuration
	if mode := os.Getenv("SQUAWK_COMMUNICATION"); mode != "" {
		config.Transport.Mode = strings.ToLower(strings.TrimSpace(mode))
	}

	// DHCP configuration
	if dhcpServerURL := os.Getenv("SQUAWK_DHCP_SERVER_URL"); dhcpServerURL != "" {
		config.DHCP.ServerURL = dhcpServerURL
	}
	if dhcpInterface := os.Getenv("SQUAWK_DHCP_INTERFACE"); dhcpInterface != "" {
		config.DHCP.Interface = dhcpInterface
	}
	if dhcpIntercept := os.Getenv("SQUAWK_DHCP_INTERCEPT"); dhcpIntercept != "" {
		if val, err := strconv.ParseBool(dhcpIntercept); err == nil {
			config.DHCP.EnableIntercept = val
		}
	}
	if dhcpLeaseFile := os.Getenv("SQUAWK_DHCP_LEASE_FILE"); dhcpLeaseFile != "" {
		config.DHCP.LeaseFile = dhcpLeaseFile
	}
	if dhcpListenPort := os.Getenv("SQUAWK_DHCP_LISTEN_PORT"); dhcpListenPort != "" {
		if val, err := strconv.Atoi(dhcpListenPort); err == nil && val > 0 {
			config.DHCP.ListenPort = val
		}
	}

	// NTP configuration
	if ntpServerURL := os.Getenv("SQUAWK_NTP_SERVER_URL"); ntpServerURL != "" {
		config.NTP.ServerURL = ntpServerURL
	}
	if ntpPort := os.Getenv("SQUAWK_NTP_PORT"); ntpPort != "" {
		if val, err := strconv.Atoi(ntpPort); err == nil && val > 0 {
			config.NTP.ListenPort = val
		}
	}
	if ntpSyncInterval := os.Getenv("SQUAWK_NTP_SYNC_INTERVAL"); ntpSyncInterval != "" {
		if val, err := strconv.Atoi(ntpSyncInterval); err == nil && val > 0 {
			config.NTP.SyncInterval = val
		}
	}
	if ntpIntercept := os.Getenv("SQUAWK_NTP_INTERCEPT"); ntpIntercept != "" {
		if val, err := strconv.ParseBool(ntpIntercept); err == nil {
			config.NTP.EnableIntercept = val
		}
	}
	if ntsKePort := os.Getenv("SQUAWK_NTS_KE_PORT"); ntsKePort != "" {
		if val, err := strconv.Atoi(ntsKePort); err == nil && val > 0 {
			config.NTP.NTSKEPort = val
		}
	}
}

// validateConfig validates the configuration
func validateConfig(config *AppConfig) error {
	if config == nil {
		return fmt.Errorf("configuration is nil")
	}

	if config.Client == nil {
		return fmt.Errorf("client configuration is required")
	}

	if config.Client.ServerURL == "" {
		return fmt.Errorf("server URL is required")
	}

	// Validate mTLS configuration
	if config.Client.ClientCert != "" && config.Client.ClientKey == "" {
		return fmt.Errorf("client key is required when client certificate is provided")
	}
	if config.Client.ClientKey != "" && config.Client.ClientCert == "" {
		return fmt.Errorf("client certificate is required when client key is provided")
	}

	// Check if certificate files exist
	if config.Client.ClientCert != "" {
		if _, err := os.Stat(config.Client.ClientCert); os.IsNotExist(err) {
			return fmt.Errorf("client certificate file not found: %s", config.Client.ClientCert)
		}
	}
	if config.Client.ClientKey != "" {
		if _, err := os.Stat(config.Client.ClientKey); os.IsNotExist(err) {
			return fmt.Errorf("client key file not found: %s", config.Client.ClientKey)
		}
	}
	if config.Client.CaCert != "" {
		if _, err := os.Stat(config.Client.CaCert); os.IsNotExist(err) {
			return fmt.Errorf("CA certificate file not found: %s", config.Client.CaCert)
		}
	}

	// License validation
	if config.License == nil {
		return fmt.Errorf("license configuration is required")
	}

	// License is optional for backward compatibility
	// Missing license will be handled at runtime with appropriate warnings

	return nil
}

// SaveConfig saves the configuration to a YAML file
func SaveConfig(config *AppConfig, filename string) error {
	data, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(filename, data, 0600); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// GetEnvVarList returns a list of all supported environment variables
func GetEnvVarList() []string {
	return []string{
		"SQUAWK_DOMAIN",
		"SQUAWK_RECORD_TYPE",
		"SQUAWK_SERVER_URL",
		"SQUAWK_SERVER_URLS",
		"SQUAWK_MAX_RETRIES",
		"SQUAWK_RETRY_DELAY",
		"SQUAWK_AUTH_TOKEN",
		"SQUAWK_CLIENT_CERT",
		"SQUAWK_CLIENT_KEY",
		"SQUAWK_CA_CERT",
		"SQUAWK_VERIFY_SSL",
		"SQUAWK_UDP_ADDRESS",
		"SQUAWK_TCP_ADDRESS",
		"SQUAWK_LISTEN_UDP",
		"SQUAWK_LISTEN_TCP",
		"SQUAWK_LICENSE_SERVER_URL",
		"SQUAWK_LICENSE_KEY",
		"SQUAWK_USER_TOKEN",
		"SQUAWK_VALIDATE_ONLINE",
		"SQUAWK_LICENSE_CACHE_TIME",
		"SQUAWK_TIME_ENABLED",
		"SQUAWK_NTP_SERVERS",
		"SQUAWK_NTP_TIMEOUT",
		"SQUAWK_NTP_LISTEN_ADDRESS",
		"SQUAWK_NTP_CACHE_TTL",
		"LOG_LEVEL",
		// Features and Transport
		"SQUAWK_FEATURES",
		"SQUAWK_COMMUNICATION",
		// DHCP configuration
		"SQUAWK_DHCP_SERVER_URL",
		"SQUAWK_DHCP_INTERFACE",
		"SQUAWK_DHCP_INTERCEPT",
		"SQUAWK_DHCP_LEASE_FILE",
		"SQUAWK_DHCP_LISTEN_PORT",
		// NTP configuration
		"SQUAWK_NTP_SERVER_URL",
		"SQUAWK_NTP_PORT",
		"SQUAWK_NTP_SYNC_INTERVAL",
		"SQUAWK_NTP_INTERCEPT",
		"SQUAWK_NTS_KE_PORT",
		// Legacy support
		"CLIENT_CERT_PATH",
		"CLIENT_KEY_PATH",
		"CA_CERT_PATH",
	}
}

// PrintConfig prints the configuration in a human-readable format
func (c *AppConfig) String() string {
	var sb strings.Builder

	sb.WriteString("Squawk DNS Client Configuration:\n")
	sb.WriteString("================================\n")
	sb.WriteString(fmt.Sprintf("Domain: %s\n", c.Domain))
	sb.WriteString(fmt.Sprintf("Record Type: %s\n", c.RecordType))
	sb.WriteString(fmt.Sprintf("Log Level: %s\n", c.LogLevel))
	sb.WriteString("\nClient Configuration:\n")
	sb.WriteString(fmt.Sprintf("  Server URL: %s\n", c.Client.ServerURL))
	sb.WriteString(fmt.Sprintf("  Auth Token: %s\n", maskToken(c.Client.AuthToken)))
	sb.WriteString(fmt.Sprintf("  Client Cert: %s\n", c.Client.ClientCert))
	sb.WriteString(fmt.Sprintf("  Client Key: %s\n", c.Client.ClientKey))
	sb.WriteString(fmt.Sprintf("  CA Cert: %s\n", c.Client.CaCert))
	sb.WriteString(fmt.Sprintf("  Verify SSL: %t\n", c.Client.VerifySSL))
	sb.WriteString("\nForwarder Configuration:\n")
	sb.WriteString(fmt.Sprintf("  UDP Address: %s (Listen: %t)\n", c.Forwarder.UDPAddress, c.Forwarder.ListenUDP))
	sb.WriteString(fmt.Sprintf("  TCP Address: %s (Listen: %t)\n", c.Forwarder.TCPAddress, c.Forwarder.ListenTCP))
	sb.WriteString("\nLicense Configuration:\n")
	sb.WriteString(fmt.Sprintf("  Server URL: %s\n", c.License.ServerURL))
	sb.WriteString(fmt.Sprintf("  License Key: %s\n", maskToken(c.License.LicenseKey)))
	sb.WriteString(fmt.Sprintf("  User Token: %s\n", maskToken(c.License.UserToken)))
	sb.WriteString(fmt.Sprintf("  Validate Online: %t\n", c.License.ValidateOnline))
	sb.WriteString(fmt.Sprintf("  Cache Time: %d minutes\n", c.License.CacheTime))
	sb.WriteString("\nTime/NTP Configuration:\n")
	sb.WriteString(fmt.Sprintf("  Enabled: %t\n", c.Time.Enabled))
	sb.WriteString(fmt.Sprintf("  NTP Servers: %v\n", c.Time.Client.ServerURLs))
	sb.WriteString(fmt.Sprintf("  Timeout: %d seconds\n", c.Time.Client.Timeout))
	sb.WriteString(fmt.Sprintf("  Listen Address: %s\n", c.Time.Forwarder.ListenAddress))
	sb.WriteString(fmt.Sprintf("  Cache TTL: %d seconds\n", c.Time.Forwarder.CacheTTL))
	sb.WriteString("\nFeatures Configuration:\n")
	sb.WriteString(fmt.Sprintf("  DNS: %t\n", c.Features.DNS))
	sb.WriteString(fmt.Sprintf("  DHCP: %t\n", c.Features.DHCP))
	sb.WriteString(fmt.Sprintf("  NTP: %t\n", c.Features.NTP))
	sb.WriteString("\nTransport Configuration:\n")
	sb.WriteString(fmt.Sprintf("  Mode: %s\n", c.Transport.Mode))
	if c.Features.DHCP {
		sb.WriteString("\nDHCP Configuration:\n")
		sb.WriteString(fmt.Sprintf("  Server URL: %s\n", c.DHCP.ServerURL))
		sb.WriteString(fmt.Sprintf("  Interface: %s\n", c.DHCP.Interface))
		sb.WriteString(fmt.Sprintf("  Enable Intercept: %t\n", c.DHCP.EnableIntercept))
		sb.WriteString(fmt.Sprintf("  Lease File: %s\n", c.DHCP.LeaseFile))
		sb.WriteString(fmt.Sprintf("  Listen Port: %d\n", c.DHCP.ListenPort))
	}
	if c.Features.NTP {
		sb.WriteString("\nNTP Configuration:\n")
		sb.WriteString(fmt.Sprintf("  Server URL: %s\n", c.NTP.ServerURL))
		sb.WriteString(fmt.Sprintf("  Listen Port: %d\n", c.NTP.ListenPort))
		sb.WriteString(fmt.Sprintf("  Sync Interval: %d seconds\n", c.NTP.SyncInterval))
		sb.WriteString(fmt.Sprintf("  Enable Intercept: %t\n", c.NTP.EnableIntercept))
		sb.WriteString(fmt.Sprintf("  NTS-KE Port: %d\n", c.NTP.NTSKEPort))
	}

	return sb.String()
}

// maskToken masks the authentication token for display purposes
func maskToken(token string) string {
	if token == "" {
		return "(not set)"
	}
	if len(token) <= 8 {
		return strings.Repeat("*", len(token))
	}
	return token[:4] + strings.Repeat("*", len(token)-8) + token[len(token)-4:]
}