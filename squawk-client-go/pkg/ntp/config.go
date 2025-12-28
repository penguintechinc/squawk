// Package ntp provides NTS (Network Time Security, RFC 8915) client functionality
// with local NTP port intercept support.
package ntp

import "time"

// Config holds the NTP/NTS client configuration.
type Config struct {
	// ServerURL is the NTP/NTS server URL (e.g., https://ntp.example.com:8082)
	ServerURL string `yaml:"server_url" json:"server_url"`

	// ListenPort is the local NTP port to intercept (default: 123)
	ListenPort int `yaml:"listen_port" json:"listen_port"`

	// SyncInterval is the time between NTP synchronizations in seconds
	SyncInterval int `yaml:"sync_interval" json:"sync_interval"`

	// EnableIntercept enables local NTP port interception
	EnableIntercept bool `yaml:"enable_intercept" json:"enable_intercept"`

	// NTSKEPort is the NTS Key Establishment port (default: 4460)
	NTSKEPort int `yaml:"nts_ke_port" json:"nts_ke_port"`

	// AuthToken is the authentication token for the NTP server
	AuthToken string `yaml:"auth_token" json:"auth_token"`

	// TLS configuration
	ClientCert string `yaml:"client_cert" json:"client_cert"`
	ClientKey  string `yaml:"client_key" json:"client_key"`
	CACert     string `yaml:"ca_cert" json:"ca_cert"`
	VerifySSL  bool   `yaml:"verify_ssl" json:"verify_ssl"`

	// Timeouts
	RequestTimeout time.Duration `yaml:"request_timeout" json:"request_timeout"`
	KETimeout      time.Duration `yaml:"ke_timeout" json:"ke_timeout"` // NTS-KE timeout

	// Key refresh interval (when to re-establish NTS keys)
	KeyRefreshInterval time.Duration `yaml:"key_refresh_interval" json:"key_refresh_interval"`
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		ListenPort:         123,
		SyncInterval:       3600, // 1 hour
		EnableIntercept:    false,
		NTSKEPort:          4460,
		VerifySSL:          true,
		RequestTimeout:     10 * time.Second,
		KETimeout:          30 * time.Second,
		KeyRefreshInterval: 24 * time.Hour,
	}
}

// NTSKeyMaterial holds the cryptographic keys from NTS-KE.
type NTSKeyMaterial struct {
	// C2S is the client-to-server key
	C2S []byte `json:"c2s"`

	// S2C is the server-to-client key
	S2C []byte `json:"s2c"`

	// Cookies for NTS-protected NTP requests
	Cookies [][]byte `json:"cookies"`

	// NTPServer is the NTP server address
	NTPServer string `json:"ntp_server"`

	// NTPPort is the NTP server port
	NTPPort int `json:"ntp_port"`

	// AEADAlgorithm is the AEAD algorithm ID
	AEADAlgorithm uint16 `json:"aead_algorithm"`

	// ExpiresAt is when the key material expires
	ExpiresAt time.Time `json:"expires_at"`
}

// IsExpired returns true if the key material has expired.
func (k *NTSKeyMaterial) IsExpired() bool {
	return time.Now().After(k.ExpiresAt)
}

// NeedsRefresh returns true if the key material should be refreshed.
func (k *NTSKeyMaterial) NeedsRefresh(buffer time.Duration) bool {
	return time.Now().Add(buffer).After(k.ExpiresAt)
}

// HasCookies returns true if there are cookies available.
func (k *NTSKeyMaterial) HasCookies() bool {
	return len(k.Cookies) > 0
}

// ConsumeCookie returns and removes a cookie from the pool.
func (k *NTSKeyMaterial) ConsumeCookie() []byte {
	if len(k.Cookies) == 0 {
		return nil
	}
	cookie := k.Cookies[0]
	k.Cookies = k.Cookies[1:]
	return cookie
}

// AddCookie adds a cookie to the pool (from server response).
func (k *NTSKeyMaterial) AddCookie(cookie []byte) {
	k.Cookies = append(k.Cookies, cookie)
}

// AEAD algorithms (from RFC 8915)
const (
	AEAD_AES_SIV_CMAC_256 uint16 = 15
	AEAD_AES_SIV_CMAC_384 uint16 = 16
	AEAD_AES_SIV_CMAC_512 uint16 = 17
)

// TimeResult represents the result of an NTP query.
type TimeResult struct {
	// Time is the synchronized time
	Time time.Time `json:"time"`

	// Offset is the difference between local and server time
	Offset time.Duration `json:"offset"`

	// Delay is the round-trip delay
	Delay time.Duration `json:"delay"`

	// Stratum is the server stratum
	Stratum int `json:"stratum"`

	// Precision is the server precision
	Precision int `json:"precision"`

	// ReferenceID identifies the reference clock
	ReferenceID string `json:"reference_id"`

	// Authenticated indicates if NTS authentication was used
	Authenticated bool `json:"authenticated"`
}

// NTPPacket represents an NTP packet structure.
type NTPPacket struct {
	Settings       byte  // LI, VN, Mode
	Stratum        byte
	Poll           byte
	Precision      int8
	RootDelay      uint32
	RootDispersion uint32
	ReferenceID    uint32
	RefTimeSec     uint32
	RefTimeFrac    uint32
	OrigTimeSec    uint32
	OrigTimeFrac   uint32
	RxTimeSec      uint32
	RxTimeFrac     uint32
	TxTimeSec      uint32
	TxTimeFrac     uint32
}

// NTS Extension Field types (from RFC 8915)
const (
	NTSExtUniqueIdentifier       uint16 = 0x0104
	NTSExtNTSCookie              uint16 = 0x0204
	NTSExtNTSCookiePlaceholder   uint16 = 0x0304
	NTSExtNTSAuthenticatorAndEEF uint16 = 0x0404
)

// NTSExtensionField represents an NTS extension field.
type NTSExtensionField struct {
	Type   uint16
	Length uint16
	Data   []byte
}
