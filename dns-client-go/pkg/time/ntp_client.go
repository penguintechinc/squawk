package time

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
)

// NTPClient represents a client for querying NTP time servers
type NTPClient struct {
	serverURLs    []string
	timeout       time.Duration
	maxRetries    int
	retryDelay    time.Duration
	currentIndex  int
	mu            sync.RWMutex
	lastOffset    time.Duration
	lastDelay     time.Duration
	lastSync      time.Time
	synchronized  bool
}

// ClientConfig holds the configuration for the NTP client
type ClientConfig struct {
	ServerURLs []string `yaml:"server_urls" json:"server_urls"`
	Timeout    int      `yaml:"timeout" json:"timeout"`       // seconds
	MaxRetries int      `yaml:"max_retries" json:"max_retries"`
	RetryDelay int      `yaml:"retry_delay" json:"retry_delay"` // seconds
}

// TimeResponse represents the result of a time query
type TimeResponse struct {
	ServerTime   time.Time     `json:"server_time"`
	LocalTime    time.Time     `json:"local_time"`
	Offset       time.Duration `json:"offset"`        // Difference between server and local time
	RoundTrip    time.Duration `json:"round_trip"`    // Round-trip delay
	Stratum      uint8         `json:"stratum"`       // NTP stratum level
	ServerAddr   string        `json:"server_addr"`   // Server that responded
	Synchronized bool          `json:"synchronized"`
}

// NTP packet structure (48 bytes)
type ntpPacket struct {
	Settings       uint8  // Leap indicator, version, mode
	Stratum        uint8  // Stratum level
	Poll           int8   // Poll interval
	Precision      int8   // Precision
	RootDelay      uint32 // Root delay
	RootDispersion uint32 // Root dispersion
	RefID          uint32 // Reference ID
	RefTimeSec     uint32 // Reference timestamp seconds
	RefTimeFrac    uint32 // Reference timestamp fraction
	OrigTimeSec    uint32 // Origin timestamp seconds
	OrigTimeFrac   uint32 // Origin timestamp fraction
	RxTimeSec      uint32 // Receive timestamp seconds
	RxTimeFrac     uint32 // Receive timestamp fraction
	TxTimeSec      uint32 // Transmit timestamp seconds
	TxTimeFrac     uint32 // Transmit timestamp fraction
}

const (
	// NTP epoch starts at 1900-01-01 00:00:00
	ntpEpochOffset = 2208988800

	// NTP packet size
	ntpPacketSize = 48

	// NTP version 4
	ntpVersion = 4

	// NTP client mode
	ntpModeClient = 3
)

// NewNTPClient creates a new NTP client
func NewNTPClient(config *ClientConfig) (*NTPClient, error) {
	if config == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}

	if len(config.ServerURLs) == 0 {
		// Default NTP servers
		config.ServerURLs = []string{
			"pool.ntp.org:123",
			"time.google.com:123",
			"time.cloudflare.com:123",
		}
	}

	// Validate server URLs
	for i, url := range config.ServerURLs {
		host, port, err := net.SplitHostPort(url)
		if err != nil {
			// Try adding default NTP port
			config.ServerURLs[i] = url + ":123"
		} else if port == "" {
			config.ServerURLs[i] = host + ":123"
		}
	}

	timeout := time.Duration(config.Timeout) * time.Second
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	maxRetries := config.MaxRetries
	if maxRetries <= 0 {
		maxRetries = len(config.ServerURLs) * 2
	}

	retryDelay := time.Duration(config.RetryDelay) * time.Second
	if retryDelay <= 0 {
		retryDelay = 1 * time.Second
	}

	return &NTPClient{
		serverURLs:   config.ServerURLs,
		timeout:      timeout,
		maxRetries:   maxRetries,
		retryDelay:   retryDelay,
		currentIndex: 0,
	}, nil
}

// Query performs an NTP query with automatic failover
func (c *NTPClient) Query(ctx context.Context) (*TimeResponse, error) {
	var lastErr error
	var errors []string

	for attempt := 0; attempt < c.maxRetries; attempt++ {
		c.mu.RLock()
		serverAddr := c.serverURLs[c.currentIndex]
		c.mu.RUnlock()

		resp, err := c.queryServer(ctx, serverAddr)
		if err != nil {
			lastErr = fmt.Errorf("NTP query failed for %s: %w", serverAddr, err)
			errors = append(errors, lastErr.Error())
			c.nextServer()

			// Add delay before next attempt
			if attempt < c.maxRetries-1 {
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-time.After(c.retryDelay):
				}
			}
			continue
		}

		// Update client state
		c.mu.Lock()
		c.lastOffset = resp.Offset
		c.lastDelay = resp.RoundTrip
		c.lastSync = time.Now()
		c.synchronized = true
		c.mu.Unlock()

		return resp, nil
	}

	// All servers failed
	c.mu.Lock()
	c.synchronized = false
	c.mu.Unlock()

	if len(errors) > 1 {
		return nil, fmt.Errorf("all NTP servers failed after %d attempts", c.maxRetries)
	}
	return nil, lastErr
}

// queryServer performs a single NTP query to the specified server
func (c *NTPClient) queryServer(ctx context.Context, serverAddr string) (*TimeResponse, error) {
	// Create deadline for the query
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(c.timeout)
	}

	// Resolve and connect to the NTP server
	conn, err := net.DialTimeout("udp", serverAddr, c.timeout)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to NTP server: %w", err)
	}
	defer conn.Close()

	if err := conn.SetDeadline(deadline); err != nil {
		return nil, fmt.Errorf("failed to set deadline: %w", err)
	}

	// Create NTP request packet
	req := &ntpPacket{
		Settings: (ntpVersion << 3) | ntpModeClient,
	}

	// Record the time we send the request (T1)
	t1 := time.Now()

	// Set origin timestamp in the packet
	setNTPTime(req, t1, true)

	// Send the request
	if err := sendNTPPacket(conn, req); err != nil {
		return nil, fmt.Errorf("failed to send NTP request: %w", err)
	}

	// Receive the response
	resp := &ntpPacket{}
	if err := recvNTPPacket(conn, resp); err != nil {
		return nil, fmt.Errorf("failed to receive NTP response: %w", err)
	}

	// Record the time we received the response (T4)
	t4 := time.Now()

	// Extract timestamps from response
	// T2: Server receive time, T3: Server transmit time
	t2 := ntpTimeToGoTime(resp.RxTimeSec, resp.RxTimeFrac)
	t3 := ntpTimeToGoTime(resp.TxTimeSec, resp.TxTimeFrac)

	// Calculate offset and delay using NTP algorithm
	// offset = ((T2 - T1) + (T3 - T4)) / 2
	// delay = (T4 - T1) - (T3 - T2)
	offset := (t2.Sub(t1) + t3.Sub(t4)) / 2
	delay := t4.Sub(t1) - t3.Sub(t2)

	return &TimeResponse{
		ServerTime:   t3,
		LocalTime:    t4,
		Offset:       offset,
		RoundTrip:    delay,
		Stratum:      resp.Stratum,
		ServerAddr:   serverAddr,
		Synchronized: true,
	}, nil
}

// nextServer advances to the next server in the list (round-robin)
func (c *NTPClient) nextServer() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.currentIndex = (c.currentIndex + 1) % len(c.serverURLs)
}

// GetStatus returns the current synchronization status
func (c *NTPClient) GetStatus() (synchronized bool, offset time.Duration, lastSync time.Time) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.synchronized, c.lastOffset, c.lastSync
}

// GetServerURLs returns the configured NTP server URLs
func (c *NTPClient) GetServerURLs() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return append([]string{}, c.serverURLs...)
}

// setNTPTime sets the timestamp in an NTP packet
func setNTPTime(pkt *ntpPacket, t time.Time, origin bool) {
	// Safe conversion with overflow check for NTP epoch (1900-2036)
	unixTime := t.Unix()
	if unixTime < -ntpEpochOffset || unixTime > (1<<32-ntpEpochOffset) {
		// Handle time outside valid NTP range - use current time as fallback
		unixTime = time.Now().Unix()
	}
	// Safe cast: unixTime + ntpEpochOffset is guaranteed to be in uint32 range by above check
	sec := uint32(unixTime + ntpEpochOffset) // #nosec G115 - validated range

	// Safe conversion for nanoseconds to fractional seconds
	nanos := t.Nanosecond()
	if nanos < 0 || nanos >= 1e9 {
		nanos = 0
	}
	// Safe cast: nanosecond is 0-999999999, multiplication and shift are safe
	frac := uint32((uint64(nanos) << 32) / 1e9) // #nosec G115 - validated range

	if origin {
		pkt.OrigTimeSec = sec
		pkt.OrigTimeFrac = frac
	} else {
		pkt.TxTimeSec = sec
		pkt.TxTimeFrac = frac
	}
}

// ntpTimeToGoTime converts NTP timestamp to Go time.Time
func ntpTimeToGoTime(sec, frac uint32) time.Time {
	// Convert NTP seconds to Unix seconds
	unixSec := int64(sec) - ntpEpochOffset

	// Convert NTP fraction to nanoseconds
	// Multiply in uint64 space before shifting to avoid overflow
	// Result is always < 1e9, safe for int64
	nsec := int64((uint64(frac) * 1e9) >> 32) // #nosec G115 - result < 1e9

	// Validate nanoseconds are in valid range
	if nsec < 0 || nsec >= 1e9 {
		nsec = 0
	}

	return time.Unix(unixSec, nsec)
}

// sendNTPPacket sends an NTP packet over the connection
func sendNTPPacket(conn net.Conn, pkt *ntpPacket) error {
	buf := make([]byte, ntpPacketSize)
	buf[0] = pkt.Settings
	buf[1] = pkt.Stratum
	buf[2] = byte(pkt.Poll)
	buf[3] = byte(pkt.Precision)

	// Encode origin timestamp
	encodeUint32(buf[24:28], pkt.OrigTimeSec)
	encodeUint32(buf[28:32], pkt.OrigTimeFrac)

	// Encode transmit timestamp (same as origin for client request)
	encodeUint32(buf[40:44], pkt.OrigTimeSec)
	encodeUint32(buf[44:48], pkt.OrigTimeFrac)

	_, err := conn.Write(buf)
	return err
}

// recvNTPPacket receives an NTP packet from the connection
func recvNTPPacket(conn net.Conn, pkt *ntpPacket) error {
	buf := make([]byte, ntpPacketSize)
	n, err := conn.Read(buf)
	if err != nil {
		return err
	}
	if n < ntpPacketSize {
		return fmt.Errorf("short NTP response: got %d bytes, expected %d", n, ntpPacketSize)
	}

	pkt.Settings = buf[0]
	pkt.Stratum = buf[1]
	pkt.Poll = int8(buf[2])
	pkt.Precision = int8(buf[3])
	pkt.RootDelay = decodeUint32(buf[4:8])
	pkt.RootDispersion = decodeUint32(buf[8:12])
	pkt.RefID = decodeUint32(buf[12:16])
	pkt.RefTimeSec = decodeUint32(buf[16:20])
	pkt.RefTimeFrac = decodeUint32(buf[20:24])
	pkt.OrigTimeSec = decodeUint32(buf[24:28])
	pkt.OrigTimeFrac = decodeUint32(buf[28:32])
	pkt.RxTimeSec = decodeUint32(buf[32:36])
	pkt.RxTimeFrac = decodeUint32(buf[36:40])
	pkt.TxTimeSec = decodeUint32(buf[40:44])
	pkt.TxTimeFrac = decodeUint32(buf[44:48])

	return nil
}

// encodeUint32 encodes a uint32 to big-endian bytes
func encodeUint32(buf []byte, v uint32) {
	buf[0] = byte(v >> 24)
	buf[1] = byte(v >> 16)
	buf[2] = byte(v >> 8)
	buf[3] = byte(v)
}

// decodeUint32 decodes big-endian bytes to uint32
func decodeUint32(buf []byte) uint32 {
	return uint32(buf[0])<<24 | uint32(buf[1])<<16 | uint32(buf[2])<<8 | uint32(buf[3])
}

// Close cleans up the NTP client resources
func (c *NTPClient) Close() error {
	// NTP client doesn't hold persistent connections
	return nil
}
