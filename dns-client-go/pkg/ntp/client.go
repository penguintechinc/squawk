package ntp

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/penguintechinc/squawk/dns-client-go/pkg/transport"
)

// NTP epoch offset (seconds between 1900 and 1970)
const ntpEpochOffset = 2208988800

// Client is an NTS (Network Time Security) client with local intercept support.
type Client struct {
	config      *Config
	transport   transport.Transport
	keManager   *KEManager
	interceptor *Interceptor
	lastSync    *TimeResult
	mu          sync.RWMutex
	stopCh      chan struct{}
	running     bool
}

// NewClient creates a new NTS client.
func NewClient(cfg *Config, t transport.Transport) (*Client, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	if t == nil {
		return nil, fmt.Errorf("transport is required")
	}

	c := &Client{
		config:    cfg,
		transport: t,
		keManager: NewKEManager(cfg, t),
		stopCh:    make(chan struct{}),
	}

	return c, nil
}

// Start starts the NTP client services.
func (c *Client) Start(ctx context.Context) error {
	c.mu.Lock()
	if c.running {
		c.mu.Unlock()
		return fmt.Errorf("NTP client is already running")
	}
	c.running = true
	c.mu.Unlock()

	// Establish NTS keys
	if _, err := c.keManager.EstablishKeys(ctx); err != nil {
		log.Printf("Warning: failed to establish NTS keys: %v", err)
		// Continue without NTS - will fall back to simple time queries
	}

	// Start interceptor if enabled
	if c.config.EnableIntercept {
		interceptor, err := NewInterceptor(c.config, c)
		if err != nil {
			return fmt.Errorf("failed to create NTP interceptor: %w", err)
		}
		c.interceptor = interceptor

		go func() {
			if err := interceptor.Start(ctx); err != nil {
				log.Printf("NTP interceptor error: %v", err)
			}
		}()
	}

	// Start sync loop
	go c.syncLoop(ctx)

	return nil
}

// Stop stops the NTP client services.
func (c *Client) Stop() error {
	c.mu.Lock()
	if !c.running {
		c.mu.Unlock()
		return nil
	}
	c.running = false
	c.mu.Unlock()

	close(c.stopCh)

	if c.interceptor != nil {
		if err := c.interceptor.Stop(); err != nil {
			return fmt.Errorf("failed to stop interceptor: %w", err)
		}
	}

	return nil
}

// Query performs an NTS-authenticated NTP query.
func (c *Client) Query(ctx context.Context) (*TimeResult, error) {
	// Refresh keys if needed
	if err := c.keManager.RefreshIfNeeded(ctx); err != nil {
		log.Printf("Warning: failed to refresh NTS keys: %v", err)
	}

	// If we have valid NTS keys, use authenticated query
	if c.keManager.HasValidKeys() {
		return c.queryWithNTS(ctx)
	}

	// Fall back to simple time query
	return c.querySimple(ctx)
}

// queryWithNTS performs an NTS-authenticated NTP query.
func (c *Client) queryWithNTS(ctx context.Context) (*TimeResult, error) {
	keyMaterial := c.keManager.GetKeyMaterial()
	if keyMaterial == nil {
		return nil, fmt.Errorf("no NTS key material available")
	}

	// Get a cookie
	cookie := keyMaterial.ConsumeCookie()
	if cookie == nil {
		// Need to refresh keys to get more cookies
		if _, err := c.keManager.EstablishKeys(ctx); err != nil {
			return nil, fmt.Errorf("failed to refresh NTS keys: %w", err)
		}
		keyMaterial = c.keManager.GetKeyMaterial()
		cookie = keyMaterial.ConsumeCookie()
		if cookie == nil {
			return nil, fmt.Errorf("no cookies available after refresh")
		}
	}

	// Generate unique ID for replay protection
	uniqueID := make([]byte, 32)
	if _, err := rand.Read(uniqueID); err != nil {
		return nil, fmt.Errorf("failed to generate unique ID: %w", err)
	}

	t1 := time.Now()

	req := &transport.NTPRequest{
		Cookie:         cookie,
		UniqueID:       uniqueID,
		ClientTransmit: t1.UnixNano(),
	}

	resp, err := c.transport.NTPQuery(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("NTP query failed: %w", err)
	}

	t4 := time.Now()

	// Add new cookie if provided
	if resp.Cookie != nil {
		keyMaterial.AddCookie(resp.Cookie)
	}

	// Calculate offset and delay
	t2 := time.Unix(0, resp.ReceiveTimestamp)
	t3 := time.Unix(0, resp.TransmitTimestamp)

	// NTP offset formula: ((t2-t1) + (t3-t4)) / 2
	offset := ((t2.Sub(t1)) + (t3.Sub(t4))) / 2

	// Round-trip delay: (t4-t1) - (t3-t2)
	delay := (t4.Sub(t1)) - (t3.Sub(t2))

	result := &TimeResult{
		Time:          time.Now().Add(offset),
		Offset:        offset,
		Delay:         delay,
		Stratum:       resp.Stratum,
		Precision:     resp.Precision,
		Authenticated: true,
	}

	c.mu.Lock()
	c.lastSync = result
	c.mu.Unlock()

	return result, nil
}

// querySimple performs a simple (unauthenticated) time query.
func (c *Client) querySimple(ctx context.Context) (*TimeResult, error) {
	t1 := time.Now()

	resp, err := c.transport.NTPGetTime(ctx)
	if err != nil {
		return nil, fmt.Errorf("time query failed: %w", err)
	}

	t4 := time.Now()

	// Server timestamp
	serverTime := time.Unix(0, resp.Timestamp)

	// Approximate offset (less accurate without proper NTP exchange)
	rtt := t4.Sub(t1)
	offset := serverTime.Sub(t1.Add(rtt / 2))

	result := &TimeResult{
		Time:          time.Now().Add(offset),
		Offset:        offset,
		Delay:         rtt,
		Stratum:       resp.Stratum,
		Authenticated: false,
	}

	c.mu.Lock()
	c.lastSync = result
	c.mu.Unlock()

	return result, nil
}

// GetTime returns the current synchronized time.
func (c *Client) GetTime() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.lastSync == nil {
		return time.Now()
	}

	// Apply stored offset to current time
	return time.Now().Add(c.lastSync.Offset)
}

// GetLastSync returns the last synchronization result.
func (c *Client) GetLastSync() *TimeResult {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.lastSync
}

// GetOffset returns the current time offset.
func (c *Client) GetOffset() time.Duration {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.lastSync == nil {
		return 0
	}
	return c.lastSync.Offset
}

// IsAuthenticated returns true if the last sync used NTS authentication.
func (c *Client) IsAuthenticated() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.lastSync == nil {
		return false
	}
	return c.lastSync.Authenticated
}

// syncLoop periodically syncs time.
func (c *Client) syncLoop(ctx context.Context) {
	// Initial sync
	if _, err := c.Query(ctx); err != nil {
		log.Printf("Initial NTP sync failed: %v", err)
	}

	ticker := time.NewTicker(time.Duration(c.config.SyncInterval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-c.stopCh:
			return
		case <-ticker.C:
			if _, err := c.Query(ctx); err != nil {
				log.Printf("NTP sync failed: %v", err)
			} else {
				log.Printf("NTP sync successful, offset: %v", c.GetOffset())
			}
		}
	}
}

// BuildNTPPacket creates an NTP client request packet.
func BuildNTPPacket() *NTPPacket {
	packet := &NTPPacket{
		Settings: 0x1B, // LI=0, VN=3, Mode=3 (Client)
	}

	// Set transmit timestamp
	now := time.Now()
	// #nosec G115 -- NTP protocol uses 32-bit timestamps (wraps in 2036)
	secs := uint32(now.Unix() + ntpEpochOffset)
	frac := uint32(float64(now.Nanosecond()) / 1e9 * 0x100000000)

	packet.TxTimeSec = secs
	packet.TxTimeFrac = frac

	return packet
}

// ParseNTPPacket parses an NTP response packet.
func ParseNTPPacket(data []byte) (*NTPPacket, error) {
	if len(data) < 48 {
		return nil, fmt.Errorf("NTP packet too short: %d bytes", len(data))
	}

	packet := &NTPPacket{
		Settings:       data[0],
		Stratum:        data[1],
		Poll:           data[2],
		Precision:      int8(data[3]),
		RootDelay:      binary.BigEndian.Uint32(data[4:8]),
		RootDispersion: binary.BigEndian.Uint32(data[8:12]),
		ReferenceID:    binary.BigEndian.Uint32(data[12:16]),
		RefTimeSec:     binary.BigEndian.Uint32(data[16:20]),
		RefTimeFrac:    binary.BigEndian.Uint32(data[20:24]),
		OrigTimeSec:    binary.BigEndian.Uint32(data[24:28]),
		OrigTimeFrac:   binary.BigEndian.Uint32(data[28:32]),
		RxTimeSec:      binary.BigEndian.Uint32(data[32:36]),
		RxTimeFrac:     binary.BigEndian.Uint32(data[36:40]),
		TxTimeSec:      binary.BigEndian.Uint32(data[40:44]),
		TxTimeFrac:     binary.BigEndian.Uint32(data[44:48]),
	}

	return packet, nil
}

// EncodeNTPPacket encodes an NTP packet to bytes.
func EncodeNTPPacket(packet *NTPPacket) []byte {
	data := make([]byte, 48)

	data[0] = packet.Settings
	data[1] = packet.Stratum
	data[2] = packet.Poll
	data[3] = byte(packet.Precision)

	binary.BigEndian.PutUint32(data[4:8], packet.RootDelay)
	binary.BigEndian.PutUint32(data[8:12], packet.RootDispersion)
	binary.BigEndian.PutUint32(data[12:16], packet.ReferenceID)
	binary.BigEndian.PutUint32(data[16:20], packet.RefTimeSec)
	binary.BigEndian.PutUint32(data[20:24], packet.RefTimeFrac)
	binary.BigEndian.PutUint32(data[24:28], packet.OrigTimeSec)
	binary.BigEndian.PutUint32(data[28:32], packet.OrigTimeFrac)
	binary.BigEndian.PutUint32(data[32:36], packet.RxTimeSec)
	binary.BigEndian.PutUint32(data[36:40], packet.RxTimeFrac)
	binary.BigEndian.PutUint32(data[40:44], packet.TxTimeSec)
	binary.BigEndian.PutUint32(data[44:48], packet.TxTimeFrac)

	return data
}

// NTPTimestampToTime converts NTP timestamp to Go time.
func NTPTimestampToTime(secs, frac uint32) time.Time {
	return time.Unix(int64(secs)-ntpEpochOffset, int64(float64(frac)/0x100000000*1e9))
}

// Close closes the NTP client and releases resources.
func (c *Client) Close() error {
	return c.Stop()
}
