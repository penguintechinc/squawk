package time

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"
)

// Forwarder handles NTP forwarding from local OS requests to upstream NTP servers
type Forwarder struct {
	ntpClient   *NTPClient
	listenAddr  string
	udpConn     *net.UDPConn
	running     bool
	stopCh      chan struct{}
	wg          sync.WaitGroup
	mu          sync.RWMutex
	cacheTime   time.Time     // Last cached time
	cacheOffset time.Duration // Cached offset
	cacheTTL    time.Duration // How long to cache responses
}

// ForwarderConfig holds the forwarder configuration
type ForwarderConfig struct {
	ListenAddress string `yaml:"listen_address" json:"listen_address"`
	CacheTTL      int    `yaml:"cache_ttl" json:"cache_ttl"` // seconds
}

// NewForwarder creates a new NTP forwarder
func NewForwarder(ntpClient *NTPClient, config *ForwarderConfig) *Forwarder {
	if config == nil {
		config = &ForwarderConfig{
			ListenAddress: "127.0.0.1:123",
			CacheTTL:      60,
		}
	}

	if config.ListenAddress == "" {
		config.ListenAddress = "127.0.0.1:123"
	}

	cacheTTL := time.Duration(config.CacheTTL) * time.Second
	if cacheTTL <= 0 {
		cacheTTL = 60 * time.Second
	}

	return &Forwarder{
		ntpClient:  ntpClient,
		listenAddr: config.ListenAddress,
		stopCh:     make(chan struct{}),
		cacheTTL:   cacheTTL,
	}
}

// Start begins the NTP forwarding service
func (f *Forwarder) Start(ctx context.Context) error {
	f.mu.Lock()
	if f.running {
		f.mu.Unlock()
		return fmt.Errorf("NTP forwarder is already running")
	}
	f.running = true
	f.mu.Unlock()

	// Parse the listen address
	addr, err := net.ResolveUDPAddr("udp", f.listenAddr)
	if err != nil {
		f.mu.Lock()
		f.running = false
		f.mu.Unlock()
		return fmt.Errorf("failed to resolve listen address: %w", err)
	}

	// Start listening on UDP port 123 (NTP)
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		f.mu.Lock()
		f.running = false
		f.mu.Unlock()
		return fmt.Errorf("failed to listen on UDP: %w", err)
	}
	f.udpConn = conn

	log.Printf("Starting NTP forwarder on %s", f.listenAddr)

	// Start the packet handler
	f.wg.Add(1)
	go func() {
		defer f.wg.Done()
		f.handlePackets(ctx)
	}()

	// Start periodic cache refresh
	f.wg.Add(1)
	go func() {
		defer f.wg.Done()
		f.refreshCache(ctx)
	}()

	// Wait for context cancellation or stop signal
	select {
	case <-ctx.Done():
		return f.Stop()
	case <-f.stopCh:
		return nil
	}
}

// Stop shuts down the NTP forwarding service
func (f *Forwarder) Stop() error {
	f.mu.Lock()
	if !f.running {
		f.mu.Unlock()
		return fmt.Errorf("NTP forwarder is not running")
	}
	f.running = false
	f.mu.Unlock()

	log.Println("Shutting down NTP forwarder...")

	// Close the stop channel
	close(f.stopCh)

	// Close the UDP connection
	if f.udpConn != nil {
		if err := f.udpConn.Close(); err != nil {
			log.Printf("Error closing UDP connection: %v", err)
		}
	}

	f.wg.Wait()

	log.Println("NTP forwarder stopped")
	return nil
}

// handlePackets processes incoming NTP requests
func (f *Forwarder) handlePackets(ctx context.Context) {
	buf := make([]byte, 512) // NTP packets are 48 bytes, but we allocate more for safety

	for {
		select {
		case <-ctx.Done():
			return
		case <-f.stopCh:
			return
		default:
		}

		// Set read deadline to check for stop signal periodically
		if err := f.udpConn.SetReadDeadline(time.Now().Add(1 * time.Second)); err != nil {
			log.Printf("Failed to set read deadline: %v", err)
			continue
		}

		n, remoteAddr, err := f.udpConn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue // Timeout is expected, continue listening
			}
			if !f.IsRunning() {
				return // Stop was called
			}
			log.Printf("Error reading UDP packet: %v", err)
			continue
		}

		// Process the NTP request
		go f.handleNTPRequest(ctx, buf[:n], remoteAddr)
	}
}

// handleNTPRequest processes a single NTP request and sends a response
func (f *Forwarder) handleNTPRequest(ctx context.Context, request []byte, remoteAddr *net.UDPAddr) {
	if len(request) < ntpPacketSize {
		log.Printf("Invalid NTP request from %s: too short (%d bytes)", remoteAddr, len(request))
		return
	}

	log.Printf("NTP request from %s", remoteAddr)

	// Parse the incoming request
	req := &ntpPacket{}
	req.Settings = request[0]
	req.Stratum = request[1]
	req.Poll = int8(request[2])
	req.Precision = int8(request[3])
	req.OrigTimeSec = decodeUint32(request[24:28])
	req.OrigTimeFrac = decodeUint32(request[28:32])

	// Get current time with offset
	var serverTime time.Time
	var stratum uint8 = 3 // Default stratum for forwarding server

	f.mu.RLock()
	if time.Since(f.cacheTime) < f.cacheTTL && !f.cacheTime.IsZero() {
		// Use cached offset
		serverTime = time.Now().Add(f.cacheOffset)
		f.mu.RUnlock()
	} else {
		f.mu.RUnlock()
		// Query upstream server
		resp, err := f.ntpClient.Query(ctx)
		if err != nil {
			log.Printf("Failed to query upstream NTP server: %v", err)
			// Use local time as fallback
			serverTime = time.Now()
			stratum = 16 // Unsynchronized stratum
		} else {
			serverTime = time.Now().Add(resp.Offset)
			stratum = resp.Stratum + 1 // One stratum higher than upstream

			// Update cache
			f.mu.Lock()
			f.cacheTime = time.Now()
			f.cacheOffset = resp.Offset
			f.mu.Unlock()
		}
	}

	// Build response packet
	response := make([]byte, ntpPacketSize)

	// Mode: server response (4), version 4, no leap indicator
	response[0] = (ntpVersion << 3) | 4 // Server mode
	response[1] = stratum
	response[2] = byte(req.Poll)
	response[3] = 0xEC // Precision (-20, approximately 1 microsecond)

	// Root delay and dispersion (placeholder values)
	encodeUint32(response[4:8], 0)  // Root delay
	encodeUint32(response[8:12], 0) // Root dispersion

	// Reference ID (use upstream server IP or "LOCL" for local)
	copy(response[12:16], []byte("SQWK")) // "SQWK" as reference ID

	// Reference timestamp (last sync time) - safe conversion
	refUnixTime := serverTime.Unix()
	if refUnixTime < -ntpEpochOffset || refUnixTime > (1<<32-ntpEpochOffset) {
		refUnixTime = time.Now().Unix()
	}
	refSec := uint32(refUnixTime + ntpEpochOffset) // #nosec G115 - validated range

	refNanos := serverTime.Nanosecond()
	if refNanos < 0 || refNanos >= 1e9 {
		refNanos = 0
	}
	refFrac := uint32((uint64(refNanos) << 32) / 1e9) // #nosec G115 - validated range
	encodeUint32(response[16:20], refSec)
	encodeUint32(response[20:24], refFrac)

	// Origin timestamp (copy from request)
	encodeUint32(response[24:28], req.OrigTimeSec)
	encodeUint32(response[28:32], req.OrigTimeFrac)

	// Receive timestamp (current server time) - safe conversion
	rxTime := serverTime
	rxUnixTime := rxTime.Unix()
	if rxUnixTime < -ntpEpochOffset || rxUnixTime > (1<<32-ntpEpochOffset) {
		rxUnixTime = time.Now().Unix()
	}
	rxSec := uint32(rxUnixTime + ntpEpochOffset) // #nosec G115 - validated range

	rxNanos := rxTime.Nanosecond()
	if rxNanos < 0 || rxNanos >= 1e9 {
		rxNanos = 0
	}
	rxFrac := uint32((uint64(rxNanos) << 32) / 1e9) // #nosec G115 - validated range
	encodeUint32(response[32:36], rxSec)
	encodeUint32(response[36:40], rxFrac)

	// Transmit timestamp (current server time) - safe conversion
	txTime := serverTime
	txUnixTime := txTime.Unix()
	if txUnixTime < -ntpEpochOffset || txUnixTime > (1<<32-ntpEpochOffset) {
		txUnixTime = time.Now().Unix()
	}
	txSec := uint32(txUnixTime + ntpEpochOffset) // #nosec G115 - validated range

	txNanos := txTime.Nanosecond()
	if txNanos < 0 || txNanos >= 1e9 {
		txNanos = 0
	}
	txFrac := uint32((uint64(txNanos) << 32) / 1e9) // #nosec G115 - validated range
	encodeUint32(response[40:44], txSec)
	encodeUint32(response[44:48], txFrac)

	// Send response
	_, err := f.udpConn.WriteToUDP(response, remoteAddr)
	if err != nil {
		log.Printf("Failed to send NTP response to %s: %v", remoteAddr, err)
	}
}

// refreshCache periodically refreshes the time cache
func (f *Forwarder) refreshCache(ctx context.Context) {
	ticker := time.NewTicker(f.cacheTTL / 2)
	defer ticker.Stop()

	// Initial query
	if _, err := f.ntpClient.Query(ctx); err != nil {
		log.Printf("Initial NTP sync failed: %v", err)
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-f.stopCh:
			return
		case <-ticker.C:
			if resp, err := f.ntpClient.Query(ctx); err != nil {
				log.Printf("NTP cache refresh failed: %v", err)
			} else {
				f.mu.Lock()
				f.cacheTime = time.Now()
				f.cacheOffset = resp.Offset
				f.mu.Unlock()
				log.Printf("NTP cache refreshed: offset=%v, stratum=%d", resp.Offset, resp.Stratum)
			}
		}
	}
}

// IsRunning returns whether the forwarder is currently running
func (f *Forwarder) IsRunning() bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.running
}

// GetStatus returns the current forwarder status
func (f *Forwarder) GetStatus() (running bool, cacheAge time.Duration, offset time.Duration) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if f.cacheTime.IsZero() {
		return f.running, 0, 0
	}
	return f.running, time.Since(f.cacheTime), f.cacheOffset
}
