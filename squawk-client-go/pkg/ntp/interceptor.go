package ntp

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"sync"
	"time"
)

// Interceptor listens on NTP port and proxies requests via NTS.
type Interceptor struct {
	config  *Config
	client  *Client
	conn    *net.UDPConn
	running bool
	stopCh  chan struct{}
	wg      sync.WaitGroup
	mu      sync.RWMutex
}

// NewInterceptor creates a new NTP interceptor.
func NewInterceptor(cfg *Config, client *Client) (*Interceptor, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	return &Interceptor{
		config: cfg,
		client: client,
		stopCh: make(chan struct{}),
	}, nil
}

// Start starts the NTP interceptor.
func (i *Interceptor) Start(ctx context.Context) error {
	i.mu.Lock()
	if i.running {
		i.mu.Unlock()
		return fmt.Errorf("interceptor is already running")
	}
	i.running = true
	i.mu.Unlock()

	// Listen on NTP port (123)
	addr := &net.UDPAddr{
		IP:   net.IPv4(0, 0, 0, 0),
		Port: i.config.ListenPort,
	}

	conn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on NTP port %d: %w", i.config.ListenPort, err)
	}
	i.conn = conn

	log.Printf("NTP interceptor listening on port %d", i.config.ListenPort)

	i.wg.Add(1)
	go func() {
		defer i.wg.Done()
		i.handlePackets(ctx)
	}()

	// Wait for context cancellation
	select {
	case <-ctx.Done():
		return i.Stop()
	case <-i.stopCh:
		return nil
	}
}

// Stop stops the NTP interceptor.
func (i *Interceptor) Stop() error {
	i.mu.Lock()
	if !i.running {
		i.mu.Unlock()
		return nil
	}
	i.running = false
	i.mu.Unlock()

	close(i.stopCh)

	if i.conn != nil {
		if err := i.conn.Close(); err != nil {
			return fmt.Errorf("failed to close NTP socket: %w", err)
		}
	}

	i.wg.Wait()
	log.Println("NTP interceptor stopped")
	return nil
}

// handlePackets reads and processes incoming NTP packets.
func (i *Interceptor) handlePackets(ctx context.Context) {
	buffer := make([]byte, 512)

	for {
		select {
		case <-ctx.Done():
			return
		case <-i.stopCh:
			return
		default:
		}

		// Set read deadline to allow checking for stop signal
		if err := i.conn.SetReadDeadline(time.Now().Add(1 * time.Second)); err != nil {
			continue
		}

		n, addr, err := i.conn.ReadFromUDP(buffer)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue // Timeout, check for stop signal
			}
			if i.running {
				log.Printf("Error reading NTP packet: %v", err)
			}
			continue
		}

		// Handle the NTP request
		go i.handleRequest(ctx, buffer[:n], addr)
	}
}

// handleRequest processes a single NTP request.
func (i *Interceptor) handleRequest(ctx context.Context, data []byte, addr *net.UDPAddr) {
	// Parse the incoming NTP packet
	reqPacket, err := ParseNTPPacket(data)
	if err != nil {
		log.Printf("Failed to parse NTP packet: %v", err)
		return
	}

	// Extract mode from settings
	mode := reqPacket.Settings & 0x07
	if mode != 3 { // Client mode
		log.Printf("Ignoring NTP packet with mode %d", mode)
		return
	}

	log.Printf("NTP request from %s", addr.String())

	// Query the NTS server
	result, err := i.client.Query(ctx)
	if err != nil {
		log.Printf("NTP query failed: %v", err)
		return
	}

	// Build response packet
	respPacket := i.buildResponse(reqPacket, result)
	respData := EncodeNTPPacket(respPacket)

	// Check for NTS extension fields in request
	if len(data) > 48 {
		// Request has extension fields - this is an NTS request
		respData = i.addNTSExtensions(respData, data[48:])
	}

	// Send response
	if _, err := i.conn.WriteToUDP(respData, addr); err != nil {
		log.Printf("Failed to send NTP response: %v", err)
	}
}

// buildResponse builds an NTP response packet.
func (i *Interceptor) buildResponse(request *NTPPacket, result *TimeResult) *NTPPacket {
	now := time.Now()

	// Convert times to NTP format
	// #nosec G115 -- NTP protocol uses 32-bit timestamps (wraps in 2036)
	nowSecs := uint32(now.Unix() + ntpEpochOffset)
	nowFrac := uint32(float64(now.Nanosecond()) / 1e9 * 0x100000000)

	// Reference time (last sync)
	refTime := result.Time
	// #nosec G115 -- NTP protocol uses 32-bit timestamps (wraps in 2036)
	refSecs := uint32(refTime.Unix() + ntpEpochOffset)
	refFrac := uint32(float64(refTime.Nanosecond()) / 1e9 * 0x100000000)

	response := &NTPPacket{
		Settings:       0x24, // LI=0, VN=4, Mode=4 (Server)
		Stratum:        byte(result.Stratum), //nolint:gosec // G115: NTP Stratum is 0-16, safe conversion
		Poll:           4, // 16 seconds minimum
		Precision:      -20, // ~1 microsecond
		RootDelay:      uint32(result.Delay.Seconds() * 65536),
		RootDispersion: 655, // ~10ms dispersion (0.01 * 65536)
		ReferenceID:    0x4E545350, // "NTSP" for NTS server
		RefTimeSec:     refSecs,
		RefTimeFrac:    refFrac,
		OrigTimeSec:    request.TxTimeSec,
		OrigTimeFrac:   request.TxTimeFrac,
		RxTimeSec:      nowSecs,
		RxTimeFrac:     nowFrac,
		TxTimeSec:      nowSecs,
		TxTimeFrac:     nowFrac,
	}

	return response
}

// addNTSExtensions adds NTS extension fields to the response.
func (i *Interceptor) addNTSExtensions(respData []byte, reqExtensions []byte) []byte {
	// Parse request extensions to get unique identifier
	var uniqueID []byte
	offset := 0
	for offset+4 <= len(reqExtensions) {
		extType := binary.BigEndian.Uint16(reqExtensions[offset : offset+2])
		extLen := binary.BigEndian.Uint16(reqExtensions[offset+2 : offset+4])

		if offset+4+int(extLen) > len(reqExtensions) {
			break
		}

		if extType == NTSExtUniqueIdentifier {
			uniqueID = reqExtensions[offset+4 : offset+4+int(extLen)]
		}

		offset += 4 + int(extLen)
		// Pad to 4-byte boundary
		if offset%4 != 0 {
			offset += 4 - (offset % 4)
		}
	}

	// Add Unique Identifier extension (echo back)
	if len(uniqueID) > 0 {
		respData = appendExtensionField(respData, NTSExtUniqueIdentifier, uniqueID)
	}

	// Add new cookie if available
	keyMaterial := i.client.keManager.GetKeyMaterial()
	if keyMaterial != nil && keyMaterial.HasCookies() {
		// Get a cookie to include in response
		if len(keyMaterial.Cookies) > 1 {
			cookie := keyMaterial.Cookies[len(keyMaterial.Cookies)-1]
			respData = appendExtensionField(respData, NTSExtNTSCookie, cookie)
		}
	}

	// Note: Full NTS authentication would require AEAD encryption here
	// For now, we're providing basic NTS-like behavior via the secure HTTPS transport

	return respData
}

// appendExtensionField appends an NTS extension field to a packet.
func appendExtensionField(packet []byte, extType uint16, data []byte) []byte {
	// Extension field header
	header := make([]byte, 4)
	binary.BigEndian.PutUint16(header[0:2], extType)
	// #nosec G115 -- NTS extension field length is protocol-limited to uint16
	binary.BigEndian.PutUint16(header[2:4], uint16(len(data)))

	packet = append(packet, header...)
	packet = append(packet, data...)

	// Pad to 4-byte boundary
	padding := (4 - len(data)%4) % 4
	if padding > 0 {
		packet = append(packet, make([]byte, padding)...)
	}

	return packet
}

// IsRunning returns whether the interceptor is running.
func (i *Interceptor) IsRunning() bool {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.running
}
