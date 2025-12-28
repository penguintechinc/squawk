package dhcp

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"sync"
)

// Interceptor listens on DHCP ports and proxies requests over HTTPS.
type Interceptor struct {
	config    *Config
	client    *Client
	conn      *net.UDPConn
	running   bool
	stopCh    chan struct{}
	wg        sync.WaitGroup
	mu        sync.RWMutex
}

// DHCP message types
const (
	DHCPDiscover = 1
	DHCPOffer    = 2
	DHCPRequest  = 3
	DHCPDecline  = 4
	DHCPAck      = 5
	DHCPNak      = 6
	DHCPRelease  = 7
	DHCPInform   = 8
)

// DHCP option codes
const (
	OptSubnetMask       = 1
	OptRouter           = 3
	OptDNS              = 6
	OptHostname         = 12
	OptRequestedIP      = 50
	OptLeaseTime        = 51
	OptMessageType      = 53
	OptServerIdentifier = 54
	OptParameterList    = 55
	OptClientIdentifier = 61
	OptEnd              = 255
)

// DHCPMessage represents a DHCP packet.
type DHCPMessage struct {
	Op            byte       // Message op code
	HType         byte       // Hardware address type
	HLen          byte       // Hardware address length
	Hops          byte       // Hops
	XID           uint32     // Transaction ID
	Secs          uint16     // Seconds elapsed
	Flags         uint16     // Flags
	CIAddr        net.IP     // Client IP address
	YIAddr        net.IP     // 'Your' IP address
	SIAddr        net.IP     // Server IP address
	GIAddr        net.IP     // Gateway IP address
	CHAddr        net.HardwareAddr // Client hardware address
	SName         [64]byte   // Server host name
	File          [128]byte  // Boot file name
	Options       []DHCPOption // DHCP options
	MessageType   byte       // DHCP message type
	ServerID      net.IP     // Server identifier
	RequestedIP   net.IP     // Requested IP
	Hostname      string     // Client hostname
}

// NewInterceptor creates a new DHCP interceptor.
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

// Start starts the DHCP interceptor.
func (i *Interceptor) Start(ctx context.Context) error {
	i.mu.Lock()
	if i.running {
		i.mu.Unlock()
		return fmt.Errorf("interceptor is already running")
	}
	i.running = true
	i.mu.Unlock()

	// Listen on DHCP client port (68)
	addr := &net.UDPAddr{
		IP:   net.IPv4(0, 0, 0, 0),
		Port: i.config.ListenPort,
	}

	conn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on DHCP port %d: %w", i.config.ListenPort, err)
	}
	i.conn = conn

	log.Printf("DHCP interceptor listening on port %d", i.config.ListenPort)

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

// Stop stops the DHCP interceptor.
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
			return fmt.Errorf("failed to close DHCP socket: %w", err)
		}
	}

	i.wg.Wait()
	log.Println("DHCP interceptor stopped")
	return nil
}

// handlePackets reads and processes incoming DHCP packets.
func (i *Interceptor) handlePackets(ctx context.Context) {
	buffer := make([]byte, 1500)

	for {
		select {
		case <-ctx.Done():
			return
		case <-i.stopCh:
			return
		default:
		}

		n, addr, err := i.conn.ReadFromUDP(buffer)
		if err != nil {
			if i.running {
				log.Printf("Error reading DHCP packet: %v", err)
			}
			continue
		}

		// Parse and handle the DHCP message
		go i.handleMessage(ctx, buffer[:n], addr)
	}
}

// handleMessage processes a single DHCP message.
func (i *Interceptor) handleMessage(ctx context.Context, data []byte, addr *net.UDPAddr) {
	msg, err := parseDHCPMessage(data)
	if err != nil {
		log.Printf("Failed to parse DHCP message: %v", err)
		return
	}

	macAddr := msg.CHAddr.String()

	switch msg.MessageType {
	case DHCPDiscover:
		log.Printf("DHCP Discover from %s", macAddr)
		i.handleDiscover(ctx, msg, addr)

	case DHCPRequest:
		log.Printf("DHCP Request from %s", macAddr)
		i.handleRequest(ctx, msg, addr)

	case DHCPRelease:
		log.Printf("DHCP Release from %s", macAddr)
		i.handleRelease(ctx, msg)

	case DHCPInform:
		log.Printf("DHCP Inform from %s", macAddr)
		// INFORM is used to get configuration without IP allocation
		// We can handle this by calling GetConfig

	default:
		log.Printf("Unhandled DHCP message type %d from %s", msg.MessageType, macAddr)
	}
}

// handleDiscover handles a DHCP Discover message.
func (i *Interceptor) handleDiscover(ctx context.Context, msg *DHCPMessage, addr *net.UDPAddr) {
	macAddr := msg.CHAddr.String()
	requestedIP := ""
	if msg.RequestedIP != nil {
		requestedIP = msg.RequestedIP.String()
	}

	// Forward to DHCP server via HTTPS
	lease, err := i.client.Discover(ctx, macAddr, msg.Hostname, requestedIP)
	if err != nil {
		log.Printf("DHCP Discover via HTTPS failed: %v", err)
		return
	}

	// Build and send DHCP Offer response
	offer := i.buildOfferPacket(msg, lease)
	i.sendResponse(offer, addr)
}

// handleRequest handles a DHCP Request message.
func (i *Interceptor) handleRequest(ctx context.Context, msg *DHCPMessage, addr *net.UDPAddr) {
	macAddr := msg.CHAddr.String()

	// Get the existing lease or re-request
	lease, exists := i.client.GetLease(macAddr)
	if !exists {
		log.Printf("No lease found for %s, performing new discover", macAddr)
		requestedIP := ""
		if msg.RequestedIP != nil {
			requestedIP = msg.RequestedIP.String()
		}
		var err error
		lease, err = i.client.Discover(ctx, macAddr, msg.Hostname, requestedIP)
		if err != nil {
			log.Printf("DHCP Request via HTTPS failed: %v", err)
			i.sendNak(msg, addr, "Lease not available")
			return
		}
	}

	// Build and send DHCP Ack response
	ack := i.buildAckPacket(msg, lease)
	i.sendResponse(ack, addr)
}

// handleRelease handles a DHCP Release message.
func (i *Interceptor) handleRelease(ctx context.Context, msg *DHCPMessage) {
	macAddr := msg.CHAddr.String()

	if err := i.client.Release(ctx, macAddr); err != nil {
		log.Printf("DHCP Release via HTTPS failed: %v", err)
	}
}

// buildOfferPacket builds a DHCP Offer packet.
func (i *Interceptor) buildOfferPacket(request *DHCPMessage, lease *Lease) []byte {
	return i.buildResponsePacket(request, lease, DHCPOffer)
}

// buildAckPacket builds a DHCP Ack packet.
func (i *Interceptor) buildAckPacket(request *DHCPMessage, lease *Lease) []byte {
	return i.buildResponsePacket(request, lease, DHCPAck)
}

// buildResponsePacket builds a DHCP response packet.
func (i *Interceptor) buildResponsePacket(request *DHCPMessage, lease *Lease, msgType byte) []byte {
	// Standard DHCP packet structure
	packet := make([]byte, 300)

	// Message type: BOOTREPLY
	packet[0] = 2
	// Hardware type: Ethernet
	packet[1] = 1
	// Hardware address length
	packet[2] = 6
	// Hops
	packet[3] = 0

	// Transaction ID
	binary.BigEndian.PutUint32(packet[4:8], request.XID)

	// Secs and flags
	binary.BigEndian.PutUint16(packet[8:10], 0)
	binary.BigEndian.PutUint16(packet[10:12], 0)

	// Client IP (ciaddr) - 0.0.0.0
	copy(packet[12:16], net.IPv4zero.To4())

	// Your IP (yiaddr) - assigned IP
	assignedIP := net.ParseIP(lease.ClientIP)
	if assignedIP != nil {
		copy(packet[16:20], assignedIP.To4())
	}

	// Server IP (siaddr)
	serverIP := net.ParseIP(lease.Gateway)
	if serverIP != nil {
		copy(packet[20:24], serverIP.To4())
	}

	// Gateway IP (giaddr)
	copy(packet[24:28], net.IPv4zero.To4())

	// Client hardware address
	copy(packet[28:34], request.CHAddr)

	// Server hostname (sname) - padded with zeros
	// Boot filename (file) - padded with zeros

	// Magic cookie
	copy(packet[236:240], []byte{99, 130, 83, 99})

	// Options start at offset 240
	offset := 240

	// Message type option
	packet[offset] = OptMessageType
	packet[offset+1] = 1
	packet[offset+2] = msgType
	offset += 3

	// Server identifier
	if serverIP != nil {
		packet[offset] = OptServerIdentifier
		packet[offset+1] = 4
		copy(packet[offset+2:offset+6], serverIP.To4())
		offset += 6
	}

	// Lease time
	packet[offset] = OptLeaseTime
	packet[offset+1] = 4
	// #nosec G115 -- DHCP lease time is always positive and within uint32 range
	binary.BigEndian.PutUint32(packet[offset+2:offset+6], uint32(lease.LeaseTime))
	offset += 6

	// Subnet mask
	subnetMask := net.ParseIP(lease.SubnetMask)
	if subnetMask != nil {
		packet[offset] = OptSubnetMask
		packet[offset+1] = 4
		copy(packet[offset+2:offset+6], subnetMask.To4())
		offset += 6
	}

	// Router/Gateway
	gateway := net.ParseIP(lease.Gateway)
	if gateway != nil {
		packet[offset] = OptRouter
		packet[offset+1] = 4
		copy(packet[offset+2:offset+6], gateway.To4())
		offset += 6
	}

	// DNS servers
	if len(lease.DNSServers) > 0 {
		packet[offset] = OptDNS
		packet[offset+1] = byte(len(lease.DNSServers) * 4)
		offset += 2
		for _, dns := range lease.DNSServers {
			dnsIP := net.ParseIP(dns)
			if dnsIP != nil {
				copy(packet[offset:offset+4], dnsIP.To4())
				offset += 4
			}
		}
	}

	// End option
	packet[offset] = OptEnd
	offset++

	return packet[:offset]
}

// sendResponse sends a DHCP response packet.
func (i *Interceptor) sendResponse(packet []byte, addr *net.UDPAddr) {
	// Send to broadcast or unicast based on flags
	destAddr := &net.UDPAddr{
		IP:   net.IPv4bcast,
		Port: 68,
	}

	if _, err := i.conn.WriteToUDP(packet, destAddr); err != nil {
		log.Printf("Failed to send DHCP response: %v", err)
	}
}

// sendNak sends a DHCP NAK response.
func (i *Interceptor) sendNak(request *DHCPMessage, addr *net.UDPAddr, message string) {
	packet := make([]byte, 300)

	packet[0] = 2 // BOOTREPLY
	packet[1] = 1 // Ethernet
	packet[2] = 6 // Hardware address length

	binary.BigEndian.PutUint32(packet[4:8], request.XID)

	copy(packet[28:34], request.CHAddr)
	copy(packet[236:240], []byte{99, 130, 83, 99}) // Magic cookie

	offset := 240
	packet[offset] = OptMessageType
	packet[offset+1] = 1
	packet[offset+2] = DHCPNak
	offset += 3

	packet[offset] = OptEnd
	offset++

	i.sendResponse(packet[:offset], addr)
}

// parseDHCPMessage parses a raw DHCP packet into a DHCPMessage.
func parseDHCPMessage(data []byte) (*DHCPMessage, error) {
	if len(data) < 240 {
		return nil, fmt.Errorf("DHCP packet too short: %d bytes", len(data))
	}

	msg := &DHCPMessage{
		Op:     data[0],
		HType:  data[1],
		HLen:   data[2],
		Hops:   data[3],
		XID:    binary.BigEndian.Uint32(data[4:8]),
		Secs:   binary.BigEndian.Uint16(data[8:10]),
		Flags:  binary.BigEndian.Uint16(data[10:12]),
		CIAddr: net.IP(data[12:16]),
		YIAddr: net.IP(data[16:20]),
		SIAddr: net.IP(data[20:24]),
		GIAddr: net.IP(data[24:28]),
		CHAddr: net.HardwareAddr(data[28 : 28+data[2]]),
	}

	// Parse options (starting after magic cookie at offset 240)
	if len(data) > 240 {
		// Verify magic cookie
		if data[236] != 99 || data[237] != 130 || data[238] != 83 || data[239] != 99 {
			return nil, fmt.Errorf("invalid DHCP magic cookie")
		}

		offset := 240
		for offset < len(data) {
			optCode := data[offset]
			if optCode == OptEnd {
				break
			}
			if optCode == 0 { // Pad option
				offset++
				continue
			}

			if offset+1 >= len(data) {
				break
			}
			optLen := int(data[offset+1])
			if offset+2+optLen > len(data) {
				break
			}

			optData := data[offset+2 : offset+2+optLen]

			switch optCode {
			case OptMessageType:
				if optLen >= 1 {
					msg.MessageType = optData[0]
				}
			case OptServerIdentifier:
				if optLen >= 4 {
					msg.ServerID = net.IP(optData[:4])
				}
			case OptRequestedIP:
				if optLen >= 4 {
					msg.RequestedIP = net.IP(optData[:4])
				}
			case OptHostname:
				msg.Hostname = string(optData)
			}

			msg.Options = append(msg.Options, DHCPOption{
				Code:  int(optCode),
				Value: string(optData),
			})

			offset += 2 + optLen
		}
	}

	return msg, nil
}

// IsRunning returns whether the interceptor is running.
func (i *Interceptor) IsRunning() bool {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.running
}
