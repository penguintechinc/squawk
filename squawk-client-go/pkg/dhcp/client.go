package dhcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/penguintechinc/squawk/squawk-client-go/pkg/transport"
)

// Client is a DHCP-over-HTTPS client with local intercept support.
type Client struct {
	config      *Config
	transport   transport.Transport
	leaseCache  map[string]*Lease // MAC -> Lease
	interceptor *Interceptor
	leaseStore  *LeaseStore
	mu          sync.RWMutex
	stopCh      chan struct{}
	running     bool
}

// NewClient creates a new DHCP client.
func NewClient(cfg *Config, t transport.Transport) (*Client, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	if t == nil {
		return nil, fmt.Errorf("transport is required")
	}

	c := &Client{
		config:     cfg,
		transport:  t,
		leaseCache: make(map[string]*Lease),
		stopCh:     make(chan struct{}),
	}

	// Initialize lease store for persistence
	if cfg.LeaseFile != "" {
		store, err := NewLeaseStore(cfg.LeaseFile)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize lease store: %w", err)
		}
		c.leaseStore = store

		// Load existing leases
		leases, err := store.LoadAll()
		if err == nil {
			for _, lease := range leases {
				c.leaseCache[lease.MACAddress] = lease
			}
		}
	}

	return c, nil
}

// Start starts the DHCP client services.
func (c *Client) Start(ctx context.Context) error {
	c.mu.Lock()
	if c.running {
		c.mu.Unlock()
		return fmt.Errorf("DHCP client is already running")
	}
	c.running = true
	c.mu.Unlock()

	// Start interceptor if enabled
	if c.config.EnableIntercept {
		interceptor, err := NewInterceptor(c.config, c)
		if err != nil {
			return fmt.Errorf("failed to create DHCP interceptor: %w", err)
		}
		c.interceptor = interceptor

		go func() {
			if err := interceptor.Start(ctx); err != nil {
				fmt.Printf("DHCP interceptor error: %v\n", err)
			}
		}()
	}

	// Start lease renewal goroutine
	go c.leaseRenewalLoop(ctx)

	return nil
}

// Stop stops the DHCP client services.
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

// Discover performs a DHCP Discover operation.
func (c *Client) Discover(ctx context.Context, macAddress, hostname string, requestedIP string) (*Lease, error) {
	req := &transport.DHCPDiscoverRequest{
		MACAddress:  macAddress,
		Hostname:    hostname,
		RequestedIP: requestedIP,
	}

	offer, err := c.transport.DHCPDiscover(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("DHCP discover failed: %w", err)
	}

	if offer.Status != "offer" {
		return nil, fmt.Errorf("unexpected DHCP status: %s", offer.Status)
	}

	// Request the offered IP
	return c.Request(ctx, macAddress, offer.TransactionID, offer.OfferedIP, offer.ServerID)
}

// Request performs a DHCP Request operation.
func (c *Client) Request(ctx context.Context, macAddress, transactionID, requestedIP, serverID string) (*Lease, error) {
	req := &transport.DHCPRequestMessage{
		MACAddress:    macAddress,
		TransactionID: transactionID,
		RequestedIP:   requestedIP,
		ServerID:      serverID,
	}

	ack, err := c.transport.DHCPRequest(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("DHCP request failed: %w", err)
	}

	if ack.Status != "ack" {
		return nil, fmt.Errorf("DHCP request rejected: %s", ack.ErrorMessage)
	}

	// Create lease from ACK
	now := time.Now()
	lease := &Lease{
		MACAddress:    macAddress,
		ClientIP:      ack.AssignedIP,
		SubnetMask:    ack.SubnetMask,
		Gateway:       ack.Gateway,
		DNSServers:    ack.DNSServers,
		LeaseTime:     ack.LeaseTime,
		RenewalTime:   ack.RenewalTime,
		RebindingTime: ack.RebindingTime,
		ServerID:      serverID,
		ObtainedAt:    now,
		ExpiresAt:     now.Add(time.Duration(ack.LeaseTime) * time.Second),
		Status:        "active",
	}

	// Cache and persist the lease
	c.mu.Lock()
	c.leaseCache[macAddress] = lease
	c.mu.Unlock()

	if c.leaseStore != nil {
		if err := c.leaseStore.Save(lease); err != nil {
			fmt.Printf("Warning: failed to persist lease: %v\n", err)
		}
	}

	return lease, nil
}

// Release releases a DHCP lease.
func (c *Client) Release(ctx context.Context, macAddress string) error {
	c.mu.RLock()
	lease, exists := c.leaseCache[macAddress]
	c.mu.RUnlock()

	if !exists {
		return fmt.Errorf("no lease found for MAC %s", macAddress)
	}

	req := &transport.DHCPReleaseRequest{
		MACAddress: macAddress,
		ClientIP:   lease.ClientIP,
	}

	resp, err := c.transport.DHCPRelease(ctx, req)
	if err != nil {
		return fmt.Errorf("DHCP release failed: %w", err)
	}

	if !resp.Success {
		return fmt.Errorf("DHCP release rejected: %s", resp.Message)
	}

	// Remove from cache
	c.mu.Lock()
	delete(c.leaseCache, macAddress)
	c.mu.Unlock()

	if c.leaseStore != nil {
		if err := c.leaseStore.Delete(macAddress); err != nil {
			fmt.Printf("Warning: failed to delete lease from store: %v\n", err)
		}
	}

	return nil
}

// GetConfig retrieves DHCP configuration from the server (REST API config pull).
func (c *Client) GetConfig(ctx context.Context, macAddress string) (*Lease, error) {
	resp, err := c.transport.DHCPGetConfig(ctx, macAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to get DHCP config: %w", err)
	}

	lease := &Lease{
		MACAddress:  macAddress,
		ClientIP:    resp.AssignedIP,
		SubnetMask:  resp.SubnetMask,
		Gateway:     resp.Gateway,
		DNSServers:  resp.DNSServers,
		LeaseTime:   resp.LeaseTime,
		RenewalTime: resp.RenewalTime,
		ObtainedAt:  time.Unix(resp.LeaseStart, 0),
		ExpiresAt:   time.Unix(resp.LeaseEnd, 0),
		Status:      resp.Status,
	}

	return lease, nil
}

// GetLease returns the cached lease for a MAC address.
func (c *Client) GetLease(macAddress string) (*Lease, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	lease, exists := c.leaseCache[macAddress]
	return lease, exists
}

// GetAllLeases returns all cached leases.
func (c *Client) GetAllLeases() []*Lease {
	c.mu.RLock()
	defer c.mu.RUnlock()

	leases := make([]*Lease, 0, len(c.leaseCache))
	for _, lease := range c.leaseCache {
		leases = append(leases, lease)
	}
	return leases
}

// RenewLease renews a specific lease.
func (c *Client) RenewLease(ctx context.Context, macAddress string) (*Lease, error) {
	c.mu.RLock()
	existingLease, exists := c.leaseCache[macAddress]
	c.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("no lease found for MAC %s", macAddress)
	}

	// Renew by requesting the same IP
	return c.Discover(ctx, macAddress, existingLease.Hostname, existingLease.ClientIP)
}

// leaseRenewalLoop handles automatic lease renewals.
func (c *Client) leaseRenewalLoop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-c.stopCh:
			return
		case <-ticker.C:
			c.checkAndRenewLeases(ctx)
		}
	}
}

// checkAndRenewLeases checks all leases and renews those that need it.
func (c *Client) checkAndRenewLeases(ctx context.Context) {
	c.mu.RLock()
	leases := make([]*Lease, 0)
	for _, lease := range c.leaseCache {
		if lease.NeedsRenewal() && !lease.IsExpired() {
			leases = append(leases, lease)
		}
	}
	c.mu.RUnlock()

	for _, lease := range leases {
		renewCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		if _, err := c.RenewLease(renewCtx, lease.MACAddress); err != nil {
			fmt.Printf("Warning: failed to renew lease for %s: %v\n", lease.MACAddress, err)
		}
		cancel()
	}
}

// GetMACAddress returns the MAC address for an interface.
func GetMACAddress(interfaceName string) (string, error) {
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return "", fmt.Errorf("interface not found: %w", err)
	}
	return iface.HardwareAddr.String(), nil
}

// Close closes the DHCP client and releases resources.
func (c *Client) Close() error {
	return c.Stop()
}

// ToJSON returns the lease as JSON.
func (l *Lease) ToJSON() ([]byte, error) {
	return json.Marshal(l)
}

// LeaseFromJSON creates a Lease from JSON.
func LeaseFromJSON(data []byte) (*Lease, error) {
	var lease Lease
	if err := json.Unmarshal(data, &lease); err != nil {
		return nil, err
	}
	return &lease, nil
}
