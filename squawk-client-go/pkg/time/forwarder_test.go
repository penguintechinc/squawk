package time

import (
	"context"
	"testing"
	"time"
)

func TestNewForwarder(t *testing.T) {
	// Create a mock NTP client
	config := &ClientConfig{
		ServerURLs: []string{"pool.ntp.org:123"},
		Timeout:    5,
		MaxRetries: 1,
		RetryDelay: 0,
	}
	ntpClient, err := NewNTPClient(config)
	if err != nil {
		t.Fatalf("Failed to create NTP client: %v", err)
	}
	defer ntpClient.Close()

	tests := []struct {
		name           string
		config         *ForwarderConfig
		expectedAddr   string
		expectedTTL    time.Duration
	}{
		{
			name:         "nil config uses defaults",
			config:       nil,
			expectedAddr: "127.0.0.1:123",
			expectedTTL:  60 * time.Second,
		},
		{
			name: "custom config",
			config: &ForwarderConfig{
				ListenAddress: "0.0.0.0:1123",
				CacheTTL:      120,
			},
			expectedAddr: "0.0.0.0:1123",
			expectedTTL:  120 * time.Second,
		},
		{
			name: "empty listen address uses default",
			config: &ForwarderConfig{
				ListenAddress: "",
				CacheTTL:      30,
			},
			expectedAddr: "127.0.0.1:123",
			expectedTTL:  30 * time.Second,
		},
		{
			name: "zero cache TTL uses default",
			config: &ForwarderConfig{
				ListenAddress: "127.0.0.1:1123",
				CacheTTL:      0,
			},
			expectedAddr: "127.0.0.1:1123",
			expectedTTL:  60 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			forwarder := NewForwarder(ntpClient, tt.config)
			if forwarder == nil {
				t.Fatal("NewForwarder returned nil")
			}
			if forwarder.listenAddr != tt.expectedAddr {
				t.Errorf("Expected listen address %s, got %s", tt.expectedAddr, forwarder.listenAddr)
			}
			if forwarder.cacheTTL != tt.expectedTTL {
				t.Errorf("Expected cache TTL %v, got %v", tt.expectedTTL, forwarder.cacheTTL)
			}
		})
	}
}

func TestForwarder_IsRunning(t *testing.T) {
	config := &ClientConfig{
		ServerURLs: []string{"pool.ntp.org:123"},
		Timeout:    5,
		MaxRetries: 1,
		RetryDelay: 0,
	}
	ntpClient, err := NewNTPClient(config)
	if err != nil {
		t.Fatalf("Failed to create NTP client: %v", err)
	}
	defer ntpClient.Close()

	forwarder := NewForwarder(ntpClient, &ForwarderConfig{
		ListenAddress: "127.0.0.1:11234", // Use high port to avoid permission issues
		CacheTTL:      60,
	})

	if forwarder.IsRunning() {
		t.Error("Forwarder should not be running initially")
	}
}

func TestForwarder_GetStatus(t *testing.T) {
	config := &ClientConfig{
		ServerURLs: []string{"pool.ntp.org:123"},
		Timeout:    5,
		MaxRetries: 1,
		RetryDelay: 0,
	}
	ntpClient, err := NewNTPClient(config)
	if err != nil {
		t.Fatalf("Failed to create NTP client: %v", err)
	}
	defer ntpClient.Close()

	forwarder := NewForwarder(ntpClient, &ForwarderConfig{
		ListenAddress: "127.0.0.1:11235",
		CacheTTL:      60,
	})

	running, cacheAge, offset := forwarder.GetStatus()
	if running {
		t.Error("Forwarder should not be running initially")
	}
	if cacheAge != 0 {
		t.Errorf("Cache age should be 0 initially, got %v", cacheAge)
	}
	if offset != 0 {
		t.Errorf("Offset should be 0 initially, got %v", offset)
	}
}

func TestForwarder_StopNotRunning(t *testing.T) {
	config := &ClientConfig{
		ServerURLs: []string{"pool.ntp.org:123"},
		Timeout:    5,
		MaxRetries: 1,
		RetryDelay: 0,
	}
	ntpClient, err := NewNTPClient(config)
	if err != nil {
		t.Fatalf("Failed to create NTP client: %v", err)
	}
	defer ntpClient.Close()

	forwarder := NewForwarder(ntpClient, &ForwarderConfig{
		ListenAddress: "127.0.0.1:11236",
		CacheTTL:      60,
	})

	err = forwarder.Stop()
	if err == nil {
		t.Error("Expected error when stopping forwarder that isn't running")
	}
}

// Integration test - tests actual UDP binding
func TestForwarder_StartStop_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	config := &ClientConfig{
		ServerURLs: []string{"pool.ntp.org:123"},
		Timeout:    5,
		MaxRetries: 1,
		RetryDelay: 0,
	}
	ntpClient, err := NewNTPClient(config)
	if err != nil {
		t.Fatalf("Failed to create NTP client: %v", err)
	}
	defer ntpClient.Close()

	// Use a high port to avoid permission issues
	forwarder := NewForwarder(ntpClient, &ForwarderConfig{
		ListenAddress: "127.0.0.1:11237",
		CacheTTL:      60,
	})

	ctx, cancel := context.WithCancel(context.Background())

	// Start forwarder in background
	errCh := make(chan error, 1)
	go func() {
		errCh <- forwarder.Start(ctx)
	}()

	// Give it time to start
	time.Sleep(100 * time.Millisecond)

	if !forwarder.IsRunning() {
		t.Error("Forwarder should be running after Start")
	}

	// Double start should fail
	go func() {
		err := forwarder.Start(ctx)
		if err == nil {
			t.Error("Expected error when starting already running forwarder")
		}
	}()

	time.Sleep(50 * time.Millisecond)

	// Cancel context to stop
	cancel()

	// Wait for start to return
	select {
	case <-errCh:
		// Expected
	case <-time.After(5 * time.Second):
		t.Fatal("Forwarder did not stop within timeout")
	}

	if forwarder.IsRunning() {
		t.Error("Forwarder should not be running after context cancel")
	}
}
