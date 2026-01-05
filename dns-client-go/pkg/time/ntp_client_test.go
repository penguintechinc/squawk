package time

import (
	"context"
	"testing"
	"time"
)

func TestNewNTPClient(t *testing.T) {
	tests := []struct {
		name    string
		config  *ClientConfig
		wantErr bool
	}{
		{
			name:    "nil config",
			config:  nil,
			wantErr: true,
		},
		{
			name: "empty server URLs uses defaults",
			config: &ClientConfig{
				ServerURLs: []string{},
				Timeout:    5,
			},
			wantErr: false,
		},
		{
			name: "valid config",
			config: &ClientConfig{
				ServerURLs: []string{"pool.ntp.org:123"},
				Timeout:    5,
				MaxRetries: 3,
				RetryDelay: 1,
			},
			wantErr: false,
		},
		{
			name: "server without port gets default port",
			config: &ClientConfig{
				ServerURLs: []string{"time.google.com"},
				Timeout:    5,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewNTPClient(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewNTPClient() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && client == nil {
				t.Error("NewNTPClient() returned nil client without error")
			}
			if client != nil {
				client.Close()
			}
		})
	}
}

func TestNTPClient_GetServerURLs(t *testing.T) {
	config := &ClientConfig{
		ServerURLs: []string{"pool.ntp.org:123", "time.google.com:123"},
		Timeout:    5,
	}

	client, err := NewNTPClient(config)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	urls := client.GetServerURLs()
	if len(urls) != 2 {
		t.Errorf("Expected 2 server URLs, got %d", len(urls))
	}

	// Verify that modifying the returned slice doesn't affect the client
	urls[0] = "modified"
	originalURLs := client.GetServerURLs()
	if originalURLs[0] == "modified" {
		t.Error("GetServerURLs() returned a reference to internal slice")
	}
}

func TestNTPClient_GetStatus(t *testing.T) {
	config := &ClientConfig{
		ServerURLs: []string{"pool.ntp.org:123"},
		Timeout:    5,
	}

	client, err := NewNTPClient(config)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	// Initially not synchronized
	synchronized, offset, lastSync := client.GetStatus()
	if synchronized {
		t.Error("Expected synchronized to be false initially")
	}
	if offset != 0 {
		t.Errorf("Expected offset to be 0 initially, got %v", offset)
	}
	if !lastSync.IsZero() {
		t.Errorf("Expected lastSync to be zero initially, got %v", lastSync)
	}
}

func TestNTPTimeConversion(t *testing.T) {
	// Test converting a known time
	testTime := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)

	// Convert to NTP format and back
	sec := uint32(testTime.Unix() + ntpEpochOffset)
	frac := uint32((uint64(testTime.Nanosecond()) << 32) / 1e9)

	result := ntpTimeToGoTime(sec, frac)

	// Should be within 1 second of original
	diff := testTime.Sub(result)
	if diff < -time.Second || diff > time.Second {
		t.Errorf("Time conversion error: original=%v, result=%v, diff=%v", testTime, result, diff)
	}
}

func TestEncodeDecodeUint32(t *testing.T) {
	tests := []uint32{
		0,
		1,
		255,
		256,
		65535,
		65536,
		0xFFFFFFFF,
		0x12345678,
	}

	for _, val := range tests {
		buf := make([]byte, 4)
		encodeUint32(buf, val)
		result := decodeUint32(buf)
		if result != val {
			t.Errorf("Encode/decode failed for %d: got %d", val, result)
		}
	}
}

// Integration test - only runs if network is available
func TestNTPClient_Query_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	config := &ClientConfig{
		ServerURLs: []string{
			"pool.ntp.org:123",
			"time.google.com:123",
		},
		Timeout:    10,
		MaxRetries: 3,
		RetryDelay: 1,
	}

	client, err := NewNTPClient(config)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	response, err := client.Query(ctx)
	if err != nil {
		t.Logf("NTP query failed (may be network issue): %v", err)
		t.Skip("Skipping - NTP servers not reachable")
	}

	// Validate response
	if response.ServerAddr == "" {
		t.Error("ServerAddr should not be empty")
	}
	if response.ServerTime.IsZero() {
		t.Error("ServerTime should not be zero")
	}
	if response.LocalTime.IsZero() {
		t.Error("LocalTime should not be zero")
	}
	if !response.Synchronized {
		t.Error("Synchronized should be true after successful query")
	}

	// Offset should be reasonable (within 1 hour)
	if response.Offset < -time.Hour || response.Offset > time.Hour {
		t.Errorf("Offset seems unreasonable: %v", response.Offset)
	}

	// Round trip should be positive and reasonable (under 10 seconds)
	if response.RoundTrip < 0 || response.RoundTrip > 10*time.Second {
		t.Errorf("RoundTrip seems unreasonable: %v", response.RoundTrip)
	}

	t.Logf("Query successful: server=%s, offset=%v, roundtrip=%v, stratum=%d",
		response.ServerAddr, response.Offset, response.RoundTrip, response.Stratum)
}

func TestNTPClient_Query_ContextCancellation(t *testing.T) {
	config := &ClientConfig{
		ServerURLs: []string{"192.0.2.1:123"}, // Non-routable IP
		Timeout:    30,
		MaxRetries: 10,
		RetryDelay: 1,
	}

	client, err := NewNTPClient(config)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	// Cancel context immediately
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = client.Query(ctx)
	if err == nil {
		t.Error("Expected error when context is cancelled")
	}
}
