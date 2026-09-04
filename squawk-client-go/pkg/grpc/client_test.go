package grpc

import "testing"

// TestParseServerAddress verifies scheme handling: grpcs:// selects a TLS
// channel, grpc:// and bare host:port stay plaintext (explicit opt-in).
// Regression: grpcs:// previously returned a hard error ("not yet
// supported"), and grpc:// unconditionally used insecure.NewCredentials(),
// leaking the bearer/license token in cleartext.
func TestParseServerAddress(t *testing.T) {
	tests := []struct {
		name       string
		serverAddr string
		wantAddr   string
		wantTLS    bool
		wantErr    bool
	}{
		{
			name:       "grpcs scheme selects TLS",
			serverAddr: "grpcs://dns.example.com:50052",
			wantAddr:   "dns.example.com:50052",
			wantTLS:    true,
		},
		{
			name:       "grpcs scheme without port uses default port",
			serverAddr: "grpcs://dns.example.com",
			wantAddr:   "dns.example.com:50052",
			wantTLS:    true,
		},
		{
			name:       "grpc scheme stays plaintext",
			serverAddr: "grpc://dns.example.com:50052",
			wantAddr:   "dns.example.com:50052",
			wantTLS:    false,
		},
		{
			name:       "bare host:port stays plaintext",
			serverAddr: "localhost:50052",
			wantAddr:   "localhost:50052",
			wantTLS:    false,
		},
		{
			name:       "bare host without port stays plaintext with default port",
			serverAddr: "localhost",
			wantAddr:   "localhost:50052",
			wantTLS:    false,
		},
		{
			name:       "missing hostname errors",
			serverAddr: "grpcs://:50052",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr, useTLS, err := parseServerAddress(tt.serverAddr)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseServerAddress(%q) error = %v, wantErr %v", tt.serverAddr, err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if addr != tt.wantAddr {
				t.Errorf("parseServerAddress(%q) addr = %q, want %q", tt.serverAddr, addr, tt.wantAddr)
			}
			if useTLS != tt.wantTLS {
				t.Errorf("parseServerAddress(%q) useTLS = %v, want %v", tt.serverAddr, useTLS, tt.wantTLS)
			}
		})
	}
}

// TestNewDNSClientWithTLS_GrpcsSelectsTLSCredentials verifies that a
// grpcs:// address builds successfully (grpc.NewClient does not dial
// eagerly, so this exercises the credential-selection path without a live
// server) and that an empty address is still rejected.
func TestNewDNSClientWithTLS_GrpcsSelectsTLSCredentials(t *testing.T) {
	c, err := NewDNSClientWithTLS("grpcs://dns.example.com:50052", "test-token", true, 0)
	if err != nil {
		t.Fatalf("NewDNSClientWithTLS() unexpected error: %v", err)
	}
	if c == nil {
		t.Fatal("NewDNSClientWithTLS() returned nil client without error")
	}
	if c.serverAddr != "dns.example.com:50052" {
		t.Errorf("serverAddr = %q, want %q", c.serverAddr, "dns.example.com:50052")
	}
	_ = c.Close()

	if _, err := NewDNSClientWithTLS("", "test-token", true, 0); err == nil {
		t.Error("NewDNSClientWithTLS(\"\", ...) expected error, got nil")
	}
}
