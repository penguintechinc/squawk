package client

import "testing"

// TestNormalizeServerURL_DefaultPath verifies that a server URL without an
// explicit path is defaulted to the Squawk server's actual route
// (/dns/query), not the RFC 8484 default (/dns-query) which the Squawk
// server does not serve. Regression: deployed clients 404ed on every query.
func TestNormalizeServerURL_DefaultPath(t *testing.T) {
	tests := []struct {
		name      string
		serverURL string
		want      string
	}{
		{
			name:      "no path defaults to squawk route",
			serverURL: "https://dns.example.com:8443",
			want:      "https://dns.example.com:8443/dns/query",
		},
		{
			name:      "root path defaults to squawk route",
			serverURL: "https://dns.example.com:8443/",
			want:      "https://dns.example.com:8443/dns/query",
		},
		{
			name:      "explicit path is preserved",
			serverURL: "https://dns.example.com:8443/custom/path",
			want:      "https://dns.example.com:8443/custom/path",
		},
		{
			name:      "known google provider keeps its own default",
			serverURL: "https://dns.google",
			want:      "https://dns.google/resolve",
		},
		{
			name:      "known cloudflare provider keeps its own default",
			serverURL: "https://cloudflare-dns.com",
			want:      "https://cloudflare-dns.com/dns-query",
		},
		{
			name:      "invalid URL returned unchanged",
			serverURL: "://not-a-url",
			want:      "://not-a-url",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeServerURL(tt.serverURL)
			if got != tt.want {
				t.Errorf("normalizeServerURL(%q) = %q, want %q", tt.serverURL, got, tt.want)
			}
		})
	}
}
