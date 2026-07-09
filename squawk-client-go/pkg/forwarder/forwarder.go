package forwarder

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/penguintechinc/squawk/squawk-client-go/pkg/client"
	"github.com/penguintechinc/squawk/squawk-client-go/pkg/metrics"
)

// safeUint32 safely converts an int to uint32, clamping to valid range
func safeUint32(value int) uint32 {
	if value < 0 {
		return 0
	}
	if value > 0xFFFFFFFF {
		return 0xFFFFFFFF
	}
	return uint32(value)
}

// Forwarder handles DNS forwarding from traditional DNS (UDP/TCP) to DNS-over-HTTPS
type Forwarder struct {
	dohClient   *client.DoHClient
	metrics     *metrics.Metrics
	udpAddr     string
	tcpAddr     string
	udpServer   *dns.Server
	tcpServer   *dns.Server
	listenUDP   bool
	listenTCP   bool
	running     bool
	stopCh      chan struct{}
	wg          sync.WaitGroup
	mu          sync.RWMutex
}

// Config holds the forwarder configuration
type Config struct {
	UDPAddress string `yaml:"udp_address" json:"udp_address"`
	TCPAddress string `yaml:"tcp_address" json:"tcp_address"`
	ListenUDP  bool   `yaml:"listen_udp" json:"listen_udp"`
	ListenTCP  bool   `yaml:"listen_tcp" json:"listen_tcp"`
}

// NewForwarder creates a new DNS forwarder
func NewForwarder(dohClient *client.DoHClient, config *Config) *Forwarder {
	return NewForwarderWithMetrics(dohClient, config, nil)
}

// NewForwarderWithMetrics creates a new DNS forwarder with optional metrics.
func NewForwarderWithMetrics(dohClient *client.DoHClient, config *Config, m *metrics.Metrics) *Forwarder {
	if config == nil {
		config = &Config{
			UDPAddress: "127.0.0.1:53",
			TCPAddress: "127.0.0.1:53",
			ListenUDP:  true,
			ListenTCP:  true,
		}
	}

	return &Forwarder{
		dohClient: dohClient,
		metrics:   m,
		udpAddr:   config.UDPAddress,
		tcpAddr:   config.TCPAddress,
		listenUDP: config.ListenUDP,
		listenTCP: config.ListenTCP,
		stopCh:    make(chan struct{}),
	}
}

// Start begins the DNS forwarding service
func (f *Forwarder) Start(ctx context.Context) error {
	f.mu.Lock()
	if f.running {
		f.mu.Unlock()
		return fmt.Errorf("forwarder is already running")
	}
	f.running = true
	f.mu.Unlock()

	dns.HandleFunc(".", f.handleDNSRequest)

	if f.listenUDP {
		f.udpServer = &dns.Server{
			Addr: f.udpAddr,
			Net:  "udp",
		}

		f.wg.Add(1)
		go func() {
			defer f.wg.Done()
			log.Printf("Starting UDP DNS forwarder on %s", f.udpAddr)
			if err := f.udpServer.ListenAndServe(); err != nil {
				log.Printf("UDP server error: %v", err)
			}
		}()
	}

	if f.listenTCP {
		f.tcpServer = &dns.Server{
			Addr: f.tcpAddr,
			Net:  "tcp",
		}

		f.wg.Add(1)
		go func() {
			defer f.wg.Done()
			log.Printf("Starting TCP DNS forwarder on %s", f.tcpAddr)
			if err := f.tcpServer.ListenAndServe(); err != nil {
				log.Printf("TCP server error: %v", err)
			}
		}()
	}

	// Wait for context cancellation or stop signal
	select {
	case <-ctx.Done():
		return f.Stop()
	case <-f.stopCh:
		return nil
	}
}

// Stop shuts down the DNS forwarding service
func (f *Forwarder) Stop() error {
	f.mu.Lock()
	if !f.running {
		f.mu.Unlock()
		return fmt.Errorf("forwarder is not running")
	}
	f.running = false
	f.mu.Unlock()

	log.Println("Shutting down DNS forwarder...")

	if f.udpServer != nil {
		if err := f.udpServer.Shutdown(); err != nil {
			log.Printf("Error shutting down UDP server: %v", err)
		}
	}

	if f.tcpServer != nil {
		if err := f.tcpServer.Shutdown(); err != nil {
			log.Printf("Error shutting down TCP server: %v", err)
		}
	}

	close(f.stopCh)
	f.wg.Wait()

	log.Println("DNS forwarder stopped")
	return nil
}

// handleDNSRequest processes incoming DNS requests
func (f *Forwarder) handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	// Track active queries
	if f.metrics != nil {
		f.metrics.ActiveQueries.Inc()
		defer f.metrics.ActiveQueries.Dec()
	}

	// Start timer for overall query duration
	start := time.Now()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Authoritative = false
	msg.RecursionAvailable = true

	// Process each question in the DNS message
	for _, q := range r.Question {
		// Convert DNS type to string
		qtype := dns.TypeToString[q.Qtype]

		log.Printf("DNS Query: %s %s from %s", q.Name, qtype, w.RemoteAddr())

		// Start upstream timer
		upstreamStart := time.Now()

		// Query via DNS-over-HTTPS
		resp, err := f.dohClient.Query(ctx, q.Name, qtype)

		// Record upstream duration
		if f.metrics != nil {
			f.metrics.UpstreamDuration.WithLabelValues("doh").Observe(time.Since(upstreamStart).Seconds())
		}

		if err != nil {
			log.Printf("DoH query failed for %s: %v", q.Name, err)
			msg.SetRcode(r, dns.RcodeServerFailure)
			// Record failed query
			if f.metrics != nil {
				f.metrics.QueriesTotal.WithLabelValues(
					"bridge",
					metrics.DNSTypeLabel(q.Qtype),
					"external",
					"servfail",
				).Inc()
			}
			continue
		}

		// Determine result code
		resultCode := metrics.DNSResultCode(resp.Status)

		// Convert DoH response to DNS records
		if resp.Status == 0 && len(resp.Answer) > 0 {
			for _, answer := range resp.Answer {
				rr := f.convertAnswerToRR(answer, q)
				if rr != nil {
					msg.Answer = append(msg.Answer, rr)
				}
			}
		} else {
			// No answer or error status
			if resp.Status == 3 {
				msg.SetRcode(r, dns.RcodeNameError) // NXDOMAIN
			} else {
				msg.SetRcode(r, dns.RcodeServerFailure)
			}
		}

		// Record successful query
		if f.metrics != nil {
			f.metrics.QueriesTotal.WithLabelValues(
				"bridge",
				metrics.DNSTypeLabel(q.Qtype),
				"external",
				resultCode,
			).Inc()
		}
	}

	// Send response
	if err := w.WriteMsg(msg); err != nil {
		log.Printf("Failed to write DNS response: %v", err)
	}

	// Record overall query duration
	if f.metrics != nil {
		f.metrics.QueryDuration.WithLabelValues("bridge", "external").Observe(time.Since(start).Seconds())
	}
}

// convertAnswerToRR converts a DoH answer to a DNS resource record
func (f *Forwarder) convertAnswerToRR(answer client.DNSRecord, question dns.Question) dns.RR {
	// Create appropriate RR based on type
	switch question.Qtype {
	case dns.TypeA:
		if ip := net.ParseIP(answer.Data); ip != nil && ip.To4() != nil {
			return &dns.A{
				Hdr: dns.RR_Header{
					Name:   question.Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    safeUint32(answer.TTL),
				},
				A: ip.To4(),
			}
		}
	case dns.TypeAAAA:
		if ip := net.ParseIP(answer.Data); ip != nil && ip.To16() != nil {
			return &dns.AAAA{
				Hdr: dns.RR_Header{
					Name:   question.Name,
					Rrtype: dns.TypeAAAA,
					Class:  dns.ClassINET,
					Ttl:    safeUint32(answer.TTL),
				},
				AAAA: ip.To16(),
			}
		}
	case dns.TypeCNAME:
		return &dns.CNAME{
			Hdr: dns.RR_Header{
				Name:   question.Name,
				Rrtype: dns.TypeCNAME,
				Class:  dns.ClassINET,
				Ttl:    safeUint32(answer.TTL),
			},
			Target: dns.Fqdn(answer.Data),
		}
	case dns.TypeMX:
		return &dns.MX{
			Hdr: dns.RR_Header{
				Name:   question.Name,
				Rrtype: dns.TypeMX,
				Class:  dns.ClassINET,
				Ttl:    safeUint32(answer.TTL),
			},
			Mx: dns.Fqdn(answer.Data),
			// Priority would need to be parsed from Data if available
		}
	case dns.TypeTXT:
		return &dns.TXT{
			Hdr: dns.RR_Header{
				Name:   question.Name,
				Rrtype: dns.TypeTXT,
				Class:  dns.ClassINET,
				Ttl:    safeUint32(answer.TTL),
			},
			Txt: []string{answer.Data},
		}
	case dns.TypeNS:
		return &dns.NS{
			Hdr: dns.RR_Header{
				Name:   question.Name,
				Rrtype: dns.TypeNS,
				Class:  dns.ClassINET,
				Ttl:    safeUint32(answer.TTL),
			},
			Ns: dns.Fqdn(answer.Data),
		}
	}

	// For unsupported types, create a generic RR
	log.Printf("Unsupported DNS type %d for answer: %s", question.Qtype, answer.Data)
	return nil
}

// IsRunning returns whether the forwarder is currently running
func (f *Forwarder) IsRunning() bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.running
}