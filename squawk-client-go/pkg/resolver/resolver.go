package resolver

import (
	"context"
	"log"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/penguintechinc/squawk/squawk-client-go/pkg/client"
	"github.com/penguintechinc/squawk/squawk-client-go/pkg/metrics"
	"github.com/penguintechinc/squawk/squawk-client-go/pkg/zonecache"
)

// Resolver handles DNS queries by consulting a local zone cache
// for cluster.local and in-addr.arpa zones, and forwarding all other
// queries to a DoH server.
type Resolver struct {
	cache         *zonecache.Cache
	dohClient     *client.DoHClient
	metrics       *metrics.Metrics
	clusterDomain string
}

// New creates a new DNS resolver.
func New(cache *zonecache.Cache, doh *client.DoHClient, clusterDomain string) *Resolver {
	return NewWithMetrics(cache, doh, clusterDomain, nil)
}

// NewWithMetrics creates a new DNS resolver with optional metrics.
func NewWithMetrics(cache *zonecache.Cache, doh *client.DoHClient, clusterDomain string, m *metrics.Metrics) *Resolver {
	if clusterDomain == "" {
		clusterDomain = "cluster.local"
	}
	return &Resolver{
		cache:         cache,
		dohClient:     doh,
		metrics:       m,
		clusterDomain: clusterDomain,
	}
}

// ServeDNS implements the dns.Handler interface.
func (r *Resolver) ServeDNS(w dns.ResponseWriter, msg *dns.Msg) {
	if r.metrics != nil {
		r.metrics.ActiveQueries.Inc()
		defer r.metrics.ActiveQueries.Dec()
	}

	response := new(dns.Msg)
	response.SetReply(msg)
	response.RecursionAvailable = true

	// Process each question
	for _, q := range msg.Question {
		qstart := time.Now()
		qname := strings.ToLower(q.Name)
		zone := metrics.ZoneLabel(qname, r.clusterDomain)

		if strings.HasSuffix(qname, r.clusterDomain+".") || strings.HasSuffix(qname, "in-addr.arpa.") {
			r.handleClusterQuery(response, &q)
		} else {
			r.handleExternalQuery(response, &q)
		}

		log.Printf("DNS Query: %s %s from %s", q.Name, dns.TypeToString[q.Qtype], w.RemoteAddr())

		if r.metrics != nil {
			r.metrics.QueryDuration.WithLabelValues("k8s-dns", zone).Observe(time.Since(qstart).Seconds())
			r.metrics.QueriesTotal.WithLabelValues(
				"k8s-dns",
				metrics.DNSTypeLabel(q.Qtype),
				zone,
				metrics.DNSResultCode(response.Rcode),
			).Inc()
		}
	}

	if err := w.WriteMsg(response); err != nil {
		log.Printf("Failed to write DNS response: %v", err)
	}
}

// handleClusterQuery looks up records in the zone cache.
// Returns NXDOMAIN if not found.
func (r *Resolver) handleClusterQuery(response *dns.Msg, q *dns.Question) {
	qname := strings.ToLower(q.Name)

	// Ensure FQDN has trailing dot
	if !strings.HasSuffix(qname, ".") {
		qname += "."
	}

	// Look up in cache
	rrs := r.cache.Lookup(qname)

	// Record cache lookup result
	if r.metrics != nil {
		if rrs == nil {
			r.metrics.CacheLookupsTotal.WithLabelValues("miss").Inc()
		} else {
			r.metrics.CacheLookupsTotal.WithLabelValues("hit").Inc()
		}
	}

	if rrs == nil {
		// No records found, return NXDOMAIN
		response.SetRcode(response, dns.RcodeNameError)
		return
	}

	// Filter records by query type (if not ANY)
	if q.Qtype != dns.TypeANY {
		for _, rr := range rrs {
			if rr.Header().Rrtype == q.Qtype {
				response.Answer = append(response.Answer, rr)
			}
		}
	} else {
		response.Answer = append(response.Answer, rrs...)
	}

	// Mark as authoritative for cluster.local
	if strings.HasSuffix(qname, r.clusterDomain+".") {
		response.Authoritative = true
	}

	// If we have answers, success; otherwise NXDOMAIN
	if len(response.Answer) == 0 {
		response.SetRcode(response, dns.RcodeNameError)
	}
}

// handleExternalQuery forwards the query to the DoH server.
func (r *Resolver) handleExternalQuery(response *dns.Msg, q *dns.Question) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	qtype := dns.TypeToString[q.Qtype]

	// Start upstream timer
	upstreamStart := time.Now()

	// Query via DoH
	resp, err := r.dohClient.Query(ctx, q.Name, qtype)

	// Record upstream duration
	if r.metrics != nil {
		r.metrics.UpstreamDuration.WithLabelValues("doh").Observe(time.Since(upstreamStart).Seconds())
	}

	if err != nil {
		log.Printf("DoH query failed for %s: %v", q.Name, err)
		response.SetRcode(response, dns.RcodeServerFailure)
		return
	}

	// Convert DoH response to DNS records
	if resp.Status == 0 && len(resp.Answer) > 0 {
		for _, answer := range resp.Answer {
			rr := r.convertAnswerToRR(answer, q)
			if rr != nil {
				response.Answer = append(response.Answer, rr)
			}
		}
	} else {
		// No answer or error status
		if resp.Status == 3 {
			response.SetRcode(response, dns.RcodeNameError) // NXDOMAIN
		} else {
			response.SetRcode(response, dns.RcodeServerFailure)
		}
	}
}

// convertAnswerToRR converts a DoH answer to a DNS resource record.
func (r *Resolver) convertAnswerToRR(answer client.DNSRecord, question *dns.Question) dns.RR {
	// safeUint32 safely converts an int to uint32
	safeUint32 := func(value int) uint32 {
		if value < 0 {
			return 0
		}
		if value > 0xFFFFFFFF {
			return 0xFFFFFFFF
		}
		return uint32(value)
	}

	switch question.Qtype {
	case dns.TypeA:
		// Parse as IPv4 address
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
		// Parse as IPv6 address
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
	case dns.TypeSRV:
		// SRV data format: "priority weight port target"
		// For now, just return nil for unsupported types from DoH
		return nil
	}

	log.Printf("Unsupported DNS type %d for answer: %s", question.Qtype, answer.Data)
	return nil
}
