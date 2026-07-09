package metrics

import (
	"strings"

	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
)

// Metrics holds all Prometheus metrics for squawk DNS services.
// All metrics are namespaced with "squawk_" prefix.
type Metrics struct {
	// Counters
	QueriesTotal          *prometheus.CounterVec
	CacheLookupsTotal     *prometheus.CounterVec
	K8sWatcherEventsTotal *prometheus.CounterVec

	// Histograms
	QueryDuration          *prometheus.HistogramVec
	UpstreamDuration       *prometheus.HistogramVec
	K8sWatcherSyncDuration prometheus.Histogram

	// Gauges
	ZoneEntries  prometheus.Gauge
	ActiveQueries prometheus.Gauge

	// Registry
	Registry *prometheus.Registry
}

// New creates and registers all metrics, returning a new *Metrics instance.
// Uses a separate registry for clean isolation.
func New() *Metrics {
	registry := prometheus.NewRegistry()

	queriesTotal := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "squawk",
			Subsystem: "dns",
			Name:      "queries_total",
			Help:      "Total number of DNS queries processed",
		},
		[]string{"component", "qtype", "zone", "result"},
	)
	registry.MustRegister(queriesTotal)

	cacheLookupsTotal := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "squawk",
			Subsystem: "dns",
			Name:      "cache_lookups_total",
			Help:      "Total number of zone cache lookups",
		},
		[]string{"result"},
	)
	registry.MustRegister(cacheLookupsTotal)

	k8sWatcherEventsTotal := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "squawk",
			Subsystem: "k8s_watcher",
			Name:      "events_total",
			Help:      "Total number of Kubernetes watcher events",
		},
		[]string{"resource", "event"},
	)
	registry.MustRegister(k8sWatcherEventsTotal)

	queryDuration := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "squawk",
			Subsystem: "dns",
			Name:      "query_duration_seconds",
			Help:      "DNS query duration in seconds",
			Buckets:   []float64{0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5},
		},
		[]string{"component", "zone"},
	)
	registry.MustRegister(queryDuration)

	upstreamDuration := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "squawk",
			Subsystem: "dns",
			Name:      "upstream_duration_seconds",
			Help:      "DoH upstream query duration in seconds",
			Buckets:   []float64{0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5},
		},
		[]string{"upstream"},
	)
	registry.MustRegister(upstreamDuration)

	k8sWatcherSyncDuration := prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: "squawk",
			Subsystem: "k8s_watcher",
			Name:      "sync_duration_seconds",
			Help:      "Kubernetes informer initial sync duration in seconds",
			Buckets:   []float64{0.1, 0.25, 0.5, 1, 2.5, 5, 10},
		},
	)
	registry.MustRegister(k8sWatcherSyncDuration)

	zoneEntries := prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "squawk",
			Subsystem: "dns",
			Name:      "zone_entries",
			Help:      "Current number of entries in zone cache",
		},
	)
	registry.MustRegister(zoneEntries)

	activeQueries := prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "squawk",
			Subsystem: "dns",
			Name:      "active_queries",
			Help:      "Current number of in-flight DNS queries",
		},
	)
	registry.MustRegister(activeQueries)

	return &Metrics{
		QueriesTotal:           queriesTotal,
		CacheLookupsTotal:      cacheLookupsTotal,
		K8sWatcherEventsTotal:  k8sWatcherEventsTotal,
		QueryDuration:          queryDuration,
		UpstreamDuration:       upstreamDuration,
		K8sWatcherSyncDuration: k8sWatcherSyncDuration,
		ZoneEntries:            zoneEntries,
		ActiveQueries:          activeQueries,
		Registry:               registry,
	}
}

// DNSResultCode maps DNS response codes to result labels.
func DNSResultCode(rcode int) string {
	switch rcode {
	case dns.RcodeSuccess:
		return "success"
	case dns.RcodeNameError:
		return "nxdomain"
	case dns.RcodeServerFailure:
		return "servfail"
	default:
		return "other"
	}
}

// DNSTypeLabel converts a DNS type code to a metric label.
// Unknown types are collapsed to "other".
func DNSTypeLabel(qtype uint16) string {
	typeStr := dns.TypeToString[qtype]
	if typeStr == "" {
		return "other"
	}
	return strings.ToLower(typeStr)
}

// ZoneLabel determines the zone category for a query name.
// Returns "cluster_local" for cluster.local. suffix,
// "arpa" for in-addr.arpa. suffix, otherwise "external".
func ZoneLabel(qname, clusterDomain string) string {
	qname = strings.ToLower(qname)
	if strings.HasSuffix(qname, clusterDomain+".") || strings.HasSuffix(qname, "."+clusterDomain+".") {
		return "cluster_local"
	}
	if strings.HasSuffix(qname, "in-addr.arpa.") {
		return "arpa"
	}
	return "external"
}
