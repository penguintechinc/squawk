package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/miekg/dns"
	"github.com/penguintechinc/squawk/dns-client-go/pkg/client"
	"github.com/penguintechinc/squawk/dns-client-go/pkg/k8swatcher"
	"github.com/penguintechinc/squawk/dns-client-go/pkg/metrics"
	"github.com/penguintechinc/squawk/dns-client-go/pkg/resolver"
	"github.com/penguintechinc/squawk/dns-client-go/pkg/zonecache"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/cobra"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

var (
	serverURL      string
	authToken      string
	udpAddress     string
	tcpAddress     string
	clusterDomain  string
	kubeconfig     string
	logLevel       string
	version        = "1.0.0"
)

// HealthResponse represents the health check response.
type HealthResponse struct {
	Status string `json:"status"`
}

func main() {
	rootCmd := &cobra.Command{
		Use:   "squawk-k8s-dns",
		Short: "Kubernetes-aware DNS server that bridges K8s cluster.local with DoH",
		Long: `squawk-k8s-dns serves DNS queries for cluster.local from Kubernetes API,
and forwards all other queries to a DoH (DNS-over-HTTPS) server.`,
	}

	serveCmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the K8s DNS server",
		RunE:  runServe,
	}

	// Register flags
	serveCmd.Flags().StringVar(&serverURL, "server-url", os.Getenv("SQUAWK_SERVER_URL"), "DoH server URL (required)")
	serveCmd.Flags().StringVar(&authToken, "auth-token", os.Getenv("SQUAWK_AUTH_TOKEN"), "Bearer token for DoH auth")
	serveCmd.Flags().StringVar(&udpAddress, "udp-address", os.Getenv("SQUAWK_UDP_ADDRESS"), "UDP DNS listen address (default 0.0.0.0:5300)")
	serveCmd.Flags().StringVar(&tcpAddress, "tcp-address", os.Getenv("SQUAWK_TCP_ADDRESS"), "TCP DNS listen address (default 0.0.0.0:5300)")
	serveCmd.Flags().StringVar(&clusterDomain, "cluster-domain", getEnvOrDefault("SQUAWK_CLUSTER_DOMAIN", "cluster.local"), "Kubernetes cluster domain")
	serveCmd.Flags().StringVar(&kubeconfig, "kubeconfig", os.Getenv("SQUAWK_KUBECONFIG"), "Path to kubeconfig (empty = in-cluster)")
	serveCmd.Flags().StringVar(&logLevel, "log-level", getEnvOrDefault("LOG_LEVEL", "info"), "Log level (debug, info, warn, error)")

	rootCmd.AddCommand(serveCmd)

	if err := rootCmd.Execute(); err != nil {
		log.Fatalf("Error: %v", err)
	}
}

func runServe(cmd *cobra.Command, args []string) error {
	// Validate required flags
	if serverURL == "" {
		return fmt.Errorf("SQUAWK_SERVER_URL is required")
	}

	// Set defaults
	if udpAddress == "" {
		udpAddress = "0.0.0.0:5300"
	}
	if tcpAddress == "" {
		tcpAddress = "0.0.0.0:5300"
	}

	log.Printf("squawk-k8s-dns %s starting", version)
	log.Printf("Server URL: %s", serverURL)
	log.Printf("UDP listen: %s", udpAddress)
	log.Printf("TCP listen: %s", tcpAddress)
	log.Printf("Cluster domain: %s", clusterDomain)

	// Create zone cache
	cache := zonecache.New()
	log.Println("Zone cache created")

	// Create metrics registry
	m := metrics.New()
	log.Println("Metrics registry created")

	// Build Kubernetes client
	var kubeClient kubernetes.Interface
	var err error

	if kubeconfig == "" {
		// In-cluster config
		config, err := rest.InClusterConfig()
		if err != nil {
			return fmt.Errorf("failed to load in-cluster kubeconfig: %w", err)
		}
		kubeClient, err = kubernetes.NewForConfig(config)
		if err != nil {
			return fmt.Errorf("failed to create kubernetes client: %w", err)
		}
		log.Println("Using in-cluster Kubernetes config")
	} else {
		// File-based config
		config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			return fmt.Errorf("failed to load kubeconfig: %w", err)
		}
		kubeClient, err = kubernetes.NewForConfig(config)
		if err != nil {
			return fmt.Errorf("failed to create kubernetes client: %w", err)
		}
		log.Printf("Using kubeconfig: %s", kubeconfig)
	}

	// Create DoH client
	dohConfig := &client.Config{
		ServerURL:  serverURL,
		AuthToken:  authToken,
		VerifySSL:  true,
		MaxRetries: 3,
		RetryDelay: 2,
	}
	dohClient, err := client.NewDoHClient(dohConfig)
	if err != nil {
		return fmt.Errorf("failed to create DoH client: %w", err)
	}
	defer dohClient.Close()

	// Create resolver with metrics
	res := resolver.NewWithMetrics(cache, dohClient, clusterDomain, m)

	// Register resolver as DNS handler
	dns.HandleFunc(".", res.ServeDNS)

	// Create watcher with metrics
	watcher := k8swatcher.NewWithMetrics(cache, kubeClient, clusterDomain, m)

	// Start watcher
	watchCtx, watchCancel := context.WithCancel(context.Background())
	defer watchCancel()
	if err := watcher.Start(watchCtx); err != nil {
		return fmt.Errorf("failed to start k8s watcher: %w", err)
	}

	// DNS servers
	var wg sync.WaitGroup
	errors := make(chan error, 2)

	// Start UDP DNS server
	wg.Add(1)
	go func() {
		defer wg.Done()
		udpServer := &dns.Server{
			Addr: udpAddress,
			Net:  "udp",
		}
		log.Printf("Starting UDP DNS server on %s", udpAddress)
		if err := udpServer.ListenAndServe(); err != nil {
			errors <- fmt.Errorf("UDP server error: %w", err)
		}
	}()

	// Start TCP DNS server
	wg.Add(1)
	go func() {
		defer wg.Done()
		tcpServer := &dns.Server{
			Addr: tcpAddress,
			Net:  "tcp",
		}
		log.Printf("Starting TCP DNS server on %s", tcpAddress)
		if err := tcpServer.ListenAndServe(); err != nil {
			errors <- fmt.Errorf("TCP server error: %w", err)
		}
	}()

	// Start health check + metrics HTTP server
	wg.Add(1)
	synced := make(chan struct{})
	close(synced) // Already synced before reaching here
	go func() {
		defer wg.Done()
		startHealthServer(synced, m)
	}()

	// Wait for interrupt signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	select {
	case <-sigCh:
		log.Println("Received shutdown signal")
	case err := <-errors:
		log.Printf("Server error: %v", err)
	}

	// Graceful shutdown
	watchCancel()
	watcher.Stop()
	dns.HandleRemove(".")

	// Give servers time to shut down
	time.Sleep(1 * time.Second)

	log.Println("Shutdown complete")
	return nil
}

// startHealthServer starts the health check HTTP server on :8081.
func startHealthServer(readyCh <-chan struct{}, m *metrics.Metrics) {
	mux := http.NewServeMux()

	// Liveness probe
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(HealthResponse{Status: "ok"})
	})

	// Readiness probe
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-readyCh:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(HealthResponse{Status: "ok"})
		default:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			json.NewEncoder(w).Encode(HealthResponse{Status: "not ready"})
		}
	})

	// Prometheus metrics endpoint
	mux.Handle("/metrics", promhttp.HandlerFor(m.Registry, promhttp.HandlerOpts{}))

	server := &http.Server{
		Addr:    ":8081",
		Handler: mux,
	}

	log.Println("Starting health check server on :8081 (/healthz, /readyz, /metrics)")
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Printf("Health server error: %v", err)
	}
}

// getEnvOrDefault returns the value of env var, or the default if not set.
func getEnvOrDefault(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}
