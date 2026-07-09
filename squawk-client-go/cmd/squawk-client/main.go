package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/penguintechinc/squawk/squawk-client-go/pkg/client"
	"github.com/penguintechinc/squawk/squawk-client-go/pkg/config"
	"github.com/penguintechinc/squawk/squawk-client-go/pkg/forwarder"
	grpcclient "github.com/penguintechinc/squawk/squawk-client-go/pkg/grpc"
	"github.com/penguintechinc/squawk/squawk-client-go/pkg/license"
	"github.com/penguintechinc/squawk/squawk-client-go/pkg/logger"
	"github.com/penguintechinc/squawk/squawk-client-go/pkg/metrics"
	"github.com/penguintechinc/squawk/squawk-client-go/pkg/performance"
	timeservice "github.com/penguintechinc/squawk/squawk-client-go/pkg/time"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/cobra"
)

var (
	// Global flags
	configFile  string
	domain      string
	recordType  string
	serverURL   string
	authToken   string
	clientCert  string
	clientKey   string
	caCert      string
	verifySSL   bool
	udpForward  bool
	tcpForward  bool
	verbose     bool
	jsonOutput  bool
	enablePerformanceMonitoring bool
	useGrpc     bool
	batchFile   string

	// New feature and transport flags
	enabledFeatures   string // --features "dns,dhcp,ntp"
	communicationMode string // --communication "http1|http2|http3"

	// DHCP flags
	dhcpServerURL string
	dhcpInterface string
	dhcpIntercept bool

	// NTP flags
	ntpServerURL string
	ntpPort      int
	ntpIntercept bool

	// Version information
	version   = "1.0.0"
	buildTime = "unknown"
	gitCommit = "unknown"
)

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

var rootCmd = &cobra.Command{
	Use:   "squawk-dns-client",
	Short: "Squawk DNS-over-HTTPS Client",
	Long: `A DNS-over-HTTPS client with mTLS support and local DNS forwarding capabilities.
Compatible with the Squawk DNS server and supports bearer token authentication.`,
	Version: fmt.Sprintf("%s (built %s, commit %s)", version, buildTime, gitCommit),
	Run:     runClient,
}

func init() {
	// Global flags
	rootCmd.PersistentFlags().StringVarP(&configFile, "config", "c", "", "Configuration file path")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")
	
	// DNS query flags
	rootCmd.Flags().StringVarP(&domain, "domain", "d", "", "Domain to query (required)")
	rootCmd.Flags().StringVarP(&recordType, "type", "t", "A", "DNS record type")
	rootCmd.Flags().BoolVarP(&jsonOutput, "json", "j", false, "Output in JSON format")
	
	// Server connection flags
	rootCmd.Flags().StringVarP(&serverURL, "server", "s", "", "DNS server URL")
	rootCmd.Flags().StringVarP(&authToken, "auth", "a", "", "Authentication token")
	
	// mTLS flags
	rootCmd.Flags().StringVar(&clientCert, "client-cert", "", "Client certificate file for mTLS")
	rootCmd.Flags().StringVar(&clientKey, "client-key", "", "Client private key file for mTLS")
	rootCmd.Flags().StringVar(&caCert, "ca-cert", "", "CA certificate file for server verification")
	rootCmd.Flags().BoolVar(&verifySSL, "verify-ssl", true, "Verify SSL/TLS certificates")
	
	// DNS forwarding flags
	rootCmd.Flags().BoolVarP(&udpForward, "udp", "u", false, "Enable UDP DNS forwarding on port 53")
	rootCmd.Flags().BoolVarP(&tcpForward, "tcp", "T", false, "Enable TCP DNS forwarding on port 53")
	
	// Performance monitoring flags
	rootCmd.Flags().BoolVar(&enablePerformanceMonitoring, "performance", false, "Enable DNS performance monitoring (Enterprise feature)")

	// gRPC flags
	rootCmd.Flags().BoolVarP(&useGrpc, "grpc", "g", true, "Use gRPC protocol (default: true, fallback to REST if unavailable)")
	rootCmd.Flags().StringVarP(&batchFile, "batch", "b", "", "Batch query file with domains (one per line)")

	// Feature flags
	rootCmd.Flags().StringVar(&enabledFeatures, "features", "dns", "Enabled features: dns,dhcp,ntp (comma-separated)")
	rootCmd.Flags().StringVar(&communicationMode, "communication", "http2", "Protocol: http1 (REST), http2 (gRPC), http3 (QUIC)")

	// DHCP flags
	rootCmd.Flags().StringVar(&dhcpServerURL, "dhcp-server", "", "DHCP server URL")
	rootCmd.Flags().StringVar(&dhcpInterface, "dhcp-interface", "", "Network interface for DHCP intercept")
	rootCmd.Flags().BoolVar(&dhcpIntercept, "dhcp-intercept", false, "Enable DHCP port interception (requires root)")

	// NTP flags
	rootCmd.Flags().StringVar(&ntpServerURL, "ntp-server", "", "NTP server URL")
	rootCmd.Flags().IntVar(&ntpPort, "ntp-port", 123, "Local NTP port for interception")
	rootCmd.Flags().BoolVar(&ntpIntercept, "ntp-intercept", false, "Enable NTP port interception (requires root)")

	// Add subcommands
	rootCmd.AddCommand(forwardCmd)
	rootCmd.AddCommand(configCmd)
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(licenseCmd)
	rootCmd.AddCommand(timeCmd)
}

// runClient is the main client function
func runClient(cmd *cobra.Command, args []string) {
	// Load configuration
	cfg, err := loadConfiguration()
	if err != nil {
		log.Fatalf("Configuration error: %v", err)
	}

	// Override config with command line flags
	overrideConfigWithFlags(cmd, cfg)

	if verbose {
		fmt.Println(cfg.String())
	}

	// Check if license is configured - skip validation if not (backward compatibility)
	if cfg.License.LicenseKey != "" || cfg.License.UserToken != "" {
		// Validate license before proceeding
		validator := license.NewValidator(cfg.License)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		isValid, err := validator.IsValid(ctx)
		if err != nil {
			if verbose {
				fmt.Printf("License validation warning: %v\n", err)
			}
			// Allow offline operation for now, but warn user
			fmt.Println("Warning: Could not validate license. Some features may be restricted.")
		} else if !isValid {
			fmt.Println("ERROR: Invalid or expired license. Please check your license key or user token.")
			fmt.Println("Contact your administrator for license assistance.")
			os.Exit(1)
		} else if verbose {
			fmt.Println("✓ License validated successfully")
			if info, err := validator.GetLicenseInfo(ctx); err == nil {
				fmt.Println(info)
			}
		}
	} else if verbose {
		fmt.Println("Note: No license configured. Running in compatibility mode.")
		fmt.Println("For premium features, configure SQUAWK_LICENSE_KEY or SQUAWK_USER_TOKEN.")
	}

	// Use license user token for DNS requests if available and no explicit auth token set
	if cfg.License.UserToken != "" && cfg.Client.AuthToken == "" {
		cfg.Client.AuthToken = cfg.License.UserToken
		if verbose {
			fmt.Println("Using license user token for DNS authentication")
		}
	}

	// Validate domain or batch file is provided
	if cfg.Domain == "" && batchFile == "" {
		fmt.Fprintf(os.Stderr, "Error: domain is required. Use -d <domain> or -b <file> or set SQUAWK_DOMAIN environment variable.\n")
		os.Exit(1)
	}

	// Try to use gRPC if enabled and URL supports it
	var grpcClient *grpcclient.DNSClient
	var dohClient *client.DoHClient

	if useGrpc && (strings.HasPrefix(cfg.Client.ServerURL, "grpc://") || strings.HasPrefix(cfg.Client.ServerURL, "grpc:")) {
		if verbose {
			fmt.Println("Attempting to create gRPC client...")
		}
		grpcClient, err = grpcclient.NewDNSClient(cfg.Client.ServerURL, cfg.Client.AuthToken)
		if err != nil {
			if verbose {
				fmt.Printf("Warning: Failed to create gRPC client: %v\n", err)
				fmt.Println("Falling back to REST DNS-over-HTTPS...")
			}
			grpcClient = nil
		} else if verbose {
			fmt.Println("Successfully created gRPC client")
		}
	}

	// If gRPC not available, use DoH client
	if grpcClient == nil {
		dohClient, err = client.NewDoHClient(cfg.Client)
		if err != nil {
			log.Fatalf("Failed to create DoH client: %v", err)
		}
		defer func() {
			if err := dohClient.Close(); err != nil {
				log.Printf("Warning: failed to close DoH client: %v", err)
			}
		}()
	} else {
		defer func() {
			if err := grpcClient.Close(); err != nil {
				log.Printf("Warning: failed to close gRPC client: %v", err)
			}
		}()
	}

	// If forwarding is enabled, start forwarder with DoH client
	if cfg.Forwarder.ListenUDP || cfg.Forwarder.ListenTCP {
		if grpcClient != nil {
			// Forwarder requires DoH client, so create one as fallback
			if verbose {
				fmt.Println("Forwarder requires REST client, switching to DoH client")
			}
			dohClient, err = client.NewDoHClient(cfg.Client)
			if err != nil {
				log.Fatalf("Failed to create DoH client for forwarder: %v", err)
			}
			defer func() {
				if err := dohClient.Close(); err != nil {
					log.Printf("Warning: failed to close DoH client: %v", err)
				}
			}()
		}
		runForwarder(dohClient, cfg)
		return
	}

	// Handle batch queries
	if batchFile != "" {
		// #nosec G304 -- batchFile is from user-provided command-line flag, not arbitrary input
		data, err := os.ReadFile(batchFile)
		if err != nil {
			log.Fatalf("Failed to read batch file: %v", err)
		}

		domains := strings.Split(strings.TrimSpace(string(data)), "\n")
		if verbose {
			fmt.Printf("Batch querying %d domains from %s\n", len(domains), batchFile)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
		defer cancel()

		if grpcClient != nil {
			// Use gRPC batch query
			results, err := grpcClient.BatchQuery(ctx, domains, cfg.RecordType)
			if err != nil {
				log.Fatalf("Batch DNS query failed: %v", err)
			}

			for i, domain := range domains {
				domain = strings.TrimSpace(domain)
				if i < len(results) {
					result := results[i]
					if jsonOutput {
						jsonData, _ := json.MarshalIndent(result, "", "  ")
						fmt.Printf("%s: %s\n", domain, string(jsonData))
					} else {
						fmt.Printf("%s: Status %d\n", domain, result.Status)
						if len(result.Answers) > 0 {
							for _, answer := range result.Answers {
								fmt.Printf("  %s -> %s\n", answer.Name, answer.Data)
							}
						}
					}
				}
			}
		} else {
			// Use sequential DoH queries
			for _, domain := range domains {
				domain = strings.TrimSpace(domain)
				if domain == "" {
					continue
				}
				response, err := dohClient.Query(ctx, domain, cfg.RecordType)
				if err != nil {
					fmt.Printf("%s: Error - %v\n", domain, err)
					continue
				}

				if jsonOutput {
					jsonData, _ := json.MarshalIndent(response, "", "  ")
					fmt.Printf("%s: %s\n", domain, string(jsonData))
				} else {
					printDNSResponse(response)
				}
			}
		}
		return
	}

	// Perform single DNS query
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if grpcClient != nil {
		response, err := grpcClient.Query(ctx, cfg.Domain, cfg.RecordType)
		if err != nil {
			log.Fatalf("DNS query failed: %v", err)
		}

		if jsonOutput {
			jsonData, _ := json.MarshalIndent(response, "", "  ")
			fmt.Println(string(jsonData))
		} else {
			fmt.Printf("Query: %s (%s)\n", cfg.Domain, cfg.RecordType)
			fmt.Printf("Status: %d\n", response.Status)
			if len(response.Answers) > 0 {
				fmt.Println("Answers:")
				for _, answer := range response.Answers {
					fmt.Printf("  %s -> %s (TTL: %d)\n", answer.Name, answer.Data, answer.Ttl)
				}
			}
		}
	} else {
		response, err := dohClient.Query(ctx, cfg.Domain, cfg.RecordType)
		if err != nil {
			log.Fatalf("DNS query failed: %v", err)
		}

		// Output results
		if jsonOutput {
			jsonData, _ := json.MarshalIndent(response, "", "  ")
			fmt.Println(string(jsonData))
		} else {
			printDNSResponse(response)
		}
	}
}

// loadConfiguration loads the configuration from file and environment
func loadConfiguration() (*config.AppConfig, error) {
	return config.LoadConfig(configFile)
}

// overrideConfigWithFlags overrides configuration with command line flags
func overrideConfigWithFlags(cmd *cobra.Command, cfg *config.AppConfig) {
	if domain != "" {
		cfg.Domain = domain
	}
	if recordType != "" {
		cfg.RecordType = recordType
	}
	if serverURL != "" {
		cfg.Client.ServerURL = serverURL
	}
	if authToken != "" {
		cfg.Client.AuthToken = authToken
	}
	if clientCert != "" {
		cfg.Client.ClientCert = clientCert
	}
	if clientKey != "" {
		cfg.Client.ClientKey = clientKey
	}
	if caCert != "" {
		cfg.Client.CaCert = caCert
	}
	if cmd.Flags().Changed("verify-ssl") {
		cfg.Client.VerifySSL = verifySSL
	}
	if udpForward {
		cfg.Forwarder.ListenUDP = true
	}
	if tcpForward {
		cfg.Forwarder.ListenTCP = true
	}

	// Features configuration
	if cmd.Flags().Changed("features") && enabledFeatures != "" {
		cfg.Features.DNS = false
		cfg.Features.DHCP = false
		cfg.Features.NTP = false
		for _, feature := range strings.Split(enabledFeatures, ",") {
			feature = strings.TrimSpace(strings.ToLower(feature))
			switch feature {
			case "dns":
				cfg.Features.DNS = true
			case "dhcp":
				cfg.Features.DHCP = true
			case "ntp":
				cfg.Features.NTP = true
			}
		}
	}

	// Transport/Communication mode
	if cmd.Flags().Changed("communication") && communicationMode != "" {
		cfg.Transport.Mode = strings.ToLower(strings.TrimSpace(communicationMode))
	}

	// DHCP configuration
	if dhcpServerURL != "" {
		cfg.DHCP.ServerURL = dhcpServerURL
	}
	if dhcpInterface != "" {
		cfg.DHCP.Interface = dhcpInterface
	}
	if cmd.Flags().Changed("dhcp-intercept") {
		cfg.DHCP.EnableIntercept = dhcpIntercept
	}

	// NTP configuration
	if ntpServerURL != "" {
		cfg.NTP.ServerURL = ntpServerURL
	}
	if cmd.Flags().Changed("ntp-port") {
		cfg.NTP.ListenPort = ntpPort
	}
	if cmd.Flags().Changed("ntp-intercept") {
		cfg.NTP.EnableIntercept = ntpIntercept
	}
}

// runForwarder starts the DNS forwarder service
func runForwarder(dohClient *client.DoHClient, cfg *config.AppConfig) {
	// Create metrics registry
	m := metrics.New()

	fwd := forwarder.NewForwarderWithMetrics(dohClient, cfg.Forwarder, m)

	// Handle graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Setup signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Setup performance monitoring if enabled
	var perfMonitor *performance.DNSPerformanceMonitor
	if enablePerformanceMonitoring {
		// Create simple logger
		log := logger.NewSimpleLogger(verbose)

		// Initialize performance monitor
		perfMonitor = performance.NewDNSPerformanceMonitor(cfg.Client, log)

		if err := perfMonitor.Start(); err != nil {
			log.Printf("Failed to start performance monitoring: %v", err)
		} else if verbose {
			fmt.Println("✓ DNS performance monitoring enabled")
		}
	}

	// Start metrics HTTP server
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		startMetricsServer(m)
	}()

	// Start forwarder in goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := fwd.Start(ctx); err != nil {
			log.Printf("Forwarder error: %v", err)
		}
	}()

	// Wait for shutdown signal
	<-sigChan
	log.Println("Received shutdown signal, stopping services...")

	// Stop performance monitoring first
	if perfMonitor != nil {
		if err := perfMonitor.Stop(); err != nil {
			log.Printf("Error stopping performance monitor: %v", err)
		}
	}

	cancel()

	// Give some time for graceful shutdown
	time.Sleep(1 * time.Second)
	wg.Wait()
}

// startMetricsServer starts the Prometheus metrics HTTP server on :2112
func startMetricsServer(m *metrics.Metrics) {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(m.Registry, promhttp.HandlerOpts{}))

	server := &http.Server{
		Addr:              ":2112",
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	log.Println("Starting metrics server on :2112/metrics")
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Printf("Metrics server error: %v", err)
	}
}

// printDNSResponse prints the DNS response in a human-readable format
func printDNSResponse(response *client.DNSResponse) {
	fmt.Printf("DNS Response Status: %d\n", response.Status)
	
	if response.Comment != "" {
		fmt.Printf("Comment: %s\n", response.Comment)
	}

	if len(response.Answer) > 0 {
		fmt.Println("Answers:")
		for _, answer := range response.Answer {
			fmt.Printf("  %s -> %s (TTL: %d)\n", answer.Name, answer.Data, answer.TTL)
		}
	} else {
		fmt.Println("No answers found")
	}
}

// Forward command
var forwardCmd = &cobra.Command{
	Use:   "forward",
	Short: "Start DNS forwarding service",
	Long: `Start the DNS forwarding service to forward traditional DNS queries to DNS-over-HTTPS.
This will listen on the configured UDP and/or TCP addresses and forward all DNS queries
to the configured DoH server.`,
	Run: func(cmd *cobra.Command, args []string) {
		// Load configuration
		cfg, err := loadConfiguration()
		if err != nil {
			log.Fatalf("Configuration error: %v", err)
		}

		// Override with flags
		overrideConfigWithFlags(cmd, cfg)

		// Force forwarding to be enabled
		if !udpForward && !tcpForward {
			cfg.Forwarder.ListenUDP = true
			cfg.Forwarder.ListenTCP = true
		}

		if verbose {
			fmt.Println(cfg.String())
		}

		// Check if license is configured for forwarder
		if cfg.License.LicenseKey != "" || cfg.License.UserToken != "" {
			// Validate license before starting forwarder
			validator := license.NewValidator(cfg.License)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			isValid, err := validator.IsValid(ctx)
			if err != nil {
				fmt.Printf("Warning: Could not validate license: %v\n", err)
				fmt.Println("DNS forwarding will continue, but some features may be restricted.")
			} else if !isValid {
				fmt.Println("ERROR: Invalid or expired license required for DNS forwarding service.")
				fmt.Println("Contact your administrator for license assistance.")
				os.Exit(1)
			} else if verbose {
				fmt.Println("✓ License validated successfully")
			}
		} else if verbose {
			fmt.Println("Note: No license configured. DNS forwarding running in compatibility mode.")
			fmt.Println("For premium features, configure SQUAWK_LICENSE_KEY or SQUAWK_USER_TOKEN.")
		}

		// Use license user token for DNS requests if available and no explicit auth token set
		if cfg.License.UserToken != "" && cfg.Client.AuthToken == "" {
			cfg.Client.AuthToken = cfg.License.UserToken
			if verbose {
				fmt.Println("Using license user token for DNS authentication")
			}
		}

		// Create DoH client
		dohClient, err := client.NewDoHClient(cfg.Client)
		if err != nil {
			log.Fatalf("Failed to create DoH client: %v", err)
		}
		defer func() {
		if err := dohClient.Close(); err != nil {
			log.Printf("Warning: failed to close DoH client: %v", err)
		}
	}()

		// Run forwarder
		runForwarder(dohClient, cfg)
	},
}

// Config command
var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Configuration management commands",
	Long:  "Commands for managing configuration files and displaying current settings",
}

var configShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show current configuration",
	Run: func(cmd *cobra.Command, args []string) {
		cfg, err := loadConfiguration()
		if err != nil {
			log.Fatalf("Configuration error: %v", err)
		}
		fmt.Println(cfg.String())
	},
}

var configEnvCmd = &cobra.Command{
	Use:   "env",
	Short: "Show supported environment variables",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Supported Environment Variables:")
		fmt.Println("=================================")
		for _, env := range config.GetEnvVarList() {
			value := os.Getenv(env)
			if value != "" {
				if strings.Contains(strings.ToLower(env), "token") {
					value = "***masked***"
				}
				fmt.Printf("%-25s = %s\n", env, value)
			} else {
				fmt.Printf("%-25s = (not set)\n", env)
			}
		}
	},
}

var configGenerateCmd = &cobra.Command{
	Use:   "generate [filename]",
	Short: "Generate example configuration file",
	Args:  cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		filename := "squawk-client.yaml"
		if len(args) > 0 {
			filename = args[0]
		}

		cfg := config.DefaultConfig()
		cfg.Domain = "example.com"
		cfg.Client.ServerURL = "https://dns.example.com:8443"
		cfg.Client.AuthToken = "your-token-here"

		if err := config.SaveConfig(cfg, filename); err != nil {
			log.Fatalf("Failed to generate config: %v", err)
		}

		fmt.Printf("Generated example configuration: %s\n", filename)
	},
}

// Version command
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("Squawk DNS Client (Go)\n")
		fmt.Printf("Version: %s\n", version)
		fmt.Printf("Build Time: %s\n", buildTime)
		fmt.Printf("Git Commit: %s\n", gitCommit)
	},
}

// License command
var licenseCmd = &cobra.Command{
	Use:   "license",
	Short: "License management and validation",
	Long:  "Manage and validate your Squawk DNS license and user tokens",
}

// License status command
var licenseStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Check license status",
	Long:  "Validate and display current license or user token status",
	Run: func(cmd *cobra.Command, args []string) {
		// Load configuration
		cfg, err := loadConfiguration()
		if err != nil {
			log.Fatalf("Configuration error: %v", err)
		}

		// Create validator
		validator := license.NewValidator(cfg.License)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		// Check status
		status, err := validator.GetStatus(ctx)
		if err != nil {
			fmt.Printf("Error validating license: %v\n", err)
			os.Exit(1)
		}

		// Display status
		if status.Valid {
			fmt.Println("✓ License is valid")
		} else {
			fmt.Println("✗ License is invalid or expired")
		}

		if status.Message != "" {
			fmt.Printf("Message: %s\n", status.Message)
		}

		if status.ExpiresAt != nil {
			fmt.Printf("Expires: %s\n", *status.ExpiresAt)
		}

		if status.UserEmail != nil {
			fmt.Printf("User: %s\n", *status.UserEmail)
		}

		if status.TokensUsed != nil && status.MaxTokens != nil {
			fmt.Printf("Token Usage: %d/%d\n", *status.TokensUsed, *status.MaxTokens)
		}

		if !status.Valid {
			fmt.Println("\nContact your administrator for license assistance.")
			os.Exit(1)
		}
	},
}

// License portal command
// License portal command removed - customers should contact administrator for license assistance

func init() {
	// Add config subcommands
	configCmd.AddCommand(configShowCmd)
	configCmd.AddCommand(configEnvCmd)
	configCmd.AddCommand(configGenerateCmd)

	// Add license subcommands
	licenseCmd.AddCommand(licenseStatusCmd)
	// License portal command removed - customers should contact administrator

	// Add time subcommands
	timeCmd.AddCommand(timeQueryCmd)
	timeCmd.AddCommand(timeForwardCmd)
	timeCmd.AddCommand(timeStatusCmd)
}

// Time command
var timeCmd = &cobra.Command{
	Use:   "time",
	Short: "Time synchronization commands",
	Long:  "Commands for NTP time queries and forwarding services",
}

// Time query command
var timeQueryCmd = &cobra.Command{
	Use:   "query [server]",
	Short: "Query an NTP time server",
	Long:  "Query an NTP time server and display the current time offset",
	Args:  cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		// Load configuration
		cfg, err := loadConfiguration()
		if err != nil {
			log.Fatalf("Configuration error: %v", err)
		}

		// Override server if provided as argument
		if len(args) > 0 {
			cfg.Time.Client.ServerURLs = []string{args[0]}
		}

		// Create NTP client
		ntpClient, err := timeservice.NewNTPClient(cfg.Time.Client)
		if err != nil {
			log.Fatalf("Failed to create NTP client: %v", err)
		}
		defer func() {
			if err := ntpClient.Close(); err != nil {
				log.Printf("Warning: failed to close NTP client: %v", err)
			}
		}()

		// Query time
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		response, err := ntpClient.Query(ctx)
		if err != nil {
			log.Fatalf("NTP query failed: %v", err)
		}

		// Output results
		if jsonOutput {
			jsonData, _ := json.MarshalIndent(response, "", "  ")
			fmt.Println(string(jsonData))
		} else {
			fmt.Printf("NTP Time Query Results:\n")
			fmt.Printf("=======================\n")
			fmt.Printf("Server: %s\n", response.ServerAddr)
			fmt.Printf("Server Time: %s\n", response.ServerTime.Format(time.RFC3339Nano))
			fmt.Printf("Local Time: %s\n", response.LocalTime.Format(time.RFC3339Nano))
			fmt.Printf("Offset: %v\n", response.Offset)
			fmt.Printf("Round Trip: %v\n", response.RoundTrip)
			fmt.Printf("Stratum: %d\n", response.Stratum)
			fmt.Printf("Synchronized: %t\n", response.Synchronized)
		}
	},
}

// Time forward command
var timeForwardCmd = &cobra.Command{
	Use:   "forward",
	Short: "Start NTP forwarding service",
	Long: `Start the NTP forwarding service to intercept local OS time requests.
This will listen on the configured address (default 127.0.0.1:123) and forward
time queries to upstream NTP servers.

NOTE: Port 123 typically requires root/administrator privileges.`,
	Run: func(cmd *cobra.Command, args []string) {
		// Load configuration
		cfg, err := loadConfiguration()
		if err != nil {
			log.Fatalf("Configuration error: %v", err)
		}

		if verbose {
			fmt.Println(cfg.String())
		}

		// Create NTP client
		ntpClient, err := timeservice.NewNTPClient(cfg.Time.Client)
		if err != nil {
			log.Fatalf("Failed to create NTP client: %v", err)
		}

		// Create forwarder
		ntpForwarder := timeservice.NewForwarder(ntpClient, cfg.Time.Forwarder)

		// Handle graceful shutdown
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		// Setup signal handling
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

		// Start forwarder in goroutine
		go func() {
			if err := ntpForwarder.Start(ctx); err != nil {
				log.Printf("NTP forwarder error: %v", err)
			}
		}()

		fmt.Printf("NTP forwarder started on %s\n", cfg.Time.Forwarder.ListenAddress)
		fmt.Println("Press Ctrl+C to stop...")

		// Wait for shutdown signal
		<-sigChan
		log.Println("Received shutdown signal, stopping NTP forwarder...")
		cancel()

		// Give some time for graceful shutdown
		time.Sleep(1 * time.Second)
		if err := ntpClient.Close(); err != nil {
			log.Printf("Error closing NTP client: %v", err)
		}
	},
}

// Time status command
var timeStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show time synchronization status",
	Long:  "Display current time synchronization status from configured NTP servers",
	Run: func(cmd *cobra.Command, args []string) {
		// Load configuration
		cfg, err := loadConfiguration()
		if err != nil {
			log.Fatalf("Configuration error: %v", err)
		}

		fmt.Printf("Time Synchronization Status:\n")
		fmt.Printf("============================\n")
		fmt.Printf("Configured NTP Servers:\n")
		for i, server := range cfg.Time.Client.ServerURLs {
			fmt.Printf("  %d. %s\n", i+1, server)
		}
		fmt.Printf("\nForwarder Configuration:\n")
		fmt.Printf("  Listen Address: %s\n", cfg.Time.Forwarder.ListenAddress)
		fmt.Printf("  Cache TTL: %d seconds\n", cfg.Time.Forwarder.CacheTTL)
		fmt.Printf("  Enabled: %t\n", cfg.Time.Enabled)

		// Try to query each server
		fmt.Printf("\nServer Reachability:\n")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		for _, serverURL := range cfg.Time.Client.ServerURLs {
			singleServerConfig := &timeservice.ClientConfig{
				ServerURLs: []string{serverURL},
				Timeout:    5,
				MaxRetries: 1,
				RetryDelay: 0,
			}

			ntpClient, err := timeservice.NewNTPClient(singleServerConfig)
			if err != nil {
				fmt.Printf("  %s: FAILED (config error: %v)\n", serverURL, err)
				continue
			}

			resp, err := ntpClient.Query(ctx)
			if closeErr := ntpClient.Close(); closeErr != nil {
				// Log but don't fail the command for close errors
				log.Printf("Warning: failed to close NTP client for %s: %v", serverURL, closeErr)
			}

			if err != nil {
				fmt.Printf("  %s: UNREACHABLE (%v)\n", serverURL, err)
			} else {
				fmt.Printf("  %s: OK (stratum %d, offset %v)\n", serverURL, resp.Stratum, resp.Offset)
			}
		}
	},
}