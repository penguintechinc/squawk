package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	grpcclient "github.com/penguintechinc/squawk/dns-client-go/pkg/grpc"
)

func main() {
	fmt.Println("Squawk DNS Client gRPC Examples")
	fmt.Println("================================")
	fmt.Println()

	// Example 1: Single DNS query
	fmt.Println("Example 1: Single DNS Query via gRPC")
	fmt.Println("------------------------------------")
	exampleSingleQuery()
	fmt.Println()

	// Example 2: Batch DNS queries
	fmt.Println("Example 2: Batch DNS Queries via gRPC")
	fmt.Println("-------------------------------------")
	exampleBatchQuery()
	fmt.Println()

	// Example 3: Health check
	fmt.Println("Example 3: DNS Server Health Check")
	fmt.Println("----------------------------------")
	exampleHealthCheck()
	fmt.Println()

	// Example 4: Multiple record types
	fmt.Println("Example 4: Multiple DNS Record Types")
	fmt.Println("------------------------------------")
	exampleMultipleRecordTypes()
	fmt.Println()

	// Example 5: Error handling
	fmt.Println("Example 5: Error Handling")
	fmt.Println("------------------------")
	exampleErrorHandling()
	fmt.Println()

	fmt.Println("Examples completed!")
}

// exampleSingleQuery demonstrates a single DNS query
func exampleSingleQuery() {
	// Get auth token from environment (optional)
	token := os.Getenv("SQUAWK_AUTH_TOKEN")

	// Create gRPC client
	client, err := grpcclient.NewDNSClient("localhost:50052", token)
	if err != nil {
		log.Printf("Failed to create client: %v", err)
		return
	}
	defer client.Close()

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Query a domain
	result, err := client.Query(ctx, "example.com", "A")
	if err != nil {
		log.Printf("Query failed: %v", err)
		return
	}

	// Display results
	fmt.Printf("Domain: example.com (Type: A)\n")
	fmt.Printf("Status: %d\n", result.Status)

	if len(result.Answers) > 0 {
		fmt.Println("Answers:")
		for _, answer := range result.Answers {
			fmt.Printf("  %s -> %s (TTL: %d)\n", answer.Name, answer.Data, answer.TTL)
		}
	} else {
		fmt.Println("No answers found")
	}

	if result.Metadata != nil {
		fmt.Printf("Response time: %.2f ms\n", result.Metadata.ResponseTimeMs)
		fmt.Printf("From cache: %v\n", result.Metadata.FromCache)
	}
}

// exampleBatchQuery demonstrates batch DNS queries
func exampleBatchQuery() {
	token := os.Getenv("SQUAWK_AUTH_TOKEN")

	client, err := grpcclient.NewDNSClient("localhost:50052", token)
	if err != nil {
		log.Printf("Failed to create client: %v", err)
		return
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// List of domains to query
	domains := []string{
		"google.com",
		"github.com",
		"cloudflare.com",
		"example.com",
	}

	fmt.Printf("Batch querying %d domains...\n", len(domains))

	// Perform batch query
	results, err := client.BatchQuery(ctx, domains, "A")
	if err != nil {
		log.Printf("Batch query failed: %v", err)
		return
	}

	// Display results
	for i, domain := range domains {
		if i < len(results) {
			result := results[i]
			if len(result.Answers) > 0 {
				fmt.Printf("%s -> %s\n", domain, result.Answers[0].Data)
			} else {
				fmt.Printf("%s -> No answer\n", domain)
			}
		}
	}
}

// exampleHealthCheck demonstrates DNS server health check
func exampleHealthCheck() {
	token := os.Getenv("SQUAWK_AUTH_TOKEN")

	client, err := grpcclient.NewDNSClient("localhost:50052", token)
	if err != nil {
		log.Printf("Failed to create client: %v", err)
		return
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Check health
	healthy, err := client.HealthCheck(ctx)
	if err != nil {
		log.Printf("Health check failed: %v", err)
		fmt.Println("Server status: Unhealthy or unreachable")
		return
	}

	if healthy {
		fmt.Println("Server status: Healthy and serving")
	} else {
		fmt.Println("Server status: Not serving")
	}
}

// exampleMultipleRecordTypes demonstrates querying different record types
func exampleMultipleRecordTypes() {
	token := os.Getenv("SQUAWK_AUTH_TOKEN")

	client, err := grpcclient.NewDNSClient("localhost:50052", token)
	if err != nil {
		log.Printf("Failed to create client: %v", err)
		return
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	domain := "example.com"
	recordTypes := []string{"A", "AAAA", "MX", "TXT", "NS"}

	fmt.Printf("Querying %s for multiple record types...\n", domain)

	for _, recordType := range recordTypes {
		result, err := client.Query(ctx, domain, recordType)
		if err != nil {
			fmt.Printf("%s (%s): Error - %v\n", domain, recordType, err)
			continue
		}

		fmt.Printf("%s (%s): ", domain, recordType)
		if len(result.Answers) > 0 {
			for _, answer := range result.Answers {
				fmt.Printf("%s ", answer.Data)
			}
			fmt.Println()
		} else {
			fmt.Println("No records found")
		}
	}
}

// exampleErrorHandling demonstrates error handling
func exampleErrorHandling() {
	// Try to connect to a non-existent server
	fmt.Println("Attempting to connect to non-existent server...")
	client, err := grpcclient.NewDNSClient("nonexistent.example.com:50052", "")
	if err != nil {
		fmt.Printf("Connection error (expected): %v\n", err)
		fmt.Println("This is expected - the server doesn't exist")
		return
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Try to query
	_, err = client.Query(ctx, "example.com", "A")
	if err != nil {
		fmt.Printf("Query error (expected): %v\n", err)
	}
}
