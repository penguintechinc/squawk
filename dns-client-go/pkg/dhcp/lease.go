package dhcp

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// LeaseStore handles persistent storage of DHCP leases.
type LeaseStore struct {
	filePath string
	mu       sync.RWMutex
}

// NewLeaseStore creates a new lease store.
func NewLeaseStore(filePath string) (*LeaseStore, error) {
	// Ensure directory exists
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return nil, fmt.Errorf("failed to create lease directory: %w", err)
	}

	return &LeaseStore{
		filePath: filePath,
	}, nil
}

// leaseFile represents the JSON structure for storing leases.
type leaseFile struct {
	Leases map[string]*Lease `json:"leases"`
}

// LoadAll loads all leases from the file.
func (s *LeaseStore) LoadAll() ([]*Lease, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	data, err := os.ReadFile(s.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // No leases file yet
		}
		return nil, fmt.Errorf("failed to read lease file: %w", err)
	}

	var lf leaseFile
	if err := json.Unmarshal(data, &lf); err != nil {
		return nil, fmt.Errorf("failed to parse lease file: %w", err)
	}

	leases := make([]*Lease, 0, len(lf.Leases))
	for _, lease := range lf.Leases {
		leases = append(leases, lease)
	}

	return leases, nil
}

// Load loads a specific lease by MAC address.
func (s *LeaseStore) Load(macAddress string) (*Lease, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	data, err := os.ReadFile(s.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read lease file: %w", err)
	}

	var lf leaseFile
	if err := json.Unmarshal(data, &lf); err != nil {
		return nil, fmt.Errorf("failed to parse lease file: %w", err)
	}

	lease, exists := lf.Leases[macAddress]
	if !exists {
		return nil, nil
	}

	return lease, nil
}

// Save saves a lease to the file.
func (s *LeaseStore) Save(lease *Lease) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Load existing leases
	var lf leaseFile
	data, err := os.ReadFile(s.filePath)
	if err == nil {
		if err := json.Unmarshal(data, &lf); err != nil {
			lf.Leases = make(map[string]*Lease)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("failed to read lease file: %w", err)
	}

	if lf.Leases == nil {
		lf.Leases = make(map[string]*Lease)
	}

	// Add/update the lease
	lf.Leases[lease.MACAddress] = lease

	// Write back
	newData, err := json.MarshalIndent(lf, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal leases: %w", err)
	}

	if err := os.WriteFile(s.filePath, newData, 0600); err != nil {
		return fmt.Errorf("failed to write lease file: %w", err)
	}

	return nil
}

// Delete removes a lease from the file.
func (s *LeaseStore) Delete(macAddress string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := os.ReadFile(s.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // Nothing to delete
		}
		return fmt.Errorf("failed to read lease file: %w", err)
	}

	var lf leaseFile
	if err := json.Unmarshal(data, &lf); err != nil {
		return fmt.Errorf("failed to parse lease file: %w", err)
	}

	delete(lf.Leases, macAddress)

	newData, err := json.MarshalIndent(lf, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal leases: %w", err)
	}

	if err := os.WriteFile(s.filePath, newData, 0600); err != nil {
		return fmt.Errorf("failed to write lease file: %w", err)
	}

	return nil
}

// DeleteExpired removes all expired leases.
func (s *LeaseStore) DeleteExpired() (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := os.ReadFile(s.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("failed to read lease file: %w", err)
	}

	var lf leaseFile
	if err := json.Unmarshal(data, &lf); err != nil {
		return 0, fmt.Errorf("failed to parse lease file: %w", err)
	}

	deleted := 0
	for mac, lease := range lf.Leases {
		if lease.IsExpired() {
			delete(lf.Leases, mac)
			deleted++
		}
	}

	if deleted > 0 {
		newData, err := json.MarshalIndent(lf, "", "  ")
		if err != nil {
			return deleted, fmt.Errorf("failed to marshal leases: %w", err)
		}

		if err := os.WriteFile(s.filePath, newData, 0600); err != nil {
			return deleted, fmt.Errorf("failed to write lease file: %w", err)
		}
	}

	return deleted, nil
}

// Clear removes all leases.
func (s *LeaseStore) Clear() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	lf := leaseFile{
		Leases: make(map[string]*Lease),
	}

	data, err := json.MarshalIndent(lf, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal leases: %w", err)
	}

	if err := os.WriteFile(s.filePath, data, 0600); err != nil {
		return fmt.Errorf("failed to write lease file: %w", err)
	}

	return nil
}
