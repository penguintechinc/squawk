package ntp

import (
	"context"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/penguintechinc/squawk/squawk-client-go/pkg/transport"
)

// NTS-KE Record Types (RFC 8915 Section 4)
const (
	NTSKERecordEndOfMessage        uint16 = 0
	NTSKERecordNTSNextProtocol     uint16 = 1
	NTSKERecordError               uint16 = 2
	NTSKERecordWarning             uint16 = 3
	NTSKERecordAEADAlgorithm       uint16 = 4
	NTSKERecordNewCookieForNTPv4   uint16 = 5
	NTSKERecordNTPv4ServerNegot    uint16 = 6
	NTSKERecordNTPv4PortNegot      uint16 = 7
)

// NTS-KE Error Codes
const (
	NTSKEErrorUnrecognizedCritical uint16 = 0
	NTSKEErrorBadRequest           uint16 = 1
	NTSKEErrorInternalServerError  uint16 = 2
)

// KEManager handles NTS Key Establishment.
type KEManager struct {
	config    *Config
	transport transport.Transport
	keyMaterial *NTSKeyMaterial
}

// NewKEManager creates a new NTS-KE manager.
func NewKEManager(cfg *Config, t transport.Transport) *KEManager {
	return &KEManager{
		config:    cfg,
		transport: t,
	}
}

// EstablishKeys performs NTS Key Establishment via HTTPS.
func (k *KEManager) EstablishKeys(ctx context.Context) (*NTSKeyMaterial, error) {
	// Build NTS-KE request
	req := &transport.NTSKERequest{
		SupportedAlgorithms: []uint16{
			AEAD_AES_SIV_CMAC_256,
			AEAD_AES_SIV_CMAC_384,
			AEAD_AES_SIV_CMAC_512,
		},
		NextProtocol: "ntske/1",
	}

	// Perform NTS-KE via transport
	resp, err := k.transport.NTSKeyEstablishment(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("NTS-KE request failed: %w", err)
	}

	if !resp.Success {
		return nil, fmt.Errorf("NTS-KE failed: %s", resp.ErrorMessage)
	}

	// Create key material
	keyMaterial := &NTSKeyMaterial{
		C2S:           resp.C2SKey,
		S2C:           resp.S2CKey,
		Cookies:       resp.Cookies,
		NTPServer:     resp.NTPServer,
		NTPPort:       resp.NTPPort,
		AEADAlgorithm: resp.AEADAlgorithm,
		ExpiresAt:     time.Unix(resp.ExpiresAt, 0),
	}

	k.keyMaterial = keyMaterial
	return keyMaterial, nil
}

// GetKeyMaterial returns the current key material.
func (k *KEManager) GetKeyMaterial() *NTSKeyMaterial {
	return k.keyMaterial
}

// HasValidKeys returns true if valid key material is available.
func (k *KEManager) HasValidKeys() bool {
	return k.keyMaterial != nil && !k.keyMaterial.IsExpired() && k.keyMaterial.HasCookies()
}

// RefreshIfNeeded checks if keys need refresh and refreshes them.
func (k *KEManager) RefreshIfNeeded(ctx context.Context) error {
	if k.keyMaterial == nil || k.keyMaterial.NeedsRefresh(k.config.KeyRefreshInterval/2) {
		_, err := k.EstablishKeys(ctx)
		return err
	}
	return nil
}

// NTSKERecord represents a record in the NTS-KE protocol.
type NTSKERecord struct {
	Critical bool
	Type     uint16
	Body     []byte
}

// BuildNTSKERequest builds a raw NTS-KE request.
func BuildNTSKERequest(supportedAlgorithms []uint16) []byte {
	var records []NTSKERecord

	// Next Protocol Negotiation (NTPv4)
	nextProto := make([]byte, 2)
	binary.BigEndian.PutUint16(nextProto, 0) // NTPv4
	records = append(records, NTSKERecord{
		Critical: true,
		Type:     NTSKERecordNTSNextProtocol,
		Body:     nextProto,
	})

	// AEAD Algorithm Negotiation
	for _, algo := range supportedAlgorithms {
		algoBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(algoBytes, algo)
		records = append(records, NTSKERecord{
			Critical: true,
			Type:     NTSKERecordAEADAlgorithm,
			Body:     algoBytes,
		})
	}

	// End of Message
	records = append(records, NTSKERecord{
		Critical: true,
		Type:     NTSKERecordEndOfMessage,
		Body:     nil,
	})

	return encodeNTSKERecords(records)
}

// ParseNTSKEResponse parses a raw NTS-KE response.
func ParseNTSKEResponse(data []byte) (*NTSKeyMaterial, error) {
	records, err := decodeNTSKERecords(data)
	if err != nil {
		return nil, fmt.Errorf("failed to decode NTS-KE records: %w", err)
	}

	keyMaterial := &NTSKeyMaterial{
		NTPPort: 123, // Default NTP port
	}

	for _, record := range records {
		switch record.Type {
		case NTSKERecordError:
			if len(record.Body) >= 2 {
				errorCode := binary.BigEndian.Uint16(record.Body[:2])
				return nil, fmt.Errorf("NTS-KE error: %d", errorCode)
			}

		case NTSKERecordAEADAlgorithm:
			if len(record.Body) >= 2 {
				keyMaterial.AEADAlgorithm = binary.BigEndian.Uint16(record.Body[:2])
			}

		case NTSKERecordNewCookieForNTPv4:
			keyMaterial.Cookies = append(keyMaterial.Cookies, record.Body)

		case NTSKERecordNTPv4ServerNegot:
			// Server name as ASCII string
			keyMaterial.NTPServer = string(record.Body)

		case NTSKERecordNTPv4PortNegot:
			if len(record.Body) >= 2 {
				keyMaterial.NTPPort = int(binary.BigEndian.Uint16(record.Body[:2]))
			}

		case NTSKERecordEndOfMessage:
			// End of records
			break
		}
	}

	// Set expiration (typically 24 hours for NTS)
	keyMaterial.ExpiresAt = time.Now().Add(24 * time.Hour)

	return keyMaterial, nil
}

// encodeNTSKERecords encodes records into wire format.
func encodeNTSKERecords(records []NTSKERecord) []byte {
	var result []byte

	for _, record := range records {
		// Header: Critical(1 bit) + Type(15 bits) + Length(16 bits)
		header := make([]byte, 4)
		typeField := record.Type
		if record.Critical {
			typeField |= 0x8000 // Set critical bit
		}
		binary.BigEndian.PutUint16(header[0:2], typeField)
		// #nosec G115 -- NTS-KE record body length is protocol-limited to uint16
		binary.BigEndian.PutUint16(header[2:4], uint16(len(record.Body)))

		result = append(result, header...)
		result = append(result, record.Body...)
	}

	return result
}

// decodeNTSKERecords decodes wire format into records.
func decodeNTSKERecords(data []byte) ([]NTSKERecord, error) {
	var records []NTSKERecord
	offset := 0

	for offset+4 <= len(data) {
		typeField := binary.BigEndian.Uint16(data[offset : offset+2])
		bodyLen := binary.BigEndian.Uint16(data[offset+2 : offset+4])

		critical := (typeField & 0x8000) != 0
		recordType := typeField & 0x7FFF

		if offset+4+int(bodyLen) > len(data) {
			return nil, fmt.Errorf("record body exceeds data length")
		}

		body := data[offset+4 : offset+4+int(bodyLen)]

		records = append(records, NTSKERecord{
			Critical: critical,
			Type:     recordType,
			Body:     body,
		})

		offset += 4 + int(bodyLen)

		// Stop at End of Message
		if recordType == NTSKERecordEndOfMessage {
			break
		}
	}

	return records, nil
}
