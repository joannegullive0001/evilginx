package core

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/kgretzky/evilginx2/log"
	"github.com/libdns/libdns"
)

// DNSSolver implements certmagic.ACMEDNSProvider for DNS-01 challenge
// This allows obtaining wildcard TLS certificates
type DNSSolver struct {
	provider DNSProvider
	cfg      *Config
	records  map[string]string // track created records: fqdn -> value
}

// NewDNSSolver creates a new DNS solver for ACME challenges
func NewDNSSolver(provider DNSProvider, cfg *Config) *DNSSolver {
	return &DNSSolver{
		provider: provider,
		cfg:      cfg,
		records:  make(map[string]string),
	}
}

// AppendRecords adds DNS records for the ACME challenge
// This implements libdns.RecordAppender interface
func (s *DNSSolver) AppendRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	var added []libdns.Record
	
	zone = strings.TrimSuffix(zone, ".")
	
	for _, rec := range recs {
		if rec.Type != "TXT" {
			continue
		}
		
		// Build the full challenge hostname
		// ACME DNS-01 uses _acme-challenge.domain.com
		name := strings.TrimSuffix(rec.Name, ".")
		var hostname string
		if name == "" || name == "@" {
			hostname = zone
		} else {
			hostname = name + "." + zone
		}
		
		log.Debug("[dns-solver] creating TXT record: %s = %s", hostname, rec.Value)
		
		err := s.provider.CreateTXTRecord(hostname, rec.Value)
		if err != nil {
			return added, fmt.Errorf("failed to create TXT record for %s: %v", hostname, err)
		}
		
		// Track this record for cleanup
		s.records[hostname] = rec.Value
		
		added = append(added, rec)
	}
	
	// Wait for DNS propagation
	if len(added) > 0 {
		log.Info("[dns-solver] waiting for DNS propagation (15 seconds)...")
		time.Sleep(15 * time.Second)
	}
	
	return added, nil
}

// DeleteRecords removes DNS records after challenge is complete
// This implements libdns.RecordDeleter interface
func (s *DNSSolver) DeleteRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	var deleted []libdns.Record
	
	zone = strings.TrimSuffix(zone, ".")
	
	for _, rec := range recs {
		if rec.Type != "TXT" {
			continue
		}
		
		name := strings.TrimSuffix(rec.Name, ".")
		var hostname string
		if name == "" || name == "@" {
			hostname = zone
		} else {
			hostname = name + "." + zone
		}
		
		log.Debug("[dns-solver] deleting TXT record: %s", hostname)
		
		err := s.provider.DeleteTXTRecord(hostname)
		if err != nil {
			log.Warning("[dns-solver] failed to delete TXT record %s: %v", hostname, err)
			// Continue anyway, record cleanup is not critical
		}
		
		delete(s.records, hostname)
		deleted = append(deleted, rec)
	}
	
	return deleted, nil
}

// Ensure DNSSolver implements the required certmagic interfaces
var _ certmagic.ACMEDNSProvider = (*DNSSolver)(nil)
