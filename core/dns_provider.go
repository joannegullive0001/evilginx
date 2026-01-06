package core

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/kgretzky/evilginx2/log"
)

// DNSProvider interface defines methods for external DNS management
type DNSProvider interface {
	// GetName returns the provider name
	GetName() string
	// CreateRecord creates a DNS A record
	CreateRecord(hostname string, ip string) error
	// UpdateRecord updates an existing DNS A record
	UpdateRecord(hostname string, ip string) error
	// DeleteRecord deletes a DNS A record
	DeleteRecord(hostname string) error
	// ListRecords lists all DNS records for the domain
	ListRecords() ([]DNSRecord, error)
	// SyncRecords syncs all required hostnames with the DNS provider
	SyncRecords(hostnames []string, ip string) error
	// IsConfigured returns true if the provider is properly configured
	IsConfigured() bool
	// CreateTXTRecord creates a DNS TXT record (for ACME DNS-01 challenge)
	CreateTXTRecord(hostname string, value string) error
	// DeleteTXTRecord deletes a DNS TXT record
	DeleteTXTRecord(hostname string) error
}

// DNSRecord represents a DNS record
type DNSRecord struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Type     string `json:"type"`
	Content  string `json:"content"`
	TTL      int    `json:"ttl"`
	Proxied  bool   `json:"proxied,omitempty"`
}

// DNSProviderConfig holds configuration for external DNS providers
type DNSProviderConfig struct {
	Provider   string `mapstructure:"provider" json:"provider" yaml:"provider"`
	ApiKey     string `mapstructure:"api_key" json:"api_key" yaml:"api_key"`
	ApiSecret  string `mapstructure:"api_secret" json:"api_secret" yaml:"api_secret"`
	ZoneID     string `mapstructure:"zone_id" json:"zone_id" yaml:"zone_id"`
	Enabled    bool   `mapstructure:"enabled" json:"enabled" yaml:"enabled"`
	AutoSync   bool   `mapstructure:"auto_sync" json:"auto_sync" yaml:"auto_sync"`
	TTL        int    `mapstructure:"ttl" json:"ttl" yaml:"ttl"`
}

// ExternalDNS manages external DNS providers
type ExternalDNS struct {
	cfg       *Config
	provider  DNSProvider
	records   map[string]string // hostname -> record_id mapping
	mu        sync.RWMutex
}

// NewExternalDNS creates a new ExternalDNS manager
func NewExternalDNS(cfg *Config) *ExternalDNS {
	e := &ExternalDNS{
		cfg:     cfg,
		records: make(map[string]string),
	}
	e.initProvider()
	return e
}

// initProvider initializes the DNS provider based on configuration
func (e *ExternalDNS) initProvider() {
	dnsConfig := e.cfg.GetDNSConfig()
	if dnsConfig == nil || !dnsConfig.Enabled {
		e.provider = nil
		return
	}

	switch strings.ToLower(dnsConfig.Provider) {
	case "cloudflare":
		e.provider = NewCloudflareDNS(dnsConfig)
	case "route53":
		e.provider = NewRoute53DNS(dnsConfig)
	case "digitalocean":
		e.provider = NewDigitalOceanDNS(dnsConfig)
	default:
		log.Warning("unknown DNS provider: %s", dnsConfig.Provider)
		e.provider = nil
	}
}

// RefreshProvider refreshes the DNS provider configuration
func (e *ExternalDNS) RefreshProvider() {
	e.initProvider()
}

// IsEnabled returns true if external DNS is enabled
func (e *ExternalDNS) IsEnabled() bool {
	return e.provider != nil && e.provider.IsConfigured()
}

// GetProvider returns the current DNS provider
func (e *ExternalDNS) GetProvider() DNSProvider {
	return e.provider
}

// SyncHostnames syncs all provided hostnames with the DNS provider
func (e *ExternalDNS) SyncHostnames(hostnames []string) error {
	if !e.IsEnabled() {
		return fmt.Errorf("external DNS is not enabled or configured")
	}

	ip := e.cfg.GetServerExternalIP()
	if ip == "" {
		return fmt.Errorf("external IP not set")
	}

	return e.provider.SyncRecords(hostnames, ip)
}

// AddRecord adds a single DNS record
func (e *ExternalDNS) AddRecord(hostname string) error {
	if !e.IsEnabled() {
		return fmt.Errorf("external DNS is not enabled or configured")
	}

	ip := e.cfg.GetServerExternalIP()
	if ip == "" {
		return fmt.Errorf("external IP not set")
	}

	return e.provider.CreateRecord(hostname, ip)
}

// RemoveRecord removes a single DNS record
func (e *ExternalDNS) RemoveRecord(hostname string) error {
	if !e.IsEnabled() {
		return fmt.Errorf("external DNS is not enabled or configured")
	}

	return e.provider.DeleteRecord(hostname)
}

// ListRecords lists all DNS records
func (e *ExternalDNS) ListRecords() ([]DNSRecord, error) {
	if !e.IsEnabled() {
		return nil, fmt.Errorf("external DNS is not enabled or configured")
	}

	return e.provider.ListRecords()
}

// ========== Cloudflare DNS Provider ==========

type CloudflareDNS struct {
	config   *DNSProviderConfig
	client   *http.Client
	baseURL  string
	records  map[string]string // hostname -> record_id
	mu       sync.RWMutex
}

func NewCloudflareDNS(config *DNSProviderConfig) *CloudflareDNS {
	return &CloudflareDNS{
		config:  config,
		client:  &http.Client{Timeout: 30 * time.Second},
		baseURL: "https://api.cloudflare.com/client/v4",
		records: make(map[string]string),
	}
}

func (c *CloudflareDNS) GetName() string {
	return "Cloudflare"
}

func (c *CloudflareDNS) IsConfigured() bool {
	return c.config.ApiKey != "" && c.config.ZoneID != ""
}

func (c *CloudflareDNS) doRequest(method, endpoint string, body interface{}) ([]byte, error) {
	var reqBody []byte
	var err error

	if body != nil {
		reqBody, err = json.Marshal(body)
		if err != nil {
			return nil, err
		}
	}

	url := fmt.Sprintf("%s%s", c.baseURL, endpoint)
	req, err := http.NewRequest(method, url, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+c.config.ApiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("cloudflare API error: %s", string(respBody))
	}

	return respBody, nil
}

func (c *CloudflareDNS) CreateRecord(hostname string, ip string) error {
	ttl := c.config.TTL
	if ttl == 0 {
		ttl = 300
	}

	record := map[string]interface{}{
		"type":    "A",
		"name":    hostname,
		"content": ip,
		"ttl":     ttl,
		"proxied": false,
	}

	endpoint := fmt.Sprintf("/zones/%s/dns_records", c.config.ZoneID)
	respBody, err := c.doRequest("POST", endpoint, record)
	if err != nil {
		return err
	}

	var response struct {
		Success bool `json:"success"`
		Result  struct {
			ID string `json:"id"`
		} `json:"result"`
	}
	if err := json.Unmarshal(respBody, &response); err != nil {
		return err
	}

	if response.Success {
		c.mu.Lock()
		c.records[hostname] = response.Result.ID
		c.mu.Unlock()
		log.Info("[dns] created A record: %s -> %s", hostname, ip)
	}

	return nil
}

func (c *CloudflareDNS) UpdateRecord(hostname string, ip string) error {
	c.mu.RLock()
	recordID, exists := c.records[hostname]
	c.mu.RUnlock()

	if !exists {
		// Try to find existing record
		records, err := c.ListRecords()
		if err != nil {
			return err
		}
		for _, r := range records {
			if r.Name == hostname && r.Type == "A" {
				recordID = r.ID
				c.mu.Lock()
				c.records[hostname] = recordID
				c.mu.Unlock()
				break
			}
		}
	}

	if recordID == "" {
		return c.CreateRecord(hostname, ip)
	}

	ttl := c.config.TTL
	if ttl == 0 {
		ttl = 300
	}

	record := map[string]interface{}{
		"type":    "A",
		"name":    hostname,
		"content": ip,
		"ttl":     ttl,
		"proxied": false,
	}

	endpoint := fmt.Sprintf("/zones/%s/dns_records/%s", c.config.ZoneID, recordID)
	_, err := c.doRequest("PUT", endpoint, record)
	if err != nil {
		return err
	}

	log.Info("[dns] updated A record: %s -> %s", hostname, ip)
	return nil
}

func (c *CloudflareDNS) DeleteRecord(hostname string) error {
	c.mu.RLock()
	recordID, exists := c.records[hostname]
	c.mu.RUnlock()

	if !exists {
		// Try to find existing record
		records, err := c.ListRecords()
		if err != nil {
			return err
		}
		for _, r := range records {
			if r.Name == hostname && r.Type == "A" {
				recordID = r.ID
				break
			}
		}
	}

	if recordID == "" {
		return fmt.Errorf("record not found: %s", hostname)
	}

	endpoint := fmt.Sprintf("/zones/%s/dns_records/%s", c.config.ZoneID, recordID)
	_, err := c.doRequest("DELETE", endpoint, nil)
	if err != nil {
		return err
	}

	c.mu.Lock()
	delete(c.records, hostname)
	c.mu.Unlock()

	log.Info("[dns] deleted A record: %s", hostname)
	return nil
}

func (c *CloudflareDNS) ListRecords() ([]DNSRecord, error) {
	endpoint := fmt.Sprintf("/zones/%s/dns_records?type=A&per_page=100", c.config.ZoneID)
	respBody, err := c.doRequest("GET", endpoint, nil)
	if err != nil {
		return nil, err
	}

	var response struct {
		Success bool        `json:"success"`
		Result  []DNSRecord `json:"result"`
	}
	if err := json.Unmarshal(respBody, &response); err != nil {
		return nil, err
	}

	// Update local cache
	c.mu.Lock()
	for _, r := range response.Result {
		c.records[r.Name] = r.ID
	}
	c.mu.Unlock()

	return response.Result, nil
}

func (c *CloudflareDNS) SyncRecords(hostnames []string, ip string) error {
	// Get existing records
	existing, err := c.ListRecords()
	if err != nil {
		return err
	}

	existingMap := make(map[string]DNSRecord)
	for _, r := range existing {
		existingMap[r.Name] = r
	}

	// Create or update records for hostnames
	for _, hostname := range hostnames {
		if r, exists := existingMap[hostname]; exists {
			if r.Content != ip {
				if err := c.UpdateRecord(hostname, ip); err != nil {
					log.Error("[dns] failed to update record %s: %v", hostname, err)
				}
			}
		} else {
			if err := c.CreateRecord(hostname, ip); err != nil {
				log.Error("[dns] failed to create record %s: %v", hostname, err)
			}
		}
	}

	log.Info("[dns] synced %d records with Cloudflare", len(hostnames))
	return nil
}

func (c *CloudflareDNS) CreateTXTRecord(hostname string, value string) error {
	ttl := 120 // Short TTL for ACME challenges

	record := map[string]interface{}{
		"type":    "TXT",
		"name":    hostname,
		"content": value,
		"ttl":     ttl,
	}

	endpoint := fmt.Sprintf("/zones/%s/dns_records", c.config.ZoneID)
	respBody, err := c.doRequest("POST", endpoint, record)
	if err != nil {
		return err
	}

	var response struct {
		Success bool `json:"success"`
		Result  struct {
			ID string `json:"id"`
		} `json:"result"`
	}
	if err := json.Unmarshal(respBody, &response); err != nil {
		return err
	}

	if response.Success {
		c.mu.Lock()
		c.records["txt:"+hostname] = response.Result.ID
		c.mu.Unlock()
		log.Debug("[dns] created TXT record: %s = %s", hostname, value)
	}

	return nil
}

func (c *CloudflareDNS) DeleteTXTRecord(hostname string) error {
	c.mu.RLock()
	recordID, exists := c.records["txt:"+hostname]
	c.mu.RUnlock()

	if !exists {
		// Try to find existing TXT record
		endpoint := fmt.Sprintf("/zones/%s/dns_records?type=TXT&name=%s&per_page=100", c.config.ZoneID, hostname)
		respBody, err := c.doRequest("GET", endpoint, nil)
		if err != nil {
			return err
		}

		var response struct {
			Success bool        `json:"success"`
			Result  []DNSRecord `json:"result"`
		}
		if err := json.Unmarshal(respBody, &response); err != nil {
			return err
		}

		for _, r := range response.Result {
			if r.Name == hostname && r.Type == "TXT" {
				recordID = r.ID
				break
			}
		}
	}

	if recordID == "" {
		return nil // Record doesn't exist, nothing to delete
	}

	endpoint := fmt.Sprintf("/zones/%s/dns_records/%s", c.config.ZoneID, recordID)
	_, err := c.doRequest("DELETE", endpoint, nil)
	if err != nil {
		return err
	}

	c.mu.Lock()
	delete(c.records, "txt:"+hostname)
	c.mu.Unlock()

	log.Debug("[dns] deleted TXT record: %s", hostname)
	return nil
}

// ========== Route53 DNS Provider ==========

type Route53DNS struct {
	config  *DNSProviderConfig
	client  *http.Client
	records map[string]string
	mu      sync.RWMutex
}

func NewRoute53DNS(config *DNSProviderConfig) *Route53DNS {
	return &Route53DNS{
		config:  config,
		client:  &http.Client{Timeout: 30 * time.Second},
		records: make(map[string]string),
	}
}

func (r *Route53DNS) GetName() string {
	return "AWS Route53"
}

func (r *Route53DNS) IsConfigured() bool {
	return r.config.ApiKey != "" && r.config.ApiSecret != "" && r.config.ZoneID != ""
}

func (r *Route53DNS) CreateRecord(hostname string, ip string) error {
	// Route53 implementation would require AWS SDK
	// For now, provide a placeholder that logs the action
	log.Warning("[dns] Route53 support requires AWS SDK integration")
	log.Info("[dns] would create A record: %s -> %s", hostname, ip)
	return nil
}

func (r *Route53DNS) UpdateRecord(hostname string, ip string) error {
	log.Warning("[dns] Route53 support requires AWS SDK integration")
	log.Info("[dns] would update A record: %s -> %s", hostname, ip)
	return nil
}

func (r *Route53DNS) DeleteRecord(hostname string) error {
	log.Warning("[dns] Route53 support requires AWS SDK integration")
	log.Info("[dns] would delete A record: %s", hostname)
	return nil
}

func (r *Route53DNS) ListRecords() ([]DNSRecord, error) {
	log.Warning("[dns] Route53 support requires AWS SDK integration")
	return []DNSRecord{}, nil
}

func (r *Route53DNS) SyncRecords(hostnames []string, ip string) error {
	log.Warning("[dns] Route53 support requires AWS SDK integration")
	return nil
}

func (r *Route53DNS) CreateTXTRecord(hostname string, value string) error {
	log.Warning("[dns] Route53 TXT record support requires AWS SDK integration")
	return nil
}

func (r *Route53DNS) DeleteTXTRecord(hostname string) error {
	log.Warning("[dns] Route53 TXT record support requires AWS SDK integration")
	return nil
}

// ========== DigitalOcean DNS Provider ==========

type DigitalOceanDNS struct {
	config  *DNSProviderConfig
	client  *http.Client
	baseURL string
	domain  string
	records map[string]int // hostname -> record_id
	mu      sync.RWMutex
}

func NewDigitalOceanDNS(config *DNSProviderConfig) *DigitalOceanDNS {
	return &DigitalOceanDNS{
		config:  config,
		client:  &http.Client{Timeout: 30 * time.Second},
		baseURL: "https://api.digitalocean.com/v2",
		domain:  config.ZoneID, // ZoneID is the domain for DO
		records: make(map[string]int),
	}
}

func (d *DigitalOceanDNS) GetName() string {
	return "DigitalOcean"
}

func (d *DigitalOceanDNS) IsConfigured() bool {
	return d.config.ApiKey != "" && d.config.ZoneID != ""
}

func (d *DigitalOceanDNS) doRequest(method, endpoint string, body interface{}) ([]byte, error) {
	var reqBody []byte
	var err error

	if body != nil {
		reqBody, err = json.Marshal(body)
		if err != nil {
			return nil, err
		}
	}

	url := fmt.Sprintf("%s%s", d.baseURL, endpoint)
	req, err := http.NewRequest(method, url, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+d.config.ApiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := d.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("DigitalOcean API error: %s", string(respBody))
	}

	return respBody, nil
}

func (d *DigitalOceanDNS) CreateRecord(hostname string, ip string) error {
	ttl := d.config.TTL
	if ttl == 0 {
		ttl = 300
	}

	// Extract subdomain from hostname
	subdomain := strings.TrimSuffix(hostname, "."+d.domain)
	if subdomain == hostname {
		subdomain = "@"
	}

	record := map[string]interface{}{
		"type": "A",
		"name": subdomain,
		"data": ip,
		"ttl":  ttl,
	}

	endpoint := fmt.Sprintf("/domains/%s/records", d.domain)
	respBody, err := d.doRequest("POST", endpoint, record)
	if err != nil {
		return err
	}

	var response struct {
		DomainRecord struct {
			ID int `json:"id"`
		} `json:"domain_record"`
	}
	if err := json.Unmarshal(respBody, &response); err != nil {
		return err
	}

	d.mu.Lock()
	d.records[hostname] = response.DomainRecord.ID
	d.mu.Unlock()

	log.Info("[dns] created A record: %s -> %s", hostname, ip)
	return nil
}

func (d *DigitalOceanDNS) UpdateRecord(hostname string, ip string) error {
	d.mu.RLock()
	recordID, exists := d.records[hostname]
	d.mu.RUnlock()

	if !exists {
		return d.CreateRecord(hostname, ip)
	}

	ttl := d.config.TTL
	if ttl == 0 {
		ttl = 300
	}

	subdomain := strings.TrimSuffix(hostname, "."+d.domain)
	if subdomain == hostname {
		subdomain = "@"
	}

	record := map[string]interface{}{
		"type": "A",
		"name": subdomain,
		"data": ip,
		"ttl":  ttl,
	}

	endpoint := fmt.Sprintf("/domains/%s/records/%d", d.domain, recordID)
	_, err := d.doRequest("PUT", endpoint, record)
	if err != nil {
		return err
	}

	log.Info("[dns] updated A record: %s -> %s", hostname, ip)
	return nil
}

func (d *DigitalOceanDNS) DeleteRecord(hostname string) error {
	d.mu.RLock()
	recordID, exists := d.records[hostname]
	d.mu.RUnlock()

	if !exists {
		return fmt.Errorf("record not found: %s", hostname)
	}

	endpoint := fmt.Sprintf("/domains/%s/records/%d", d.domain, recordID)
	_, err := d.doRequest("DELETE", endpoint, nil)
	if err != nil {
		return err
	}

	d.mu.Lock()
	delete(d.records, hostname)
	d.mu.Unlock()

	log.Info("[dns] deleted A record: %s", hostname)
	return nil
}

func (d *DigitalOceanDNS) ListRecords() ([]DNSRecord, error) {
	endpoint := fmt.Sprintf("/domains/%s/records?type=A&per_page=200", d.domain)
	respBody, err := d.doRequest("GET", endpoint, nil)
	if err != nil {
		return nil, err
	}

	var response struct {
		DomainRecords []struct {
			ID   int    `json:"id"`
			Type string `json:"type"`
			Name string `json:"name"`
			Data string `json:"data"`
			TTL  int    `json:"ttl"`
		} `json:"domain_records"`
	}
	if err := json.Unmarshal(respBody, &response); err != nil {
		return nil, err
	}

	var records []DNSRecord
	d.mu.Lock()
	for _, r := range response.DomainRecords {
		name := r.Name
		if name == "@" {
			name = d.domain
		} else {
			name = r.Name + "." + d.domain
		}
		records = append(records, DNSRecord{
			ID:      fmt.Sprintf("%d", r.ID),
			Name:    name,
			Type:    r.Type,
			Content: r.Data,
			TTL:     r.TTL,
		})
		d.records[name] = r.ID
	}
	d.mu.Unlock()

	return records, nil
}

func (d *DigitalOceanDNS) SyncRecords(hostnames []string, ip string) error {
	existing, err := d.ListRecords()
	if err != nil {
		return err
	}

	existingMap := make(map[string]DNSRecord)
	for _, r := range existing {
		existingMap[r.Name] = r
	}

	for _, hostname := range hostnames {
		if r, exists := existingMap[hostname]; exists {
			if r.Content != ip {
				if err := d.UpdateRecord(hostname, ip); err != nil {
					log.Error("[dns] failed to update record %s: %v", hostname, err)
				}
			}
		} else {
			if err := d.CreateRecord(hostname, ip); err != nil {
				log.Error("[dns] failed to create record %s: %v", hostname, err)
			}
		}
	}

	log.Info("[dns] synced %d records with DigitalOcean", len(hostnames))
	return nil
}

func (d *DigitalOceanDNS) CreateTXTRecord(hostname string, value string) error {
	// Extract subdomain from hostname
	subdomain := strings.TrimSuffix(hostname, "."+d.domain)
	if subdomain == hostname {
		subdomain = "@"
	}

	record := map[string]interface{}{
		"type": "TXT",
		"name": subdomain,
		"data": value,
		"ttl":  120, // Short TTL for ACME challenges
	}

	endpoint := fmt.Sprintf("/domains/%s/records", d.domain)
	respBody, err := d.doRequest("POST", endpoint, record)
	if err != nil {
		return err
	}

	var response struct {
		DomainRecord struct {
			ID int `json:"id"`
		} `json:"domain_record"`
	}
	if err := json.Unmarshal(respBody, &response); err != nil {
		return err
	}

	d.mu.Lock()
	d.records["txt:"+hostname] = response.DomainRecord.ID
	d.mu.Unlock()

	log.Debug("[dns] created TXT record: %s = %s", hostname, value)
	return nil
}

func (d *DigitalOceanDNS) DeleteTXTRecord(hostname string) error {
	d.mu.RLock()
	recordID, exists := d.records["txt:"+hostname]
	d.mu.RUnlock()

	if !exists {
		// Try to find existing TXT record
		endpoint := fmt.Sprintf("/domains/%s/records?type=TXT&per_page=200", d.domain)
		respBody, err := d.doRequest("GET", endpoint, nil)
		if err != nil {
			return err
		}

		var response struct {
			DomainRecords []struct {
				ID   int    `json:"id"`
				Name string `json:"name"`
			} `json:"domain_records"`
		}
		if err := json.Unmarshal(respBody, &response); err != nil {
			return err
		}

		subdomain := strings.TrimSuffix(hostname, "."+d.domain)
		if subdomain == hostname {
			subdomain = "@"
		}

		for _, r := range response.DomainRecords {
			if r.Name == subdomain {
				recordID = r.ID
				break
			}
		}
	}

	if recordID == 0 {
		return nil // Record doesn't exist
	}

	endpoint := fmt.Sprintf("/domains/%s/records/%d", d.domain, recordID)
	_, err := d.doRequest("DELETE", endpoint, nil)
	if err != nil {
		return err
	}

	d.mu.Lock()
	delete(d.records, "txt:"+hostname)
	d.mu.Unlock()

	log.Debug("[dns] deleted TXT record: %s", hostname)
	return nil
}
