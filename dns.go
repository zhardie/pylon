package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// DNSConfig defines the configuration for DNS provider integrations.
type DNSConfig struct {
	Provider string `json:"provider"`            // e.g. "cloudflare", "none", ""
	APIToken string `json:"api_token"`           // Provider API Token
	ZoneID   string `json:"zone_id,omitempty"`   // Optional Zone ID override
	Proxied  bool   `json:"proxied"`             // Enable Cloudflare Proxy / CDN (orange cloud)
	Target   string `json:"target,omitempty"`    // CNAME target override (defaults to TLDN)
	AutoSync bool   `json:"auto_sync"`           // Auto-create CNAME when saving new proxy routes
}

// DNSRecord represents a DNS record retrieved or created via a DNS provider.
type DNSRecord struct {
	ID      string `json:"id,omitempty"`
	Name    string `json:"name"`
	Type    string `json:"type"`
	Content string `json:"content"`
	Proxied bool   `json:"proxied"`
	TTL     int    `json:"ttl"`
	ZoneID  string `json:"zone_id,omitempty"`
}

// DNSCheckResult represents the DNS resolution health check for a proxy hostname.
type DNSCheckResult struct {
	Host                 string   `json:"host"`
	Target               string   `json:"target"`
	Resolved             bool     `json:"resolved"`
	Status               string   `json:"status"` // "ok", "missing", "error"
	CNAME                string   `json:"cname,omitempty"`
	IPs                  []string `json:"ips,omitempty"`
	ProviderRecordExists bool     `json:"provider_record_exists"`
	ProviderRecordID     string   `json:"provider_record_id,omitempty"`
	Message              string   `json:"message"`
}

// DNSProvider defines the interface for DNS management operations.
type DNSProvider interface {
	Name() string
	TestConnection(ctx context.Context) (string, error)
	GetZoneID(ctx context.Context, domain string) (string, error)
	CreateOrUpdateCNAME(ctx context.Context, host, target string, proxied bool) (*DNSRecord, error)
	GetRecord(ctx context.Context, host, recordType string) (*DNSRecord, error)
	ListRecords(ctx context.Context, zoneID string) ([]DNSRecord, error)
}

// NormalizeHost strips protocols, ports, and paths, and appends tldn if needed.
func NormalizeHost(rawHost, tldn string) string {
	rawHost = strings.TrimSpace(rawHost)
	if rawHost == "" {
		return ""
	}

	// Handle url format with protocol
	if strings.Contains(rawHost, "://") {
		if u, err := url.Parse(rawHost); err == nil && u.Host != "" {
			rawHost = u.Host
		}
	}

	// Strip trailing slashes, paths, and ports
	rawHost = strings.TrimPrefix(rawHost, "http://")
	rawHost = strings.TrimPrefix(rawHost, "https://")
	if idx := strings.Index(rawHost, "/"); idx != -1 {
		rawHost = rawHost[:idx]
	}
	if host, _, err := net.SplitHostPort(rawHost); err == nil {
		rawHost = host
	}

	rawHost = strings.TrimSpace(strings.ToLower(rawHost))

	// If rawHost does not contain dots and tldn is specified, append tldn
	if !strings.Contains(rawHost, ".") && tldn != "" {
		rawHost = rawHost + "." + strings.TrimPrefix(tldn, ".")
	}

	return rawHost
}

// GetCNAMETarget determines the canonical target domain for CNAME records.
func GetCNAMETarget(dnsCfg DNSConfig, tldn string) string {
	if dnsCfg.Target != "" {
		return NormalizeHost(dnsCfg.Target, tldn)
	}
	return NormalizeHost(tldn, "")
}

// GetDNSProvider instantiates a DNSProvider based on configuration.
func GetDNSProvider(dnsCfg DNSConfig, tldn string) (DNSProvider, error) {
	providerType := strings.ToLower(strings.TrimSpace(dnsCfg.Provider))
	switch providerType {
	case "cloudflare":
		if strings.TrimSpace(dnsCfg.APIToken) == "" {
			return nil, fmt.Errorf("cloudflare provider selected but api_token is empty")
		}
		return NewCloudflareProvider(dnsCfg.APIToken, dnsCfg.ZoneID, tldn), nil
	case "", "none", "disabled":
		return nil, nil
	default:
		return nil, fmt.Errorf("unsupported dns provider: %s", providerType)
	}
}

// CheckSingleHostDNS verifies DNS resolution for a single hostname.
func CheckSingleHostDNS(ctx context.Context, host, target string, resolver *net.Resolver) DNSCheckResult {
	result := DNSCheckResult{
		Host:   host,
		Target: target,
	}

	if host == "" {
		result.Status = "error"
		result.Message = "Hostname is empty"
		return result
	}

	if resolver == nil {
		resolver = net.DefaultResolver
	}

	// 1. Check CNAME resolution
	cname, err := resolver.LookupCNAME(ctx, host)
	if err == nil && cname != "" {
		cleanCNAME := strings.TrimSuffix(cname, ".")
		result.CNAME = cleanCNAME
	}

	// 2. Check IP address resolution
	ips, err := resolver.LookupHost(ctx, host)
	if err == nil && len(ips) > 0 {
		result.Resolved = true
		result.Status = "ok"
		result.IPs = ips
		if result.CNAME != "" && result.CNAME != host {
			result.Message = fmt.Sprintf("Resolves to %s (CNAME -> %s)", strings.Join(ips, ", "), result.CNAME)
		} else {
			result.Message = fmt.Sprintf("Resolves to %s", strings.Join(ips, ", "))
		}
		return result
	}

	// DNS lookup failed
	result.Resolved = false
	result.Status = "missing"
	if err != nil {
		if dnsErr, ok := err.(*net.DNSError); ok && dnsErr.IsNotFound {
			result.Message = "DNS record not found (NXDOMAIN)"
		} else {
			result.Message = fmt.Sprintf("Unresolved: %v", err)
		}
	} else {
		result.Message = "No IP records found"
	}

	return result
}

// CheckDNSStatus concurrently verifies DNS resolution for a list of hosts.
func CheckDNSStatus(ctx context.Context, hosts []string, target string, provider DNSProvider) []DNSCheckResult {
	results := make([]DNSCheckResult, len(hosts))
	var wg sync.WaitGroup

	resolver := &net.Resolver{
		PreferGo: true,
	}

	// Set timeout for all DNS checks if context has no deadline
	checkCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()

	for i, host := range hosts {
		wg.Add(1)
		go func(idx int, rawHost string) {
			defer wg.Done()
			normalized := NormalizeHost(rawHost, target)
			res := CheckSingleHostDNS(checkCtx, normalized, target, resolver)

			// If provider is active, check if record exists in provider even if public DNS hasn't propagated yet
			if provider != nil && normalized != "" {
				if rec, err := provider.GetRecord(checkCtx, normalized, "CNAME"); err == nil && rec != nil {
					res.ProviderRecordExists = true
					res.ProviderRecordID = rec.ID
					if !res.Resolved {
						res.Message = fmt.Sprintf("Cloudflare record exists (%s -> %s), pending DNS propagation", rec.Name, rec.Content)
					}
				}
			}

			results[idx] = res
		}(i, host)
	}

	wg.Wait()
	return results
}

// DNSStatusResponse represents the response payload for the DNS status API.
type DNSStatusResponse struct {
	Provider   string           `json:"provider"`
	Target     string           `json:"target"`
	Configured bool             `json:"configured"`
	AutoSync   bool             `json:"auto_sync"`
	Results    []DNSCheckResult `json:"results"`
}

// DNSStatusHandler handles GET /dns/status requests.
func DNSStatusHandler(w http.ResponseWriter, r *http.Request) {
	enableCORS(&w, r)
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != "GET" {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	cfgMu.RLock()
	dnsCfg := cfg.DNS
	tldn := cfg.TLDN
	proxiesList := cfg.Proxies
	cfgMu.RUnlock()

	target := GetCNAMETarget(dnsCfg, tldn)
	var hosts []string
	for _, p := range proxiesList {
		if p.External != "" {
			hosts = append(hosts, p.External)
		}
	}

	provider, err := GetDNSProvider(dnsCfg, tldn)
	if err != nil {
		log.Printf("Error initializing DNS provider for status check: %v", err)
	}

	results := CheckDNSStatus(r.Context(), hosts, target, provider)

	resp := DNSStatusResponse{
		Provider:   dnsCfg.Provider,
		Target:     target,
		Configured: provider != nil,
		AutoSync:   dnsCfg.AutoSync,
		Results:    results,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// DNSCreateRequest represents the request body for creating a DNS CNAME record.
type DNSCreateRequest struct {
	Host    string `json:"host"`
	Target  string `json:"target,omitempty"`
	Proxied *bool  `json:"proxied,omitempty"`
}

// DNSCreateResponse represents the response body for CNAME creation.
type DNSCreateResponse struct {
	Success bool       `json:"success"`
	Message string     `json:"message"`
	Record  *DNSRecord `json:"record,omitempty"`
}

// DNSCreateHandler handles POST /dns/create requests.
func DNSCreateHandler(w http.ResponseWriter, r *http.Request) {
	enableCORS(&w, r)
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != "POST" {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req DNSCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON body: "+err.Error(), http.StatusBadRequest)
		return
	}

	if strings.TrimSpace(req.Host) == "" {
		http.Error(w, "host is required", http.StatusBadRequest)
		return
	}

	cfgMu.RLock()
	dnsCfg := cfg.DNS
	tldn := cfg.TLDN
	cfgMu.RUnlock()

	provider, err := GetDNSProvider(dnsCfg, tldn)
	if err != nil {
		http.Error(w, "DNS Provider configuration error: "+err.Error(), http.StatusBadRequest)
		return
	}
	if provider == nil {
		http.Error(w, "DNS Provider is not configured. Please configure Cloudflare in Settings.", http.StatusBadRequest)
		return
	}

	normalizedHost := NormalizeHost(req.Host, tldn)
	target := req.Target
	if target == "" {
		target = GetCNAMETarget(dnsCfg, tldn)
	} else {
		target = NormalizeHost(target, tldn)
	}

	proxied := dnsCfg.Proxied
	if req.Proxied != nil {
		proxied = *req.Proxied
	}

	record, err := provider.CreateOrUpdateCNAME(r.Context(), normalizedHost, target, proxied)
	if err != nil {
		log.Printf("Failed to create CNAME for %s -> %s: %v", normalizedHost, target, err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(DNSCreateResponse{
			Success: false,
			Message: err.Error(),
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(DNSCreateResponse{
		Success: true,
		Message: fmt.Sprintf("Successfully configured CNAME: %s -> %s", normalizedHost, target),
		Record:  record,
	})
}

// DNSSyncResponse represents the summary result of batch syncing DNS records.
type DNSSyncResponse struct {
	Success     bool              `json:"success"`
	SyncedCount int               `json:"synced_count"`
	ErrorCount  int               `json:"error_count"`
	Results     []DNSCreateResponse `json:"results"`
}

// DNSSyncHandler handles POST /dns/sync requests to sync all routes.
func DNSSyncHandler(w http.ResponseWriter, r *http.Request) {
	enableCORS(&w, r)
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != "POST" {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	cfgMu.RLock()
	dnsCfg := cfg.DNS
	tldn := cfg.TLDN
	proxiesList := cfg.Proxies
	cfgMu.RUnlock()

	provider, err := GetDNSProvider(dnsCfg, tldn)
	if err != nil {
		http.Error(w, "DNS Provider configuration error: "+err.Error(), http.StatusBadRequest)
		return
	}
	if provider == nil {
		http.Error(w, "DNS Provider is not configured. Please configure Cloudflare in Settings.", http.StatusBadRequest)
		return
	}

	target := GetCNAMETarget(dnsCfg, tldn)
	var syncResults []DNSCreateResponse
	syncedCount := 0
	errorCount := 0

	for _, p := range proxiesList {
		host := NormalizeHost(p.External, tldn)
		if host == "" || host == target {
			continue
		}

		rec, err := provider.CreateOrUpdateCNAME(r.Context(), host, target, dnsCfg.Proxied)
		if err != nil {
			errorCount++
			syncResults = append(syncResults, DNSCreateResponse{
				Success: false,
				Message: fmt.Sprintf("Failed %s -> %s: %v", host, target, err),
			})
		} else {
			syncedCount++
			syncResults = append(syncResults, DNSCreateResponse{
				Success: true,
				Message: fmt.Sprintf("Synced %s -> %s", host, target),
				Record:  rec,
			})
		}
	}

	resp := DNSSyncResponse{
		Success:     errorCount == 0,
		SyncedCount: syncedCount,
		ErrorCount:  errorCount,
		Results:     syncResults,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// DNSTestRequest represents test parameters sent to verify DNS connectivity.
type DNSTestRequest struct {
	Provider string `json:"provider"`
	APIToken string `json:"api_token"`
	ZoneID   string `json:"zone_id,omitempty"`
	TLDN     string `json:"tldn,omitempty"`
}

// DNSTestResponse represents the result of the DNS connection test.
type DNSTestResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	ZoneID  string `json:"zone_id,omitempty"`
}

// DNSTestHandler handles POST /dns/test requests to verify provider credentials.
func DNSTestHandler(w http.ResponseWriter, r *http.Request) {
	enableCORS(&w, r)
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != "POST" {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req DNSTestRequest
	// Optional body parsing - if empty, use current config
	_ = json.NewDecoder(r.Body).Decode(&req)

	cfgMu.RLock()
	dnsCfg := cfg.DNS
	tldn := cfg.TLDN
	cfgMu.RUnlock()

	if req.Provider != "" {
		dnsCfg.Provider = req.Provider
	}
	if req.APIToken != "" {
		dnsCfg.APIToken = req.APIToken
	}
	if req.ZoneID != "" {
		dnsCfg.ZoneID = req.ZoneID
	}
	if req.TLDN != "" {
		tldn = req.TLDN
	}

	provider, err := GetDNSProvider(dnsCfg, tldn)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(DNSTestResponse{
			Success: false,
			Message: "Provider error: " + err.Error(),
		})
		return
	}

	if provider == nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(DNSTestResponse{
			Success: false,
			Message: "No DNS provider selected or credentials missing",
		})
		return
	}

	msg, err := provider.TestConnection(r.Context())
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(DNSTestResponse{
			Success: false,
			Message: err.Error(),
		})
		return
	}

	zoneID, _ := provider.GetZoneID(r.Context(), tldn)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(DNSTestResponse{
		Success: true,
		Message: msg,
		ZoneID:  zoneID,
	})
}
