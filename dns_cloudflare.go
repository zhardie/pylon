package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// CloudflareProvider implements DNSProvider for Cloudflare.
type CloudflareProvider struct {
	APIToken     string
	AccountEmail string
	ZoneID       string
	TLDN         string
	BaseURL      string // defaults to https://api.cloudflare.com/client/v4
	Client       *http.Client
}

// NewCloudflareProvider creates a new Cloudflare DNS provider instance.
func NewCloudflareProvider(apiToken, accountEmail, zoneID, tldn string) *CloudflareProvider {
	cleanToken := strings.TrimSpace(apiToken)
	cleanToken = strings.Trim(cleanToken, `"'`+"`")
	if strings.HasPrefix(strings.ToLower(cleanToken), "bearer ") {
		cleanToken = strings.TrimSpace(cleanToken[7:])
	}
	cleanToken = strings.Trim(cleanToken, `"'`+"`")

	return &CloudflareProvider{
		APIToken:     cleanToken,
		AccountEmail: strings.TrimSpace(accountEmail),
		ZoneID:       strings.TrimSpace(zoneID),
		TLDN:         strings.TrimSpace(tldn),
		BaseURL:      "https://api.cloudflare.com/client/v4",
		Client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func (cf *CloudflareProvider) Name() string {
	return "cloudflare"
}

type cfResponse struct {
	Success  bool            `json:"success"`
	Errors   []cfError       `json:"errors"`
	Messages []cfError       `json:"messages"`
	Result   json.RawMessage `json:"result"`
}

type cfError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type cfZone struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"`
}

type cfDNSRecord struct {
	ID        string `json:"id"`
	Type      string `json:"type"`
	Name      string `json:"name"`
	Content   string `json:"content"`
	Proxiable bool   `json:"proxiable"`
	Proxied   bool   `json:"proxied"`
	TTL       int    `json:"ttl"`
	ZoneID    string `json:"zone_id"`
	Comment   string `json:"comment"`
}

func (cf *CloudflareProvider) doRequest(ctx context.Context, method, endpoint string, body interface{}) (*cfResponse, error) {
	var bodyReader io.Reader
	if body != nil {
		jsonBytes, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to encode request body: %w", err)
		}
		bodyReader = bytes.NewReader(jsonBytes)
	}

	url := cf.BaseURL + endpoint
	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	if cf.AccountEmail != "" {
		req.Header.Set("X-Auth-Key", cf.APIToken)
		req.Header.Set("X-Auth-Email", cf.AccountEmail)
	} else {
		req.Header.Set("Authorization", "Bearer "+cf.APIToken)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Pylon-Reverse-Proxy/1.0")

	resp, err := cf.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http request failed: %w", err)
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var cfResp cfResponse
	if err := json.Unmarshal(respBytes, &cfResp); err != nil {
		return nil, fmt.Errorf("failed to parse cloudflare response (HTTP %d): %s", resp.StatusCode, string(respBytes))
	}

	if !cfResp.Success || resp.StatusCode >= 400 {
		var errMsgs []string
		for _, e := range cfResp.Errors {
			errMsgs = append(errMsgs, fmt.Sprintf("[%d] %s", e.Code, e.Message))
		}
		if len(errMsgs) == 0 {
			errMsgs = append(errMsgs, fmt.Sprintf("HTTP status %d", resp.StatusCode))
		}
		return &cfResp, fmt.Errorf("cloudflare API error: %s", strings.Join(errMsgs, "; "))
	}

	return &cfResp, nil
}

// TestConnection verifies token validity and retrieves zone info.
func (cf *CloudflareProvider) TestConnection(ctx context.Context) (string, error) {
	if cf.APIToken == "" {
		return "", fmt.Errorf("api_token is empty")
	}

	// 1. If no account email is set, try standard Bearer token verification
	if cf.AccountEmail == "" {
		_, err := cf.doRequest(ctx, "GET", "/user/tokens/verify", nil)
		if err == nil {
			if cf.ZoneID != "" {
				return fmt.Sprintf("API Token verified successfully. Using configured Zone ID: %s", cf.ZoneID), nil
			}
			if cf.TLDN != "" {
				zoneID, err := cf.GetZoneID(ctx, cf.TLDN)
				if err != nil {
					return "", fmt.Errorf("API Token is active, but failed to find Zone for %q: %w", cf.TLDN, err)
				}
				return fmt.Sprintf("API Token verified successfully! Found Zone %q (ID: %s)", cf.TLDN, zoneID), nil
			}
			return "API Token is valid and active", nil
		}

		// 2. Fallback: If /user/tokens/verify fails, try direct zone discovery.
		// Tokens scoped exclusively to a Zone (e.g. Zone.DNS Edit) may not have permission to read /user/tokens/verify.
		if cf.TLDN != "" {
			zoneID, zoneErr := cf.GetZoneID(ctx, cf.TLDN)
			if zoneErr == nil && zoneID != "" {
				return fmt.Sprintf("Token verified successfully! Connected to Zone %q (ID: %s)", cf.TLDN, zoneID), nil
			}
		}

		return "", fmt.Errorf("token verification failed: %w. (Tip: If using a Global API Key instead of an API Token, please configure Account Email. If using an API Token, ensure it was created from https://dash.cloudflare.com/profile/api-tokens with 'Zone - DNS - Edit' and 'Zone - Zone - Read' permissions)", err)
	}

	// 3. Global API Key + Email Verification
	if cf.TLDN != "" {
		zoneID, err := cf.GetZoneID(ctx, cf.TLDN)
		if err != nil {
			return "", fmt.Errorf("Global API Key authentication failed for Zone %q: %w", cf.TLDN, err)
		}
		return fmt.Sprintf("Global API Key verified successfully! Connected to Zone %q (ID: %s)", cf.TLDN, zoneID), nil
	}

	resp, err := cf.doRequest(ctx, "GET", "/zones?status=active&per_page=1", nil)
	if err != nil {
		return "", fmt.Errorf("Global API Key authentication failed: %w", err)
	}
	if resp.Success {
		return "Global API Key verified successfully", nil
	}
	return "", fmt.Errorf("authentication failed")
}

// GetZoneID discovers the Zone ID for a domain name or its parent zone.
func (cf *CloudflareProvider) GetZoneID(ctx context.Context, domain string) (string, error) {
	if cf.ZoneID != "" {
		return cf.ZoneID, nil
	}

	cleanDomain := strings.TrimSpace(strings.ToLower(domain))
	cleanDomain = strings.TrimPrefix(cleanDomain, "http://")
	cleanDomain = strings.TrimPrefix(cleanDomain, "https://")
	if idx := strings.Index(cleanDomain, "/"); idx != -1 {
		cleanDomain = cleanDomain[:idx]
	}

	// Try progressively stripping subdomains until zone is found (e.g. foo.bar.example.com -> bar.example.com -> example.com)
	currentDomain := cleanDomain
	for currentDomain != "" && strings.Contains(currentDomain, ".") {
		endpoint := fmt.Sprintf("/zones?name=%s&status=active", currentDomain)
		resp, err := cf.doRequest(ctx, "GET", endpoint, nil)
		if err == nil && resp.Success {
			var zones []cfZone
			if err := json.Unmarshal(resp.Result, &zones); err == nil && len(zones) > 0 {
				return zones[0].ID, nil
			}
		}

		// Strip left-most label
		idx := strings.Index(currentDomain, ".")
		if idx == -1 {
			break
		}
		currentDomain = currentDomain[idx+1:]
	}

	// If still not found and TLDN is configured, try TLDN
	if cf.TLDN != "" && cleanDomain != cf.TLDN {
		endpoint := fmt.Sprintf("/zones?name=%s&status=active", cf.TLDN)
		resp, err := cf.doRequest(ctx, "GET", endpoint, nil)
		if err == nil && resp.Success {
			var zones []cfZone
			if err := json.Unmarshal(resp.Result, &zones); err == nil && len(zones) > 0 {
				return zones[0].ID, nil
			}
		}
	}

	return "", fmt.Errorf("zone not found in Cloudflare for domain %q", domain)
}

// GetRecord searches for an existing DNS record by host and type.
func (cf *CloudflareProvider) GetRecord(ctx context.Context, host, recordType string) (*DNSRecord, error) {
	zoneID, err := cf.GetZoneID(ctx, host)
	if err != nil {
		return nil, err
	}

	endpoint := fmt.Sprintf("/zones/%s/dns_records?name=%s", zoneID, host)
	if recordType != "" {
		endpoint += fmt.Sprintf("&type=%s", recordType)
	}

	resp, err := cf.doRequest(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, err
	}

	var records []cfDNSRecord
	if err := json.Unmarshal(resp.Result, &records); err != nil {
		return nil, fmt.Errorf("failed to unmarshal DNS records: %w", err)
	}

	if len(records) == 0 {
		return nil, nil
	}

	rec := records[0]
	return &DNSRecord{
		ID:      rec.ID,
		Name:    rec.Name,
		Type:    rec.Type,
		Content: rec.Content,
		Proxied: rec.Proxied,
		TTL:     rec.TTL,
		ZoneID:  rec.ZoneID,
	}, nil
}

// ListRecords lists all DNS records in a zone.
func (cf *CloudflareProvider) ListRecords(ctx context.Context, zoneID string) ([]DNSRecord, error) {
	if zoneID == "" {
		var err error
		zoneID, err = cf.GetZoneID(ctx, cf.TLDN)
		if err != nil {
			return nil, err
		}
	}

	endpoint := fmt.Sprintf("/zones/%s/dns_records?per_page=100", zoneID)
	resp, err := cf.doRequest(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, err
	}

	var cfRecords []cfDNSRecord
	if err := json.Unmarshal(resp.Result, &cfRecords); err != nil {
		return nil, fmt.Errorf("failed to unmarshal DNS records list: %w", err)
	}

	records := make([]DNSRecord, len(cfRecords))
	for i, r := range cfRecords {
		records[i] = DNSRecord{
			ID:      r.ID,
			Name:    r.Name,
			Type:    r.Type,
			Content: r.Content,
			Proxied: r.Proxied,
			TTL:     r.TTL,
			ZoneID:  r.ZoneID,
		}
	}

	return records, nil
}

// CreateOrUpdateCNAME creates a new CNAME or updates an existing record.
func (cf *CloudflareProvider) CreateOrUpdateCNAME(ctx context.Context, host, target string, proxied bool) (*DNSRecord, error) {
	host = strings.TrimSpace(strings.ToLower(host))
	target = strings.TrimSpace(strings.ToLower(target))

	if host == "" || target == "" {
		return nil, fmt.Errorf("both host and target are required")
	}

	zoneID, err := cf.GetZoneID(ctx, host)
	if err != nil {
		return nil, err
	}

	// Check if record already exists
	existing, err := cf.GetRecord(ctx, host, "")
	if err != nil {
		return nil, fmt.Errorf("failed to check existing DNS record: %w", err)
	}

	payload := map[string]interface{}{
		"type":    "CNAME",
		"name":    host,
		"content": target,
		"ttl":     1, // 1 = Auto TTL in Cloudflare
		"proxied": proxied,
		"comment": "Managed by Pylon",
	}

	if existing != nil {
		// Update existing record
		endpoint := fmt.Sprintf("/zones/%s/dns_records/%s", zoneID, existing.ID)
		resp, err := cf.doRequest(ctx, "PUT", endpoint, payload)
		if err != nil {
			return nil, fmt.Errorf("failed to update CNAME record: %w", err)
		}

		var updated cfDNSRecord
		if err := json.Unmarshal(resp.Result, &updated); err != nil {
			return nil, fmt.Errorf("failed to parse updated record: %w", err)
		}

		return &DNSRecord{
			ID:      updated.ID,
			Name:    updated.Name,
			Type:    updated.Type,
			Content: updated.Content,
			Proxied: updated.Proxied,
			TTL:     updated.TTL,
			ZoneID:  zoneID,
		}, nil
	}

	// Create new record
	endpoint := fmt.Sprintf("/zones/%s/dns_records", zoneID)
	resp, err := cf.doRequest(ctx, "POST", endpoint, payload)
	if err != nil {
		return nil, fmt.Errorf("failed to create CNAME record in Cloudflare: %w", err)
	}

	var created cfDNSRecord
	if err := json.Unmarshal(resp.Result, &created); err != nil {
		return nil, fmt.Errorf("failed to parse created record: %w", err)
	}

	return &DNSRecord{
		ID:      created.ID,
		Name:    created.Name,
		Type:    created.Type,
		Content: created.Content,
		Proxied: created.Proxied,
		TTL:     created.TTL,
		ZoneID:  zoneID,
	}, nil
}
