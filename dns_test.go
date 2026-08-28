package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNormalizeHost(t *testing.T) {
	tests := []struct {
		input    string
		tldn     string
		expected string
	}{
		{"grafana.example.com", "example.com", "grafana.example.com"},
		{"https://grafana.example.com", "example.com", "grafana.example.com"},
		{"http://grafana.example.com:8080/path", "example.com", "grafana.example.com"},
		{"newapp", "hardie.dev", "newapp.hardie.dev"},
		{"newapp.hardie.dev", "hardie.dev", "newapp.hardie.dev"},
		{"  FOO.BAR.COM  ", "bar.com", "foo.bar.com"},
		{"", "hardie.dev", ""},
	}

	for _, tc := range tests {
		got := NormalizeHost(tc.input, tc.tldn)
		if got != tc.expected {
			t.Errorf("NormalizeHost(%q, %q) = %q; want %q", tc.input, tc.tldn, got, tc.expected)
		}
	}
}

func TestGetCNAMETarget(t *testing.T) {
	cfg1 := DNSConfig{Target: "ddns.hardie.dev"}
	if got := GetCNAMETarget(cfg1, "hardie.dev"); got != "ddns.hardie.dev" {
		t.Errorf("GetCNAMETarget with override = %q; want 'ddns.hardie.dev'", got)
	}

	cfg2 := DNSConfig{Target: ""}
	if got := GetCNAMETarget(cfg2, "hardie.dev"); got != "hardie.dev" {
		t.Errorf("GetCNAMETarget without override = %q; want 'hardie.dev'", got)
	}
}

func TestCloudflareProvider_MockAPI(t *testing.T) {
	var recordsCreated []map[string]interface{}
	var recordsUpdated []map[string]interface{}

	// Mock Cloudflare API Server
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify Bearer Auth Header
		auth := r.Header.Get("Authorization")
		if auth != "Bearer valid-cf-token" {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"errors": []map[string]interface{}{
					{"code": 10000, "message": "Authentication error"},
				},
			})
			return
		}

		w.Header().Set("Content-Type", "application/json")

		// 1. /user/tokens/verify
		if r.URL.Path == "/user/tokens/verify" {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": true,
				"result": map[string]interface{}{
					"id":     "token-id-123",
					"status": "active",
				},
			})
			return
		}

		// 2. /zones
		if r.URL.Path == "/zones" {
			zoneName := r.URL.Query().Get("name")
			if zoneName == "hardie.dev" || zoneName == "sub.hardie.dev" {
				json.NewEncoder(w).Encode(map[string]interface{}{
					"success": true,
					"result": []map[string]interface{}{
						{
							"id":     "zone-12345",
							"name":   "hardie.dev",
							"status": "active",
						},
					},
				})
				return
			}
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": true,
				"result":  []map[string]interface{}{},
			})
			return
		}

		// 3. /zones/:id/dns_records
		if strings.HasPrefix(r.URL.Path, "/zones/zone-12345/dns_records") {
			if r.Method == "GET" {
				name := r.URL.Query().Get("name")
				if name == "existing.hardie.dev" {
					json.NewEncoder(w).Encode(map[string]interface{}{
						"success": true,
						"result": []map[string]interface{}{
							{
								"id":        "rec-existing-1",
								"type":      "CNAME",
								"name":      "existing.hardie.dev",
								"content":   "hardie.dev",
								"proxiable": true,
								"proxied":   false,
								"ttl":       1,
								"zone_id":   "zone-12345",
							},
						},
					})
					return
				}
				json.NewEncoder(w).Encode(map[string]interface{}{
					"success": true,
					"result":  []map[string]interface{}{},
				})
				return
			}

			if r.Method == "POST" {
				var body map[string]interface{}
				json.NewDecoder(r.Body).Decode(&body)
				recordsCreated = append(recordsCreated, body)

				json.NewEncoder(w).Encode(map[string]interface{}{
					"success": true,
					"result": map[string]interface{}{
						"id":        "rec-new-999",
						"type":      body["type"],
						"name":      body["name"],
						"content":   body["content"],
						"proxied":   body["proxied"],
						"ttl":       body["ttl"],
						"zone_id":   "zone-12345",
					},
				})
				return
			}

			if r.Method == "PUT" {
				var body map[string]interface{}
				json.NewDecoder(r.Body).Decode(&body)
				recordsUpdated = append(recordsUpdated, body)

				json.NewEncoder(w).Encode(map[string]interface{}{
					"success": true,
					"result": map[string]interface{}{
						"id":        "rec-existing-1",
						"type":      body["type"],
						"name":      body["name"],
						"content":   body["content"],
						"proxied":   body["proxied"],
						"ttl":       body["ttl"],
						"zone_id":   "zone-12345",
					},
				})
				return
			}
		}

		http.NotFound(w, r)
	}))
	defer mockServer.Close()

	provider := NewCloudflareProvider("valid-cf-token", "", "", "hardie.dev")
	provider.BaseURL = mockServer.URL
	ctx := context.Background()

	// Test Connection
	msg, err := provider.TestConnection(ctx)
	if err != nil {
		t.Fatalf("TestConnection failed: %v", err)
	}
	if !strings.Contains(msg, "zone-12345") {
		t.Errorf("TestConnection response unexpected: %s", msg)
	}

	// Test GetZoneID
	zoneID, err := provider.GetZoneID(ctx, "app.hardie.dev")
	if err != nil {
		t.Fatalf("GetZoneID failed: %v", err)
	}
	if zoneID != "zone-12345" {
		t.Errorf("GetZoneID = %q; want 'zone-12345'", zoneID)
	}

	// Test Create CNAME for new record
	rec, err := provider.CreateOrUpdateCNAME(ctx, "newapp.hardie.dev", "hardie.dev", true)
	if err != nil {
		t.Fatalf("CreateOrUpdateCNAME for new record failed: %v", err)
	}
	if rec.ID != "rec-new-999" || rec.Name != "newapp.hardie.dev" || rec.Content != "hardie.dev" || !rec.Proxied {
		t.Errorf("CreateOrUpdateCNAME returned unexpected record: %+v", rec)
	}
	if len(recordsCreated) != 1 {
		t.Errorf("Expected 1 record created, got %d", len(recordsCreated))
	}

	// Test Update existing CNAME
	rec2, err := provider.CreateOrUpdateCNAME(ctx, "existing.hardie.dev", "hardie.dev", false)
	if err != nil {
		t.Fatalf("CreateOrUpdateCNAME for existing record failed: %v", err)
	}
	if rec2.ID != "rec-existing-1" {
		t.Errorf("CreateOrUpdateCNAME update returned unexpected ID: %s", rec2.ID)
	}
}

func TestDNSAPIHandlers(t *testing.T) {
	setupTestConfig()

	// Create mock Cloudflare server
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/user/tokens/verify" {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": true,
				"result":  map[string]interface{}{"id": "token-1", "status": "active"},
			})
			return
		}
		if r.URL.Path == "/zones" {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": true,
				"result":  []map[string]interface{}{{"id": "zone-ex", "name": "example.com", "status": "active"}},
			})
			return
		}
		if strings.HasPrefix(r.URL.Path, "/zones/zone-ex/dns_records") {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": true,
				"result": map[string]interface{}{
					"id":      "rec-123",
					"type":    "CNAME",
					"name":    "app.example.com",
					"content": "example.com",
					"proxied": false,
					"ttl":     1,
					"zone_id": "zone-ex",
				},
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer mockServer.Close()

	cfgMu.Lock()
	cfg.DNS = DNSConfig{
		Provider: "cloudflare",
		APIToken: "mock-token",
		Target:   "example.com",
		Proxied:  false,
		AutoSync: true,
	}
	cfgMu.Unlock()

	// 1. Test DNSStatusHandler
	{
		req := httptest.NewRequest("GET", "/dns/status", nil)
		rec := httptest.NewRecorder()
		DNSStatusHandler(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("DNSStatusHandler returned status %d; want 200", rec.Code)
		}

		var resp DNSStatusResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("Failed to decode DNSStatusResponse: %v", err)
		}
		if resp.Provider != "cloudflare" || resp.Target != "example.com" {
			t.Errorf("Unexpected DNSStatusResponse metadata: %+v", resp)
		}
		if len(resp.Results) != len(cfg.Proxies) {
			t.Errorf("Expected %d results, got %d", len(cfg.Proxies), len(resp.Results))
		}
	}

	// 2. Test DNSTestHandler
	{
		testBody := DNSTestRequest{
			Provider: "cloudflare",
			APIToken: "test-token",
			TLDN:     "example.com",
		}
		b, _ := json.Marshal(testBody)
		req := httptest.NewRequest("POST", "/dns/test", bytes.NewReader(b))
		rec := httptest.NewRecorder()
		DNSTestHandler(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("DNSTestHandler returned status %d; want 200", rec.Code)
		}
	}
}

func TestCheckSingleHostDNS(t *testing.T) {
	ctx := context.Background()

	// Empty host
	res := CheckSingleHostDNS(ctx, "", "example.com", nil)
	if res.Status != "error" {
		t.Errorf("CheckSingleHostDNS with empty host status = %q; want 'error'", res.Status)
	}

	// Localhost should resolve
	resLocal := CheckSingleHostDNS(ctx, "localhost", "localhost", nil)
	if !resLocal.Resolved || resLocal.Status != "ok" {
		t.Errorf("CheckSingleHostDNS('localhost') should resolve, got %+v", resLocal)
	}

	// Non-existent domain
	resMissing := CheckSingleHostDNS(ctx, "nonexistent-domain-xyz-123456789.invalid", "example.com", nil)
	if resMissing.Resolved || resMissing.Status != "missing" {
		t.Errorf("CheckSingleHostDNS for non-existent domain should be missing, got %+v", resMissing)
	}
}

func TestCloudflareTokenSanitizationAndAuthHeaders(t *testing.T) {
	// 1. Test Bearer prefix stripping and quotes trimming
	cf1 := NewCloudflareProvider("  \"Bearer my-secret-token\"  ", "", "", "example.com")
	if cf1.APIToken != "my-secret-token" {
		t.Errorf("NewCloudflareProvider did not strip Bearer prefix and quotes: got %q, want 'my-secret-token'", cf1.APIToken)
	}

	cf2 := NewCloudflareProvider("`bearer  abc-123`", "", "", "example.com")
	if cf2.APIToken != "abc-123" {
		t.Errorf("NewCloudflareProvider did not strip lowercase bearer: got %q, want 'abc-123'", cf2.APIToken)
	}

	// 2. Test Global API Key Auth Headers
	var receivedAuthKey, receivedAuthEmail string
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuthKey = r.Header.Get("X-Auth-Key")
		receivedAuthEmail = r.Header.Get("X-Auth-Email")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"result":  []map[string]interface{}{{"id": "zone-global", "name": "example.com", "status": "active"}},
		})
	}))
	defer mockServer.Close()

	cfGlobal := NewCloudflareProvider("global-key-123", "user@example.com", "", "example.com")
	cfGlobal.BaseURL = mockServer.URL

	msg, err := cfGlobal.TestConnection(context.Background())
	if err != nil {
		t.Fatalf("Global API Key TestConnection failed: %v", err)
	}
	if !strings.Contains(msg, "zone-global") {
		t.Errorf("Unexpected TestConnection message: %s", msg)
	}
	if receivedAuthKey != "global-key-123" || receivedAuthEmail != "user@example.com" {
		t.Errorf("Expected X-Auth-Key and X-Auth-Email headers, got key=%q, email=%q", receivedAuthKey, receivedAuthEmail)
	}
}
