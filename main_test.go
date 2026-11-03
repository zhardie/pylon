package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/sessions"
)

func setupTestConfig() {
	cfgMu.Lock()
	cfg = Config{
		TLDN:         "example.com",
		SessionKey:   "test-secret-session-key-123456",
		CookieExpire: 24 * time.Hour,
		Proxies: []ProxyRouteConfig{
			{
				Internal:     "http://192.168.1.10:3000",
				External:     "grafana.example.com",
				AllowedUsers: []string{}, // open to all authenticated users
			},
			{
				Internal:     "http://192.168.1.11:8080",
				External:     "home-assistant.example.com",
				AllowedUsers: []string{"alice@example.com"}, // restricted
			},
			{
				Internal:     "http://192.168.1.12:8096",
				External:     "jellyfin.example.com",
				AllowedUsers: []string{"bob@example.com"}, // restricted
			},
			{
				Internal:     "http://192.168.1.13:8000",
				External:     "vault.example.com",
				AllowedUsers: []string{"alice@example.com", "bob@example.com"},
			},
		},
		OAuthProviders: make(map[string]OAuthProvider),
	}
	store = sessions.NewCookieStore([]byte(cfg.SessionKey))
	cfgMu.Unlock()
}

func createAuthenticatedRequest(method, urlStr, email string) *http.Request {
	req := httptest.NewRequest(method, urlStr, nil)
	sessionStore := getSessionStore()
	session, _ := sessionStore.Get(req, "pylon")
	session.Values["email"] = email

	// Save to a recorder to get the cookie header
	rec := httptest.NewRecorder()
	_ = session.Save(req, rec)

	// Transfer cookie to request
	for _, cookie := range rec.Result().Cookies() {
		req.AddCookie(cookie)
	}

	return req
}

func TestFormatAppItem(t *testing.T) {
	tests := []struct {
		external     string
		expectedName string
		expectedIcon string
		expectedCat  string
		expectedURL  string
	}{
		{
			external:     "grafana.example.com",
			expectedName: "Grafana",
			expectedIcon: "insights",
			expectedCat:  "Monitoring",
			expectedURL:  "https://grafana.example.com",
		},
		{
			external:     "home-assistant.example.com",
			expectedName: "Home Assistant",
			expectedIcon: "home",
			expectedCat:  "Smart Home",
			expectedURL:  "https://home-assistant.example.com",
		},
		{
			external:     "jellyfin.example.com",
			expectedName: "Jellyfin",
			expectedIcon: "movie",
			expectedCat:  "Media",
			expectedURL:  "https://jellyfin.example.com",
		},
		{
			external:     "vault.example.com",
			expectedName: "Vault",
			expectedIcon: "lock",
			expectedCat:  "Security",
			expectedURL:  "https://vault.example.com",
		},
		{
			external:     "http://custom-tool.example.com:8080",
			expectedName: "Custom Tool",
			expectedIcon: "apps",
			expectedCat:  "Service",
			expectedURL:  "http://custom-tool.example.com:8080",
		},
	}

	for _, tc := range tests {
		item := formatAppItem(tc.external)
		if item.Name != tc.expectedName {
			t.Errorf("formatAppItem(%q).Name = %q; want %q", tc.external, item.Name, tc.expectedName)
		}
		if item.Icon != tc.expectedIcon {
			t.Errorf("formatAppItem(%q).Icon = %q; want %q", tc.external, item.Icon, tc.expectedIcon)
		}
		if item.Description != tc.expectedCat {
			t.Errorf("formatAppItem(%q).Description = %q; want %q", tc.external, item.Description, tc.expectedCat)
		}
		if item.URL != tc.expectedURL {
			t.Errorf("formatAppItem(%q).URL = %q; want %q", tc.external, item.URL, tc.expectedURL)
		}
	}
}

func TestUserInAllowedList(t *testing.T) {
	openProxy := &ProxyDetails{
		AllowedUsers: []string{},
	}
	if !openProxy.userInAllowedList("random@example.com") {
		t.Errorf("expected open proxy (empty AllowedUsers) to allow any authenticated user")
	}

	restrictedProxy := &ProxyDetails{
		AllowedUsers: []string{"alice@example.com", "charlie@example.com"},
	}
	if !restrictedProxy.userInAllowedList("alice@example.com") {
		t.Errorf("expected restricted proxy to allow alice@example.com")
	}
	if restrictedProxy.userInAllowedList("bob@example.com") {
		t.Errorf("expected restricted proxy to deny bob@example.com")
	}
}

func TestGetUserAllowedApps(t *testing.T) {
	setupTestConfig()

	// Alice has access to: open (grafana), home-assistant, vault
	appsAlice, itemsAlice := getUserAllowedApps("alice@example.com")
	if len(appsAlice) != 3 {
		t.Fatalf("expected Alice to have 3 apps; got %d (%v)", len(appsAlice), appsAlice)
	}
	if !sliceContains(appsAlice, "grafana.example.com") ||
		!sliceContains(appsAlice, "home-assistant.example.com") ||
		!sliceContains(appsAlice, "vault.example.com") {
		t.Errorf("unexpected apps for Alice: %v", appsAlice)
	}
	if len(itemsAlice) != 3 {
		t.Errorf("expected 3 items for Alice, got %d", len(itemsAlice))
	}

	// Bob has access to: open (grafana), jellyfin, vault
	appsBob, _ := getUserAllowedApps("bob@example.com")
	if len(appsBob) != 3 {
		t.Fatalf("expected Bob to have 3 apps; got %d (%v)", len(appsBob), appsBob)
	}
	if sliceContains(appsBob, "home-assistant.example.com") {
		t.Errorf("Bob should not have access to home-assistant")
	}

	// Stranger only has access to open proxies (grafana)
	appsStranger, _ := getUserAllowedApps("stranger@other.com")
	if len(appsStranger) != 1 || appsStranger[0] != "grafana.example.com" {
		t.Errorf("expected Stranger to have only grafana.example.com; got %v", appsStranger)
	}
}

func TestAppsDashboardHandler_UnauthenticatedRedirect(t *testing.T) {
	setupTestConfig()

	req := httptest.NewRequest("GET", "https://example.com/pylon/apps", nil)
	rec := httptest.NewRecorder()

	appsDashboardHandler(rec, req)

	res := rec.Result()
	if res.StatusCode != http.StatusFound {
		t.Fatalf("expected StatusFound (302), got %d", res.StatusCode)
	}

	location := res.Header.Get("Location")
	if !strings.Contains(location, "/pylon/login") {
		t.Errorf("expected redirect to /pylon/login, got %q", location)
	}
}

func TestAppsDashboardHandler_Authenticated(t *testing.T) {
	setupTestConfig()

	req := createAuthenticatedRequest("GET", "https://example.com/pylon/apps", "alice@example.com")
	rec := httptest.NewRecorder()

	appsDashboardHandler(rec, req)

	res := rec.Result()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected StatusOK (200), got %d", res.StatusCode)
	}

	body := rec.Body.String()

	// Verify header contains user email
	if !strings.Contains(body, "alice@example.com") {
		t.Errorf("dashboard HTML does not contain user email")
	}

	// Verify Grid and List elements exist
	if !strings.Contains(body, `id="apps-grid"`) {
		t.Errorf("dashboard HTML missing #apps-grid container")
	}
	if !strings.Contains(body, `id="apps-list"`) {
		t.Errorf("dashboard HTML missing #apps-list container")
	}
	if !strings.Contains(body, `id="btn-grid"`) || !strings.Contains(body, `id="btn-list"`) {
		t.Errorf("dashboard HTML missing view toggle buttons")
	}

	// Verify Alice's apps are in the HTML
	if !strings.Contains(body, "grafana.example.com") ||
		!strings.Contains(body, "home-assistant.example.com") ||
		!strings.Contains(body, "vault.example.com") {
		t.Errorf("dashboard HTML missing Alice's authorized apps")
	}

	// Bob's exclusive app shouldn't be rendered for Alice
	if strings.Contains(body, "jellyfin.example.com") {
		t.Errorf("dashboard rendered jellyfin.example.com which Alice is not authorized for")
	}
}

func TestAppsAPIHandler(t *testing.T) {
	setupTestConfig()

	// Test unauthenticated
	reqUnauth := httptest.NewRequest("GET", "https://example.com/pylon/api/apps", nil)
	recUnauth := httptest.NewRecorder()
	appsAPIHandler(recUnauth, reqUnauth)
	if recUnauth.Result().StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized, got %d", recUnauth.Result().StatusCode)
	}

	// Test authenticated
	reqAuth := createAuthenticatedRequest("GET", "https://example.com/pylon/api/apps", "alice@example.com")
	recAuth := httptest.NewRecorder()
	appsAPIHandler(recAuth, reqAuth)
	if recAuth.Result().StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", recAuth.Result().StatusCode)
	}

	var resp AppListResponse
	if err := json.NewDecoder(recAuth.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode JSON response: %v", err)
	}

	if resp.User != "alice@example.com" {
		t.Errorf("expected User to be alice@example.com, got %q", resp.User)
	}
	if len(resp.Apps) != 3 || len(resp.Items) != 3 {
		t.Errorf("expected 3 apps and items, got %d apps, %d items", len(resp.Apps), len(resp.Items))
	}
}

func TestLogoutHandler(t *testing.T) {
	setupTestConfig()

	req := createAuthenticatedRequest("GET", "https://example.com/pylon/logout", "alice@example.com")
	rec := httptest.NewRecorder()

	logoutHandler(rec, req)

	res := rec.Result()
	if res.StatusCode != http.StatusFound {
		t.Fatalf("expected 302 Found, got %d", res.StatusCode)
	}
	if loc := res.Header.Get("Location"); !strings.HasPrefix(loc, "/pylon/login") {
		t.Errorf("expected redirect to /pylon/login, got %q", loc)
	}

	// Verify cookie removal
	cookies := res.Cookies()
	var pylonCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == "pylon" {
			pylonCookie = c
			break
		}
	}
	if pylonCookie == nil || pylonCookie.MaxAge > 0 || pylonCookie.Value != "" {
		t.Errorf("expected cleared pylon cookie, got %v", pylonCookie)
	}
}

func TestMainProxyHandlerRoutes(t *testing.T) {
	setupTestConfig()

	// Test /pylon/apps unauthenticated
	req := httptest.NewRequest("GET", "https://example.com/pylon/apps", nil)
	rec := httptest.NewRecorder()
	mainProxyHandler(rec, req)
	if rec.Result().StatusCode != http.StatusFound {
		t.Errorf("/pylon/apps expected 302 redirect to login, got %d", rec.Result().StatusCode)
	}

	// Test /pylon/logout
	reqLogout := httptest.NewRequest("GET", "https://example.com/pylon/logout", nil)
	recLogout := httptest.NewRecorder()
	mainProxyHandler(recLogout, reqLogout)
	if recLogout.Result().StatusCode != http.StatusFound {
		t.Errorf("/pylon/logout expected 302 redirect, got %d", recLogout.Result().StatusCode)
	}
}

func TestDedicatedAppsDomain(t *testing.T) {
	setupTestConfig()

	// Check isAllowedDomain includes apps.example.com and dashboard.example.com
	if !isAllowedDomain("apps.example.com") {
		t.Errorf("expected isAllowedDomain(apps.example.com) to be true")
	}
	if !isAllowedDomain("dashboard.example.com") {
		t.Errorf("expected isAllowedDomain(dashboard.example.com) to be true")
	}

	// Unauthenticated request to https://apps.example.com/ should redirect to login
	reqUnauth := httptest.NewRequest("GET", "https://apps.example.com/", nil)
	recUnauth := httptest.NewRecorder()
	mainProxyHandler(recUnauth, reqUnauth)
	if recUnauth.Result().StatusCode != http.StatusFound {
		t.Errorf("expected 302 redirect, got %d", recUnauth.Result().StatusCode)
	}

	// Authenticated request to https://apps.example.com/ directly renders apps portal
	reqAuth := createAuthenticatedRequest("GET", "https://apps.example.com/", "alice@example.com")
	recAuth := httptest.NewRecorder()
	mainProxyHandler(recAuth, reqAuth)
	if recAuth.Result().StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", recAuth.Result().StatusCode)
	}
	if !strings.Contains(recAuth.Body.String(), "Applications Portal") {
		t.Errorf("expected Apps Portal HTML on apps.example.com/")
	}
}

func TestGitHubRegisterHandler_MissingCode(t *testing.T) {
	setupTestConfig()

	req := httptest.NewRequest("GET", "https://example.com/pylon/github/register", nil)
	rec := httptest.NewRecorder()
	githubRegisterHandler(rec, req)

	if rec.Result().StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request for missing code, got %d", rec.Result().StatusCode)
	}
}

func createAuthenticatedClaimsRequest(method, urlStr string, claims *UserClaims) *http.Request {
	req := httptest.NewRequest(method, urlStr, nil)
	sessionStore := getSessionStore()
	session, _ := sessionStore.Get(req, "pylon")
	session.Values["email"] = claims.Email
	session.Values["user_id"] = claims.ID
	session.Values["first_name"] = claims.FirstName
	session.Values["last_name"] = claims.LastName
	session.Values["name"] = claims.Name
	session.Values["avatar_url"] = claims.AvatarURL
	session.Values["provider"] = claims.Provider

	rec := httptest.NewRecorder()
	_ = session.Save(req, rec)

	for _, cookie := range rec.Result().Cookies() {
		req.AddCookie(cookie)
	}

	return req
}

func TestClaimsHandler_Unauthenticated(t *testing.T) {
	setupTestConfig()

	req := httptest.NewRequest("GET", "https://example.com/pylon/claims", nil)
	rec := httptest.NewRecorder()
	mainProxyHandler(rec, req)

	res := rec.Result()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized, got %d", res.StatusCode)
	}

	var resp ClaimsResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode claims JSON: %v", err)
	}
	if resp.Authenticated {
		t.Errorf("expected Authenticated = false, got true")
	}
	if resp.Error != "unauthorized" {
		t.Errorf("expected Error = unauthorized, got %q", resp.Error)
	}
}

func TestClaimsHandler_Authenticated(t *testing.T) {
	setupTestConfig()

	claims := &UserClaims{
		ID:        "sub-12345",
		Email:     "alice@example.com",
		FirstName: "Alice",
		LastName:  "Smith",
		Name:      "Alice Smith",
		AvatarURL: "https://example.com/alice.png",
		Provider:  "google",
	}

	req := createAuthenticatedClaimsRequest("GET", "https://example.com/pylon/claims", claims)
	rec := httptest.NewRecorder()
	mainProxyHandler(rec, req)

	res := rec.Result()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", res.StatusCode)
	}

	var resp ClaimsResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode claims JSON: %v", err)
	}

	if !resp.Authenticated {
		t.Errorf("expected Authenticated = true")
	}
	if resp.ID != "sub-12345" {
		t.Errorf("expected ID = sub-12345, got %q", resp.ID)
	}
	if resp.Email != "alice@example.com" {
		t.Errorf("expected Email = alice@example.com, got %q", resp.Email)
	}
	if resp.FirstName != "Alice" {
		t.Errorf("expected FirstName = Alice, got %q", resp.FirstName)
	}
	if resp.LastName != "Smith" {
		t.Errorf("expected LastName = Smith, got %q", resp.LastName)
	}
	if resp.Name != "Alice Smith" {
		t.Errorf("expected Name = Alice Smith, got %q", resp.Name)
	}
	if resp.AvatarURL != "https://example.com/alice.png" {
		t.Errorf("expected AvatarURL = https://example.com/alice.png, got %q", resp.AvatarURL)
	}
	if resp.Provider != "google" {
		t.Errorf("expected Provider = google, got %q", resp.Provider)
	}
}

func TestClaimsHandler_LegacySession(t *testing.T) {
	setupTestConfig()

	// Legacy session only has email
	req := createAuthenticatedRequest("GET", "https://example.com/pylon/claims", "legacy@example.com")
	rec := httptest.NewRecorder()
	mainProxyHandler(rec, req)

	res := rec.Result()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", res.StatusCode)
	}

	var resp ClaimsResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode claims JSON: %v", err)
	}

	if !resp.Authenticated {
		t.Errorf("expected Authenticated = true")
	}
	if resp.Email != "legacy@example.com" {
		t.Errorf("expected Email = legacy@example.com, got %q", resp.Email)
	}
	if resp.ID != "legacy@example.com" {
		t.Errorf("expected fallback ID = legacy@example.com, got %q", resp.ID)
	}
}

func TestProxy_HeadersInjectedAndStripped(t *testing.T) {
	setupTestConfig()

	var receivedHeaders http.Header
	testBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("backend ok"))
	}))
	defer testBackend.Close()

	backendURL, err := url.Parse(testBackend.URL)
	if err != nil {
		t.Fatalf("failed to parse backend url: %v", err)
	}

	pd := &ProxyDetails{
		Internal:                   testBackend.URL,
		AllowedUsers:               []string{"alice@example.com"},
		UnauthenticatedRoutesRegex: regexp.MustCompile("^$"),
		ReverseProxy:               httputil.NewSingleHostReverseProxy(backendURL),
	}

	claims := &UserClaims{
		ID:        "sub-99999",
		Email:     "alice@example.com",
		FirstName: "Alice",
		LastName:  "Wonderland",
		Name:      "Alice Wonderland",
		AvatarURL: "https://example.com/avatar.png",
		Provider:  "github",
	}

	req := createAuthenticatedClaimsRequest("GET", "https://example.com/api/test", claims)
	// Try spoofing a header from client
	req.Header.Set("X-Pylon-User-Id", "spoofed-attacker-id")
	req.Header.Set("X-Pylon-Spoofed", "malicious-value")

	rec := httptest.NewRecorder()
	pd.proxy(rec, req)

	if rec.Result().StatusCode != http.StatusOK {
		t.Fatalf("expected proxy status 200, got %d", rec.Result().StatusCode)
	}

	if receivedHeaders.Get("X-Pylon-User-Id") != "sub-99999" {
		t.Errorf("expected X-Pylon-User-Id = sub-99999, got %q", receivedHeaders.Get("X-Pylon-User-Id"))
	}
	if receivedHeaders.Get("X-Pylon-User-Email") != "alice@example.com" {
		t.Errorf("expected X-Pylon-User-Email = alice@example.com, got %q", receivedHeaders.Get("X-Pylon-User-Email"))
	}
	if receivedHeaders.Get("X-Pylon-User-First-Name") != "Alice" {
		t.Errorf("expected X-Pylon-User-First-Name = Alice, got %q", receivedHeaders.Get("X-Pylon-User-First-Name"))
	}
	if receivedHeaders.Get("X-Pylon-User-Last-Name") != "Wonderland" {
		t.Errorf("expected X-Pylon-User-Last-Name = Wonderland, got %q", receivedHeaders.Get("X-Pylon-User-Last-Name"))
	}
	if receivedHeaders.Get("X-Pylon-User-Name") != "Alice Wonderland" {
		t.Errorf("expected X-Pylon-User-Name = Alice Wonderland, got %q", receivedHeaders.Get("X-Pylon-User-Name"))
	}
	if receivedHeaders.Get("X-Pylon-User-Avatar") != "https://example.com/avatar.png" {
		t.Errorf("expected X-Pylon-User-Avatar = https://example.com/avatar.png, got %q", receivedHeaders.Get("X-Pylon-User-Avatar"))
	}
	if receivedHeaders.Get("X-Pylon-User-Provider") != "github" {
		t.Errorf("expected X-Pylon-User-Provider = github, got %q", receivedHeaders.Get("X-Pylon-User-Provider"))
	}
	if receivedHeaders.Get("X-Forwarded-User") != "alice@example.com" {
		t.Errorf("expected X-Forwarded-User = alice@example.com, got %q", receivedHeaders.Get("X-Forwarded-User"))
	}
	if receivedHeaders.Get("X-Pylon-Spoofed") != "" {
		t.Errorf("expected spoofed header X-Pylon-Spoofed to be stripped, got %q", receivedHeaders.Get("X-Pylon-Spoofed"))
	}
}

func TestClaimsFromIdToken(t *testing.T) {
	// Construct test JWT payload
	payload := map[string]interface{}{
		"sub":            "test-sub-123",
		"email":          "jwtuser@example.com",
		"email_verified": true,
		"given_name":     "Bob",
		"family_name":    "Builder",
		"name":           "Bob Builder",
		"picture":        "https://example.com/bob.jpg",
	}
	payloadBytes, _ := json.Marshal(payload)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadBytes)
	fakeJWT := "eyJhbGciOiJIUzI1NiJ9." + payloadB64 + ".fakesignature"

	claims, err := claimsFromIdToken(fakeJWT)
	if err != nil {
		t.Fatalf("claimsFromIdToken failed: %v", err)
	}
	if claims.ID != "test-sub-123" {
		t.Errorf("expected ID = test-sub-123, got %q", claims.ID)
	}
	if claims.Email != "jwtuser@example.com" {
		t.Errorf("expected Email = jwtuser@example.com, got %q", claims.Email)
	}
	if claims.FirstName != "Bob" {
		t.Errorf("expected FirstName = Bob, got %q", claims.FirstName)
	}
	if claims.LastName != "Builder" {
		t.Errorf("expected LastName = Builder, got %q", claims.LastName)
	}
	if claims.Name != "Bob Builder" {
		t.Errorf("expected Name = Bob Builder, got %q", claims.Name)
	}
	if claims.AvatarURL != "https://example.com/bob.jpg" {
		t.Errorf("expected AvatarURL = https://example.com/bob.jpg, got %q", claims.AvatarURL)
	}
}

func TestNormalizeClaims(t *testing.T) {
	// Splitting full name when first and last are missing
	c1 := &UserClaims{
		Email: "user1@example.com",
		Name:  "Grace Hopper",
	}
	normalizeClaims(c1)
	if c1.FirstName != "Grace" || c1.LastName != "Hopper" {
		t.Errorf("expected Grace Hopper split into Grace and Hopper, got %q / %q", c1.FirstName, c1.LastName)
	}

	// Combining first and last when name is missing
	c2 := &UserClaims{
		Email:     "user2@example.com",
		FirstName: "Ada",
		LastName:  "Lovelace",
	}
	normalizeClaims(c2)
	if c2.Name != "Ada Lovelace" {
		t.Errorf("expected combined name Ada Lovelace, got %q", c2.Name)
	}

	// Fallback ID
	c3 := &UserClaims{
		Email: "user3@example.com",
	}
	normalizeClaims(c3)
	if c3.ID != "user3@example.com" {
		t.Errorf("expected ID fallback to email, got %q", c3.ID)
	}
}

func TestLoginGateway_SingleProviderBypassAndLogout(t *testing.T) {
	setupTestConfig()

	// Configure exactly one provider
	cfgMu.Lock()
	cfg.OAuthProviders = map[string]OAuthProvider{
		"google": {
			ID:       "google",
			Name:     "Google",
			Type:     "google",
			ClientID: "dummy-client-id",
		},
	}
	cfgMu.Unlock()

	// Normal visit with 1 provider -> should bypass and redirect to /pylon/auth/google
	reqNormal := httptest.NewRequest("GET", "https://example.com/pylon/login", nil)
	recNormal := httptest.NewRecorder()
	loginGatewayHandler(recNormal, reqNormal)
	if recNormal.Result().StatusCode != http.StatusFound {
		t.Fatalf("expected 302 redirect for single provider bypass, got %d", recNormal.Result().StatusCode)
	}
	if loc := recNormal.Header().Get("Location"); !strings.Contains(loc, "/pylon/auth/google") {
		t.Errorf("expected redirect to /pylon/auth/google, got %q", loc)
	}

	// Post-logout visit -> should NOT bypass, but show login page with sign out notice
	reqLogout := httptest.NewRequest("GET", "https://example.com/pylon/login?logged_out=true", nil)
	recLogout := httptest.NewRecorder()
	loginGatewayHandler(recLogout, reqLogout)
	if recLogout.Result().StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK after logout, got %d", recLogout.Result().StatusCode)
	}
	body := recLogout.Body.String()
	if !strings.Contains(body, "signed out") {
		t.Errorf("expected signed out notice in login page")
	}
	if !strings.Contains(body, "Login with Google") {
		t.Errorf("expected Login with Google button in login page")
	}
}

func TestOAuth2AuthHandler_PromptSelectAccount(t *testing.T) {
	setupTestConfig()

	cfgMu.Lock()
	cfg.OAuthProviders = map[string]OAuthProvider{
		"google": {
			ID:          "google",
			Name:        "Google",
			Type:        "google",
			ClientID:    "test-client-id",
			RedirectURL: "https://example.com/pylon/callback/google",
			Scopes:      []string{"email", "profile"},
		},
	}
	cfgMu.Unlock()

	req := httptest.NewRequest("GET", "https://example.com/pylon/auth/google", nil)
	rec := httptest.NewRecorder()
	oauth2authhandler(rec, req)

	res := rec.Result()
	if res.StatusCode != http.StatusTemporaryRedirect {
		t.Fatalf("expected 307 Temporary Redirect, got %d", res.StatusCode)
	}

	loc := res.Header.Get("Location")
	if !strings.Contains(loc, "prompt=select_account") {
		t.Errorf("expected prompt=select_account in Google OAuth URL, got %q", loc)
	}
}


