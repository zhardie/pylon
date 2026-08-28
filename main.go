package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/sessions"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type OAuthProvider struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Type         string   `json:"type"` // "google", "github", "microsoft", "gitlab", "oidc"
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	RedirectURL  string   `json:"redirect_url"`
	Scopes       []string `json:"scopes,omitempty"`
	AuthURL      string   `json:"auth_url,omitempty"`
	TokenURL     string   `json:"token_url,omitempty"`
	UserInfoURL  string   `json:"user_info_url,omitempty"`
}

type Config struct {
	TLDN               string                   `json:"tldn"`
	AllowedUsers       []string                 `json:"allowed_users"`
	AdminPasswordHash  string                   `json:"admin_password_hash"`
	InsecureSkipVerify bool                     `json:"insecure_skip_verify"`
	Proxies            []struct {
		Internal              string   `json:"internal"`
		External              string   `json:"external"`
		AllowedUsers          []string `json:"allowed_users"`
		UnauthenticatedRoutes []string `json:"unauthenticated_routes"`
	} `json:"proxies"`
	SessionKey         string                   `json:"session_key"`
	CookieExpire       time.Duration            `json:"cookie_expire"`
	
	// Deprecated: Kept for backwards compatibility
	OAuth              struct {
		Auth_URL      string `json:"auth_url"`
		Client_ID     string `json:"client_id"`
		Client_Secret string `json:"client_secret"`
		Redirect_URL  string `json:"redirect_url"`
	} `json:"oauth"`

	OAuthProviders     map[string]OAuthProvider `json:"oauth_providers"`
}

type ProxyServer struct {
	redirect_server *http.Server
	server          *http.Server
	wg              *sync.WaitGroup
}

type ProxyDetails struct {
	Internal                   string
	AllowedUsers               []string               `json:"allowed_users"`
	UnauthenticatedRoutesRegex *regexp.Regexp
	ReverseProxy               *httputil.ReverseProxy
}

type AppItem struct {
	Name        string `json:"name"`
	External    string `json:"external"`
	URL         string `json:"url"`
	Icon        string `json:"icon"`
	Description string `json:"description"`
}

type AppListResponse struct {
	User  string    `json:"user,omitempty"`
	Apps  []string  `json:"apps"`
	Items []AppItem `json:"items,omitempty"`
}

var (
	cfgMu     sync.RWMutex
	cfg       Config
	store     *sessions.CookieStore
	proxiesMu sync.RWMutex
	proxies   map[string]*ProxyDetails
	server    = &ProxyServer{wg: &sync.WaitGroup{}}
)

func main() {
	// CLI Password Hashing Helper
	hashPass := flag.String("hash", "", "Generate a bcrypt hash of the specified password and exit")
	flag.Parse()

	if *hashPass != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(*hashPass), bcrypt.DefaultCost)
		if err != nil {
			log.Fatalf("Failed to generate bcrypt hash: %v", err)
		}
		fmt.Println(string(hash))
		return
	}

	// Load Initial Config
	if err := loadConfig(); err != nil {
		log.Fatalf("Failed to load initial config: %v", err)
	}

	// Frontend handler and api endpoint (port :3001)
	frontend := http.NewServeMux()
	fs := http.FileServer(http.Dir("frontend"))
	frontend.Handle("/", fs)
	frontend.HandleFunc("/config", ConfigHandler)

	// Start Proxy Server (ports :http and :https)
	server.startServer()

	// Serve Frontend with Basic Auth Middleware
	log.Printf("Serving admin panel on port :3001...")
	log.Fatal(http.ListenAndServe(":3001", basicAuthMiddleware(frontend)))
}

func getConfigPath() string {
	configPath := "/config/config.json"
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		configPath = "config.json"
	}
	return configPath
}

func loadConfig() error {
	configPath := getConfigPath()
	var conf Config

	f, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			// Initialize with empty default config for onboarding
			conf = Config{
				SessionKey:     generateState(), // generate a random default key
				CookieExpire:   24 * time.Hour,
				OAuthProviders: make(map[string]OAuthProvider),
			}
		} else {
			return err
		}
	} else {
		err = json.Unmarshal(f, &conf)
		if err != nil {
			return err
		}
	}

	// Bind environment variables as overrides/fallbacks
	if os.Getenv("PYLON_TLDN") != "" {
		conf.TLDN = os.Getenv("PYLON_TLDN")
	}
	if os.Getenv("PYLON_SESSION_KEY") != "" {
		conf.SessionKey = os.Getenv("PYLON_SESSION_KEY")
	}
	if os.Getenv("PYLON_ADMIN_PASSWORD_HASH") != "" {
		conf.AdminPasswordHash = os.Getenv("PYLON_ADMIN_PASSWORD_HASH")
	} else if os.Getenv("PYLON_ADMIN_PASSWORD") != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(os.Getenv("PYLON_ADMIN_PASSWORD")), bcrypt.DefaultCost)
		if err == nil {
			conf.AdminPasswordHash = string(hash)
		}
	}

	// Initialize OAuthProviders map if empty
	if conf.OAuthProviders == nil {
		conf.OAuthProviders = make(map[string]OAuthProvider)
	}

	// Dynamic Legacy Migration: if old oauth configuration is present, translate to multi-provider
	if len(conf.OAuthProviders) == 0 && conf.OAuth.Client_ID != "" {
		conf.OAuthProviders["google"] = OAuthProvider{
			ID:           "google",
			Name:         "Google",
			Type:         "google",
			ClientID:     conf.OAuth.Client_ID,
			ClientSecret: conf.OAuth.Client_Secret,
			RedirectURL:  conf.OAuth.Redirect_URL,
			Scopes:       []string{"email", "profile"},
		}
	}

	// Environment variable Google OAuth binding fallback
	if os.Getenv("GOOGLE_CLIENT_ID") != "" && os.Getenv("GOOGLE_CLIENT_SECRET") != "" {
		conf.OAuthProviders["google"] = OAuthProvider{
			ID:           "google",
			Name:         "Google",
			Type:         "google",
			ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
			ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
			RedirectURL:  os.Getenv("GOOGLE_REDIRECT_URL"),
			Scopes:       []string{"email", "profile"},
		}
	}

	// Build proxies lookup map
	newProxies := make(map[string]*ProxyDetails)
	for _, p := range conf.Proxies {
		unauthenticatedRegex, err := regexp.Compile(strings.Join(p.UnauthenticatedRoutes, "|"))
		if err != nil {
			return fmt.Errorf("invalid unauthenticated routes regex: %v", err)
		}

		var rp *httputil.ReverseProxy
		isBuiltinTarget := p.Internal == "" || p.Internal == "builtin" || p.Internal == "dashboard" || p.Internal == "apps"

		if !isBuiltinTarget {
			u, err := url.Parse(p.Internal)
			if err != nil {
				return fmt.Errorf("invalid internal URL %q: %v", p.Internal, err)
			}

			rp = httputil.NewSingleHostReverseProxy(u)
			rp.Transport = &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: conf.InsecureSkipVerify,
				},
			}
		}

		newProxies[p.External] = &ProxyDetails{
			Internal:                   p.Internal,
			AllowedUsers:               p.AllowedUsers,
			UnauthenticatedRoutesRegex: unauthenticatedRegex,
			ReverseProxy:               rp,
		}
	}

	cfgMu.Lock()
	cfg = conf
	store = sessions.NewCookieStore([]byte(conf.SessionKey))
	cfgMu.Unlock()

	proxiesMu.Lock()
	proxies = newProxies
	proxiesMu.Unlock()

	return nil
}

func getSessionStore() *sessions.CookieStore {
	cfgMu.RLock()
	defer cfgMu.RUnlock()
	return store
}

func isOnboardingMode() bool {
	cfgMu.RLock()
	defer cfgMu.RUnlock()
	return cfg.AdminPasswordHash == "" || len(cfg.OAuthProviders) == 0
}

func isAllowedDomain(host string) bool {
	cfgMu.RLock()
	providersList := cfg.OAuthProviders
	tldn := cfg.TLDN
	cfgMu.RUnlock()

	if tldn != "" && (host == tldn || host == "apps."+tldn || host == "dashboard."+tldn) {
		return true
	}

	// Direct check for OAuth redirects
	for _, prov := range providersList {
		u, err := url.Parse(prov.RedirectURL)
		if err == nil && u.Host == host {
			return true
		}
	}

	proxiesMu.RLock()
	defer proxiesMu.RUnlock()
	_, exists := proxies[host]
	return exists
}

func lookupProxy(host string) (*ProxyDetails, bool) {
	proxiesMu.RLock()
	defer proxiesMu.RUnlock()
	pd, found := proxies[host]
	return pd, found
}

func basicAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Bypass authentication if in Onboarding Mode
		if isOnboardingMode() {
			next.ServeHTTP(w, r)
			return
		}

		// Bypass CORS preflight requests
		if r.Method == "OPTIONS" {
			next.ServeHTTP(w, r)
			return
		}

		user, pass, ok := r.BasicAuth()

		cfgMu.RLock()
		hash := cfg.AdminPasswordHash
		cfgMu.RUnlock()

		if !ok || user != "admin" || bcrypt.CompareHashAndPassword([]byte(hash), []byte(pass)) != nil {
			w.Header().Set("WWW-Authenticate", `Basic realm="Pylon Admin Dashboard"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (ps *ProxyServer) startServer() {
	proxy_mux := http.NewServeMux()

	// Catch-all main handler for dynamic proxy routing and OAuth endpoints
	proxy_mux.HandleFunc("/", mainProxyHandler)

	// Create the autocert.Manager with dynamic HostPolicy
	certManager := autocert.Manager{
		Cache:  autocert.DirCache("/certs"),
		Prompt: autocert.AcceptTOS,
		HostPolicy: func(ctx context.Context, host string) error {
			if isAllowedDomain(host) {
				return nil
			}
			return fmt.Errorf("acme/autocert: host %q not configured", host)
		},
	}

	// Create the TLS proxy server
	ps.server = &http.Server{
		ReadTimeout:  120 * time.Second,
		WriteTimeout: 240 * time.Second,
		IdleTimeout:  240 * time.Second,
		Addr:         ":https",
		Handler:      proxy_mux,
		TLSConfig:    certManager.TLSConfig(),
	}

	h := certManager.HTTPHandler(nil)
	ps.redirect_server = &http.Server{
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
		Addr:         ":http",
		Handler:      h,
	}

	ps.wg.Add(2)

	go func() {
		// Serve HTTP, which redirects to HTTPS
		defer ps.wg.Done()
		err := ps.redirect_server.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			log.Print("Error starting redirect server:", err)
		}
	}()

	go func() {
		// Serve HTTPS
		defer ps.wg.Done()
		err := ps.server.ListenAndServeTLS("", "")
		if err != nil && err != http.ErrServerClosed {
			log.Print("Error starting proxy server:", err)
		}
	}()

	fmt.Println("Serving proxy routes...")
}

func mainProxyHandler(w http.ResponseWriter, r *http.Request) {
	// Handle CORS preflight options
	if r.Method == "OPTIONS" {
		enableCORS(&w, r)
		w.WriteHeader(http.StatusOK)
		return
	}

	// 1. Check if login gateway path
	if r.URL.Path == "/pylon/login" {
		loginGatewayHandler(w, r)
		return
	}

	// 2. Check if specific provider auth request
	if strings.HasPrefix(r.URL.Path, "/pylon/auth/") {
		oauth2authhandler(w, r)
		return
	}

	// 3. Check if specific provider callback request
	if strings.HasPrefix(r.URL.Path, "/pylon/callback/") {
		oauth2callbackhandler(w, r)
		return
	}

	// Check if GitHub App Manifest callback
	if r.URL.Path == "/pylon/github/register" {
		githubRegisterHandler(w, r)
		return
	}

	// 4. Apps Dashboard & Portal Routes
	if r.URL.Path == "/pylon" || r.URL.Path == "/pylon/" || r.URL.Path == "/pylon/apps" || r.URL.Path == "/pylon/dashboard" {
		appsDashboardHandler(w, r)
		return
	}

	if r.URL.Path == "/pylon/api/apps" {
		appsAPIHandler(w, r)
		return
	}

	if r.URL.Path == "/pylon/logout" {
		logoutHandler(w, r)
		return
	}

	// 5. Dedicated Portal Host or Resolve Proxy Destination
	subdomain := getSubdomain(r)
	cfgMu.RLock()
	tldn := cfg.TLDN
	cfgMu.RUnlock()

	isPortalHost := subdomain == "apps" || subdomain == "dashboard" || (tldn != "" && r.Host == tldn)

	pd, found := lookupProxy(r.Host)
	if !found {
		if isPortalHost && (r.URL.Path == "/" || r.URL.Path == "") {
			appsDashboardHandler(w, r)
			return
		}
		if r.URL.Path == "/" || r.URL.Path == "" {
			http.Redirect(w, r, "/pylon/apps", http.StatusFound)
			return
		}
		http.Error(w, "Proxy Host Not Found", http.StatusNotFound)
		return
	}

	pd.proxy(w, r)
}

func loginGatewayHandler(w http.ResponseWriter, r *http.Request) {
	referer := r.URL.Query().Get("referer")

	cfgMu.RLock()
	providersList := cfg.OAuthProviders
	cfgMu.RUnlock()

	// If no provider is configured, return error
	if len(providersList) == 0 {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		http.Error(w, "<h3>Error: No OAuth Providers configured. Please set up Pylon admin.</h3>", http.StatusInternalServerError)
		return
	}

	// If exactly one provider is configured, bypass the gate and redirect directly
	if len(providersList) == 1 {
		for key := range providersList {
			http.Redirect(w, r, fmt.Sprintf("/pylon/auth/%s?referer=%s", key, referer), http.StatusFound)
			return
		}
	}

	// Render a beautifully designed glassmorphic login gate
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)

	var buttonsHTML strings.Builder
	for key, p := range providersList {
		displayName := p.Name
		if displayName == "" {
			displayName = strings.Title(key)
		}
		
		brandColor := "#4f46e5" // Default indigo
		switch key {
		case "google":
			brandColor = "#ea4335" // Red
		case "github":
			brandColor = "#24292e" // Charcoal
		case "microsoft":
			brandColor = "#00a4ef" // Cyan/Blue
		case "gitlab":
			brandColor = "#fc6d26" // Orange
		}

		buttonsHTML.WriteString(fmt.Sprintf(`
			<a href="/pylon/auth/%s?referer=%s" class="login-btn" style="background-color: %s;">
				<span>Login with %s</span>
			</a>
		`, key, referer, brandColor, displayName))
	}

	html := fmt.Sprintf(`
	<!DOCTYPE html>
	<html lang="en">
	<head>
		<meta charset="UTF-8">
		<meta name="viewport" content="width=device-width, initial-scale=1.0">
		<title>Pylon Login Gateway</title>
		<style>
			body {
				font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
				background: linear-gradient(135deg, #0f172a 0%%, #1e293b 100%%);
				color: #f8fafc;
				display: flex;
				justify-content: center;
				align-items: center;
				min-height: 100vh;
				margin: 0;
			}
			.container {
				background: rgba(30, 41, 59, 0.7);
				backdrop-filter: blur(16px);
				-webkit-backdrop-filter: blur(16px);
				border: 1px solid rgba(255, 255, 255, 0.1);
				border-radius: 24px;
				padding: 40px;
				width: 100%%;
				max-width: 400px;
				box-shadow: 0 20px 25px -5px rgb(0 0 0 / 0.5), 0 8px 10px -6px rgb(0 0 0 / 0.5);
				text-align: center;
			}
			h1 {
				font-size: 28px;
				font-weight: 700;
				margin-bottom: 8px;
				background: linear-gradient(to right, #38bdf8, #818cf8);
				-webkit-background-clip: text;
				-webkit-text-fill-color: transparent;
			}
			p {
				color: #94a3b8;
				font-size: 14px;
				margin-bottom: 32px;
			}
			.login-btn {
				display: flex;
				justify-content: center;
				align-items: center;
				padding: 14px 24px;
				margin-bottom: 14px;
				border-radius: 12px;
				text-decoration: none;
				color: white;
				font-weight: 600;
				font-size: 15px;
				transition: transform 0.2s, filter 0.2s;
				box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.1);
			}
			.login-btn:hover {
				transform: translateY(-2px);
				filter: brightness(1.1);
			}
			.login-btn:active {
				transform: translateY(0);
			}
		</style>
	</head>
	<body>
		<div class="container">
			<h1>Pylon Gateway</h1>
			<p>Select a provider below to authenticate and access this resource.</p>
			<div style="display: flex; flex-direction: column;">
				%s
			</div>
		</div>
	</body>
	</html>
	`, buttonsHTML.String())

	w.Write([]byte(html))
}

func oauth2authhandler(w http.ResponseWriter, r *http.Request) {
	referer := r.URL.Query().Get("referer")

	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 4 {
		http.Error(w, "Invalid Auth Request URL", http.StatusBadRequest)
		return
	}
	providerKey := parts[3]

	cfgMu.RLock()
	prov, found := cfg.OAuthProviders[providerKey]
	tldn := cfg.TLDN
	cfgMu.RUnlock()

	if !found {
		http.Error(w, fmt.Sprintf("OAuth Provider %q not configured", providerKey), http.StatusBadRequest)
		return
	}

	state := generateState()
	if state == "" {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Set short-lived state verification cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "pylon_oauth_state",
		Value:    state,
		Domain:   tldn,
		Path:     "/",
		MaxAge:   300,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	// Set short-lived referer cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "pylon_oauth_referer",
		Value:    referer,
		Domain:   tldn,
		Path:     "/",
		MaxAge:   300,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	endpoint := getProviderEndpoint(prov.Type, prov.AuthURL, prov.TokenURL)
	googleAuth := &oauth2.Config{
		ClientID:     prov.ClientID,
		ClientSecret: prov.ClientSecret,
		RedirectURL:  prov.RedirectURL,
		Scopes:       prov.Scopes,
		Endpoint:     endpoint,
	}

	url := googleAuth.AuthCodeURL(state)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func getProviderEndpoint(provType string, customAuth, customToken string) oauth2.Endpoint {
	switch provType {
	case "google":
		return google.Endpoint
	case "github":
		return oauth2.Endpoint{
			AuthURL:  "https://github.com/login/oauth/authorize",
			TokenURL: "https://github.com/login/oauth/access_token",
		}
	case "microsoft":
		return oauth2.Endpoint{
			AuthURL:  "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
			TokenURL: "https://login.microsoftonline.com/common/oauth2/v2.0/token",
		}
	case "gitlab":
		return oauth2.Endpoint{
			AuthURL:  "https://gitlab.com/oauth/authorize",
			TokenURL: "https://gitlab.com/oauth/token",
		}
	default:
		return oauth2.Endpoint{
			AuthURL:  customAuth,
			TokenURL: customToken,
		}
	}
}

func oauth2callbackhandler(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 4 {
		http.Error(w, "Invalid Callback Request URL", http.StatusBadRequest)
		return
	}
	providerKey := parts[3]

	cfgMu.RLock()
	prov, found := cfg.OAuthProviders[providerKey]
	tldn := cfg.TLDN
	cfgMu.RUnlock()

	if !found {
		http.Error(w, fmt.Sprintf("OAuth Provider %q not configured", providerKey), http.StatusBadRequest)
		return
	}

	// Verify state parameter (CSRF protection)
	stateParam := r.URL.Query().Get("state")
	stateCookie, err := r.Cookie("pylon_oauth_state")
	if err != nil || stateCookie.Value == "" || stateCookie.Value != stateParam {
		http.Error(w, "CSRF State Verification Failed", http.StatusBadRequest)
		log.Printf("OAuth callback state mismatch: param=%s, cookie=%v", stateParam, stateCookie)
		return
	}

	// Retrieve referer cookie
	var referer string
	refererCookie, err := r.Cookie("pylon_oauth_referer")
	if err == nil {
		referer = refererCookie.Value
	}

	// Clear OAuth cookies
	http.SetCookie(w, &http.Cookie{
		Name:     "pylon_oauth_state",
		Value:    "",
		Domain:   tldn,
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "pylon_oauth_referer",
		Value:    "",
		Domain:   tldn,
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})

	endpoint := getProviderEndpoint(prov.Type, prov.AuthURL, prov.TokenURL)
	googleAuth := &oauth2.Config{
		ClientID:     prov.ClientID,
		ClientSecret: prov.ClientSecret,
		RedirectURL:  prov.RedirectURL,
		Scopes:       prov.Scopes,
		Endpoint:     endpoint,
	}

	tkn, err := googleAuth.Exchange(context.TODO(), r.URL.Query().Get("code"))
	if err != nil {
		log.Print("Error exchanging token:", err)
		http.Error(w, "Failed to exchange authorization token", http.StatusInternalServerError)
		return
	}

	if !tkn.Valid() {
		log.Print("Invalid token received")
		http.Error(w, "Invalid Token", http.StatusBadRequest)
		return
	}

	// Fetch user email based on provider rules
	email, err := getEmailFromProvider(context.TODO(), prov.Type, tkn, prov.UserInfoURL)
	if err != nil {
		log.Print("Failed to retrieve email:", err)
		http.Error(w, "Failed to retrieve verified email", http.StatusUnauthorized)
		return
	}

	sessionStore := getSessionStore()
	session, _ := sessionStore.Get(r, "pylon")
	session.Values["email"] = email
	session.Options = &sessions.Options{
		Path:     "/",
		Domain:   tldn,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}
	err = session.Save(r, w)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if referer == "" || referer == "/pylon/login" || referer == "/pylon" || referer == "/pylon/apps" {
		targetHost := "apps." + tldn
		if tldn == "" {
			targetHost = r.Host
		}
		http.Redirect(w, r, fmt.Sprintf("https://%s/", targetHost), http.StatusFound)
		return
	}

	if !isValidRedirect(referer, tldn) {
		http.Error(w, "Forbidden Redirect Target", http.StatusForbidden)
		log.Printf("Blocked open redirect attempt to: %s", referer)
		return
	}

	http.Redirect(w, r, "https://"+referer, http.StatusFound)
}

func getEmailFromProvider(ctx context.Context, provType string, token *oauth2.Token, userInfoURL string) (string, error) {
	switch provType {
	case "google":
		idToken, ok := token.Extra("id_token").(string)
		if !ok {
			return "", errors.New("missing id_token in Google OAuth response")
		}
		return emailFromIdToken(idToken)
	case "github":
		req, err := http.NewRequestWithContext(ctx, "GET", "https://api.github.com/user/emails", nil)
		if err != nil {
			return "", err
		}
		req.Header.Set("Authorization", "Bearer "+token.AccessToken)
		req.Header.Set("Accept", "application/vnd.github.v3+json")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return "", fmt.Errorf("github api returned status %d", resp.StatusCode)
		}

		var emails []struct {
			Email    string `json:"email"`
			Primary  bool   `json:"primary"`
			Verified bool   `json:"verified"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&emails); err != nil {
			return "", err
		}
		for _, e := range emails {
			if e.Primary && e.Verified {
				return e.Email, nil
			}
		}
		if len(emails) > 0 {
			return emails[0].Email, nil // Fallback to first address if primary is missing
		}
		return "", errors.New("no emails found for Github user")

	case "microsoft":
		idToken, ok := token.Extra("id_token").(string)
		if ok {
			email, err := emailFromIdToken(idToken)
			if err == nil && email != "" {
				return email, nil
			}
		}

		// Fallback to Graph API Query
		req, err := http.NewRequestWithContext(ctx, "GET", "https://graph.microsoft.com/v1.0/me", nil)
		if err != nil {
			return "", err
		}
		req.Header.Set("Authorization", "Bearer "+token.AccessToken)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return "", fmt.Errorf("microsoft graph API returned status %d", resp.StatusCode)
		}

		var info struct {
			Mail              string `json:"mail"`
			UserPrincipalName string `json:"userPrincipalName"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
			return "", err
		}
		if info.Mail != "" {
			return info.Mail, nil
		}
		return info.UserPrincipalName, nil

	case "gitlab":
		req, err := http.NewRequestWithContext(ctx, "GET", "https://gitlab.com/api/v4/user", nil)
		if err != nil {
			return "", err
		}
		req.Header.Set("Authorization", "Bearer "+token.AccessToken)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return "", fmt.Errorf("gitlab api returned status %d", resp.StatusCode)
		}

		var info struct {
			Email string `json:"email"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
			return "", err
		}
		return info.Email, nil

	default: // oidc or custom
		if userInfoURL == "" {
			idToken, ok := token.Extra("id_token").(string)
			if ok {
				return emailFromIdToken(idToken)
			}
			return "", errors.New("missing userInfoURL for custom OIDC provider")
		}

		req, err := http.NewRequestWithContext(ctx, "GET", userInfoURL, nil)
		if err != nil {
			return "", err
		}
		req.Header.Set("Authorization", "Bearer "+token.AccessToken)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return "", fmt.Errorf("custom userInfo endpoint returned status %d", resp.StatusCode)
		}

		var info struct {
			Email string `json:"email"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
			return "", err
		}
		return info.Email, nil
	}
}

func (pd *ProxyDetails) proxy(w http.ResponseWriter, r *http.Request) {
	sessionStore := getSessionStore()
	session, _ := sessionStore.Get(r, "pylon")
	emailVal := session.Values["email"]

	// Dedicated Apps / Dashboard Host or Builtin Handler
	subdomain := getSubdomain(r)
	isAppsHost := strings.HasPrefix(subdomain, "dashboard") || strings.HasPrefix(subdomain, "apps")
	isBuiltinTarget := pd.ReverseProxy == nil || pd.Internal == "builtin" || pd.Internal == "dashboard" || pd.Internal == "apps" || pd.Internal == ""

	if isAppsHost || isBuiltinTarget {
		appsDashboardHandler(w, r)
		return
	}

	// App API Handler
	isPylonApi := strings.HasPrefix(r.URL.Path, "/8ef55d02bd174c29177d5618bfb3a2f3")
	if isPylonApi {
		log.Printf("matches pylon api path; handling pylon request")
		resource := strings.TrimPrefix(r.URL.Path, "/8ef55d02bd174c29177d5618bfb3a2f3/")
		if resource == "allowedApps" {
			if emailVal == nil {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			AppListHandler(w, r, emailVal.(string))
		}
		return
	}

	// Authenticate and Authorize
	if !pd.isUnauthenticatedRoute(r.URL.Path) {
		if emailVal == nil {
			referer := fmt.Sprintf("%s%s", r.Host, r.URL.Path)
			// Redirect to the unified login gateway
			http.Redirect(w, r, fmt.Sprintf("/pylon/login?referer=%s", referer), http.StatusFound)
			return
		}

		email := emailVal.(string)
		if !pd.userInAllowedList(email) {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, `<h3>User %s is unauthorized to access this resource.</h3>
							<button onclick="window.location.href = '/pylon/login';">Login</button>`, email)
			log.Printf("user %s not allowed for target host: %s", email, r.Host)
			return
		}
	}

	// Forward request via the pre-instantiated ReverseProxy
	remoteAddr := strings.Split(r.RemoteAddr, ":")[0]

    r.Header.Set("X-Forwarded-Host", r.Host)
	if r.TLS != nil {
		r.Header.Set("X-Forwarded-Ssl", "on")
		r.Header.Set("X-Forwarded-Proto", "https")
		r.Header.Set("X-Forwarded-Port", "443")
	} else {
		r.Header.Set("X-Forwarded-Proto", "http")
		r.Header.Set("X-Forwarded-Port", "80")
	}

	r.Header.Set("X-Forwarded-For", remoteAddr)

	pd.ReverseProxy.ServeHTTP(w, r)
}

func enableCORS(w *http.ResponseWriter, r *http.Request) {
	(*w).Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
	(*w).Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
	(*w).Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
	(*w).Header().Set("Access-Control-Allow-Credentials", "true")
}

func ConfigHandler(w http.ResponseWriter, r *http.Request) {
	enableCORS(&w, r)

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method == "GET" {
		cfgMu.RLock()
		onboarded := cfg.AdminPasswordHash != "" && len(cfg.OAuthProviders) > 0
		
		// Return config along with onboarded virtual status field
		respMap := map[string]interface{}{
			"tldn":                 cfg.TLDN,
			"allowed_users":        cfg.AllowedUsers,
			"admin_password_hash":  cfg.AdminPasswordHash,
			"insecure_skip_verify": cfg.InsecureSkipVerify,
			"proxies":              cfg.Proxies,
			"session_key":          cfg.SessionKey,
			"cookie_expire":        cfg.CookieExpire,
			"oauth_providers":      cfg.OAuthProviders,
			"onboarded":            onboarded,
		}
		payload, err := json.MarshalIndent(respMap, "", "    ")
		cfgMu.RUnlock()
		
		if err != nil {
			log.Printf("Error marshalling config: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(payload)
		return
	}

	if r.Method == "POST" {
		decoder := json.NewDecoder(r.Body)
		var new_config Config
		err := decoder.Decode(&new_config)
		if err != nil {
			log.Print("Error decoding config json:", err)
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}

		cfgMu.RLock()
		currentHash := cfg.AdminPasswordHash
		cfgMu.RUnlock()

		// Hash password if plain-text was sent, otherwise preserve existing
		if new_config.AdminPasswordHash != "" {
			isBcrypt := strings.HasPrefix(new_config.AdminPasswordHash, "$2a$") ||
				strings.HasPrefix(new_config.AdminPasswordHash, "$2b$") ||
				strings.HasPrefix(new_config.AdminPasswordHash, "$2y$")
			
			if !isBcrypt {
				hash, err := bcrypt.GenerateFromPassword([]byte(new_config.AdminPasswordHash), bcrypt.DefaultCost)
				if err != nil {
					log.Print("Error generating password hash:", err)
					http.Error(w, "Internal Server Error", http.StatusInternalServerError)
					return
				}
				new_config.AdminPasswordHash = string(hash)
			}
		} else {
			new_config.AdminPasswordHash = currentHash
		}

		pretty, err := json.MarshalIndent(new_config, "", "    ")
		if err != nil {
			log.Print("Error encoding configuration:", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		configPath := getConfigPath()
		err = os.WriteFile(configPath, pretty, 0600)
		if err != nil {
			log.Print("Error writing to config file:", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		// Reload configuration dynamically
		if err := loadConfig(); err != nil {
			log.Print("Failed to reload newly written config:", err)
			http.Error(w, "Failed to apply configuration internally", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("okay"))
		return
	}
}

func getUserAllowedApps(userEmail string) ([]string, []AppItem) {
	cfgMu.RLock()
	proxiesList := cfg.Proxies
	tldn := cfg.TLDN
	cfgMu.RUnlock()

	var appStrings []string
	var appItems []AppItem

	for _, proxy := range proxiesList {
		ext := strings.TrimSpace(proxy.External)
		if ext == "" {
			continue
		}
		// Exclude dedicated dashboard/portal routes from the app card list
		if (tldn != "" && (ext == "apps."+tldn || ext == "dashboard."+tldn || ext == tldn)) ||
			proxy.Internal == "builtin" || proxy.Internal == "dashboard" || proxy.Internal == "apps" {
			continue
		}
		// Proxies with empty allowed_users are accessible to any authenticated user
		if len(proxy.AllowedUsers) == 0 || sliceContains(proxy.AllowedUsers, userEmail) {
			appStrings = append(appStrings, proxy.External)
			appItems = append(appItems, formatAppItem(proxy.External))
		}
	}

	return appStrings, appItems
}

func formatAppItem(external string) AppItem {
	cleanExternal := strings.TrimSpace(external)
	cleanExternal = strings.TrimPrefix(cleanExternal, "http://")
	cleanExternal = strings.TrimPrefix(cleanExternal, "https://")
	cleanExternal = strings.TrimRight(cleanExternal, "/")

	appUrl := "https://" + cleanExternal
	if strings.HasPrefix(external, "http://") || strings.HasPrefix(external, "https://") {
		appUrl = external
	}

	hostPart := cleanExternal
	if idx := strings.Index(hostPart, "/"); idx != -1 {
		hostPart = hostPart[:idx]
	}
	if idx := strings.Index(hostPart, ":"); idx != -1 {
		hostPart = hostPart[:idx]
	}

	// Extract subdomain or first component
	parts := strings.Split(hostPart, ".")
	rawName := parts[0]
	if rawName == "www" && len(parts) > 1 {
		rawName = parts[1]
	}

	// Determine icon and friendly category
	lower := strings.ToLower(rawName)
	icon := "apps"
	category := "Application"

	switch {
	case strings.Contains(lower, "grafana") || strings.Contains(lower, "metric"):
		icon = "insights"
		category = "Monitoring"
	case strings.Contains(lower, "prom") || strings.Contains(lower, "victoriametrics"):
		icon = "show_chart"
		category = "Monitoring"
	case strings.Contains(lower, "plex") || strings.Contains(lower, "jellyfin") || strings.Contains(lower, "emby"):
		icon = "movie"
		category = "Media"
	case strings.Contains(lower, "home") || strings.Contains(lower, "hass") || strings.Contains(lower, "assistant"):
		icon = "home"
		category = "Smart Home"
	case strings.Contains(lower, "vault") || strings.Contains(lower, "bitwarden") || strings.Contains(lower, "pass"):
		icon = "lock"
		category = "Security"
	case strings.Contains(lower, "nextcloud") || strings.Contains(lower, "owncloud") || strings.Contains(lower, "drive"):
		icon = "cloud"
		category = "Cloud Storage"
	case strings.Contains(lower, "git") || strings.Contains(lower, "gitea") || strings.Contains(lower, "code"):
		icon = "code"
		category = "Development"
	case strings.Contains(lower, "portainer") || strings.Contains(lower, "docker") || strings.Contains(lower, "k8s"):
		icon = "layers"
		category = "Infrastructure"
	case strings.Contains(lower, "wiki") || strings.Contains(lower, "book") || strings.Contains(lower, "doc"):
		icon = "menu_book"
		category = "Documentation"
	case strings.Contains(lower, "sonarr") || strings.Contains(lower, "radarr") || strings.Contains(lower, "prowlarr") || strings.Contains(lower, "lidarr"):
		icon = "download"
		category = "Automation"
	case strings.Contains(lower, "torrent") || strings.Contains(lower, "nzb") || strings.Contains(lower, "aria"):
		icon = "cloud_download"
		category = "Downloads"
	case strings.Contains(lower, "uptime") || strings.Contains(lower, "kuma") || strings.Contains(lower, "status"):
		icon = "query_stats"
		category = "Status"
	case strings.Contains(lower, "pihole") || strings.Contains(lower, "adguard") || strings.Contains(lower, "dns"):
		icon = "shield"
		category = "Network & DNS"
	case strings.Contains(lower, "nas") || strings.Contains(lower, "synology") || strings.Contains(lower, "unraid") || strings.Contains(lower, "truenas"):
		icon = "storage"
		category = "Storage"
	case strings.Contains(lower, "mail") || strings.Contains(lower, "roundcube") || strings.Contains(lower, "inbox"):
		icon = "email"
		category = "Mail"
	case strings.Contains(lower, "chat") || strings.Contains(lower, "matrix") || strings.Contains(lower, "discord") || strings.Contains(lower, "slack"):
		icon = "chat"
		category = "Chat"
	case strings.Contains(lower, "photo") || strings.Contains(lower, "immich"):
		icon = "photo_library"
		category = "Photos"
	case strings.Contains(lower, "music") || strings.Contains(lower, "navidrome") || strings.Contains(lower, "audio"):
		icon = "music_note"
		category = "Audio"
	case strings.Contains(lower, "admin") || strings.Contains(lower, "pylon"):
		icon = "tune"
		category = "Administration"
	default:
		icon = "apps"
		category = "Service"
	}

	// Format human-readable title
	words := strings.FieldsFunc(rawName, func(r rune) bool {
		return r == '-' || r == '_' || r == '.'
	})
	for i, w := range words {
		if len(w) > 0 {
			words[i] = strings.ToUpper(w[:1]) + w[1:]
		}
	}
	displayName := strings.Join(words, " ")
	if displayName == "" {
		displayName = cleanExternal
	}

	return AppItem{
		Name:        displayName,
		External:    cleanExternal,
		URL:         appUrl,
		Icon:        icon,
		Description: category,
	}
}

func AppListHandler(w http.ResponseWriter, r *http.Request, user string) {
	enableCORS(&w, r)

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method == "GET" {
		appStrings, appItems := getUserAllowedApps(user)
		allowedApps := AppListResponse{
			User:  user,
			Apps:  appStrings,
			Items: appItems,
		}

		w.Header().Set("Content-Type", "application/json")
		jsonResponse, err := json.Marshal(allowedApps)
		if err != nil {
			log.Printf("could not marshal AppListHandler response: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		w.Write(jsonResponse)
	}
}

func appsAPIHandler(w http.ResponseWriter, r *http.Request) {
	enableCORS(&w, r)

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	sessionStore := getSessionStore()
	session, _ := sessionStore.Get(r, "pylon")
	emailVal := session.Values["email"]
	if emailVal == nil || emailVal.(string) == "" {
		http.Error(w, `{"error":"Unauthorized"}`, http.StatusUnauthorized)
		return
	}

	email := emailVal.(string)
	appStrings, appItems := getUserAllowedApps(email)

	resp := AppListResponse{
		User:  email,
		Apps:  appStrings,
		Items: appItems,
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	cfgMu.RLock()
	tldn := cfg.TLDN
	cfgMu.RUnlock()

	http.SetCookie(w, &http.Cookie{
		Name:     "pylon",
		Value:    "",
		Domain:   tldn,
		Path:     "/",
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	http.Redirect(w, r, "/pylon/login", http.StatusFound)
}

func appsDashboardHandler(w http.ResponseWriter, r *http.Request) {
	sessionStore := getSessionStore()
	session, _ := sessionStore.Get(r, "pylon")
	emailVal := session.Values["email"]

	if emailVal == nil || emailVal.(string) == "" {
		referer := fmt.Sprintf("%s%s", r.Host, r.URL.Path)
		http.Redirect(w, r, fmt.Sprintf("/pylon/login?referer=%s", referer), http.StatusFound)
		return
	}

	email := emailVal.(string)
	_, appItems := getUserAllowedApps(email)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	renderAppsDashboard(w, email, appItems)
}

func renderAppsDashboard(w io.Writer, email string, apps []AppItem) {
	var gridHTML strings.Builder
	var listHTML strings.Builder

	escapedEmail := html.EscapeString(email)

	for _, app := range apps {
		escapedName := html.EscapeString(app.Name)
		escapedExt := html.EscapeString(app.External)
		escapedURL := html.EscapeString(app.URL)
		escapedIcon := html.EscapeString(app.Icon)
		escapedDesc := html.EscapeString(app.Description)

		// Grid Card
		gridHTML.WriteString(fmt.Sprintf(`
			<a href="%s" class="app-card" data-name="%s" data-domain="%s" data-category="%s">
				<div class="card-top">
					<div class="app-icon-wrap">
						<span class="material-icons">%s</span>
					</div>
					<span class="launch-icon material-icons">open_in_new</span>
				</div>
				<div class="card-info">
					<h3 class="app-title">%s</h3>
					<span class="category-badge">%s</span>
					<div class="app-domain">%s</div>
				</div>
			</a>
		`, escapedURL, escapedName, escapedExt, escapedDesc, escapedIcon, escapedName, escapedDesc, escapedExt))

		// List Row
		listHTML.WriteString(fmt.Sprintf(`
			<div class="app-list-item" data-name="%s" data-domain="%s" data-category="%s" onclick="window.location.href='%s'">
				<div class="list-item-left">
					<div class="app-icon-wrap small">
						<span class="material-icons">%s</span>
					</div>
					<div class="list-item-info">
						<span class="list-item-title">%s</span>
						<span class="category-badge small">%s</span>
					</div>
				</div>
				<div class="list-item-center">
					<span class="list-item-domain">%s</span>
				</div>
				<div class="list-item-right">
					<span class="badge-authorized">Authorized</span>
					<a href="%s" class="btn-launch" onclick="event.stopPropagation();">
						<span>Open</span>
						<span class="material-icons">arrow_forward</span>
					</a>
				</div>
			</div>
		`, escapedName, escapedExt, escapedDesc, escapedURL, escapedIcon, escapedName, escapedDesc, escapedExt, escapedURL))
	}

	appsCount := len(apps)

	fullHTML := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>Pylon Apps Portal</title>
	<link rel="stylesheet" href="https://fonts.googleapis.com/icon?family=Material+Icons">
	<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap">
	<style>
		:root {
			--bg-main: #090d16;
			--bg-gradient: linear-gradient(135deg, #090d16 0%%, #0f172a 50%%, #1e293b 100%%);
			--text-main: #f8fafc;
			--text-muted: #94a3b8;
			--card-bg: rgba(30, 41, 59, 0.45);
			--card-hover: rgba(30, 41, 59, 0.7);
			--card-border: rgba(255, 255, 255, 0.08);
			--card-border-hover: rgba(56, 189, 248, 0.4);
			--glass-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.4), 0 8px 10px -6px rgba(0, 0, 0, 0.4);
			--input-bg: #0f172a;
			--input-border: #334155;
			--accent: #38bdf8;
			--accent-gradient: linear-gradient(to right, #38bdf8, #818cf8);
			--badge-bg: rgba(56, 189, 248, 0.12);
			--badge-text: #38bdf8;
			--badge-auth-bg: rgba(16, 185, 129, 0.12);
			--badge-auth-text: #34d399;
			--btn-active-bg: rgba(255, 255, 255, 0.1);
			--btn-inactive-bg: transparent;
			--header-bg: rgba(15, 23, 42, 0.75);
			--divider: rgba(255, 255, 255, 0.06);
		}

		body.light-mode {
			--bg-main: #f8fafc;
			--bg-gradient: linear-gradient(135deg, #f1f5f9 0%%, #f8fafc 50%%, #e2e8f0 100%%);
			--text-main: #0f172a;
			--text-muted: #64748b;
			--card-bg: rgba(255, 255, 255, 0.85);
			--card-hover: #ffffff;
			--card-border: rgba(0, 0, 0, 0.08);
			--card-border-hover: #38bdf8;
			--glass-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.06), 0 8px 10px -6px rgba(0, 0, 0, 0.04);
			--input-bg: #ffffff;
			--input-border: #cbd5e1;
			--accent: #0284c7;
			--accent-gradient: linear-gradient(to right, #0284c7, #6366f1);
			--badge-bg: rgba(2, 132, 199, 0.1);
			--badge-text: #0284c7;
			--badge-auth-bg: rgba(16, 185, 129, 0.1);
			--badge-auth-text: #059669;
			--btn-active-bg: #ffffff;
			--btn-inactive-bg: transparent;
			--header-bg: rgba(255, 255, 255, 0.85);
			--divider: rgba(0, 0, 0, 0.06);
		}

		* {
			box-sizing: border-box;
			margin: 0;
			padding: 0;
		}

		body {
			font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
			background: var(--bg-gradient);
			background-attachment: fixed;
			color: var(--text-main);
			min-height: 100vh;
			display: flex;
			flex-direction: column;
			transition: background 0.3s, color 0.3s;
		}

		/* Header */
		.app-header {
			position: sticky;
			top: 0;
			z-index: 100;
			background: var(--header-bg);
			backdrop-filter: blur(16px);
			-webkit-backdrop-filter: blur(16px);
			border-bottom: 1px solid var(--card-border);
			padding: 14px 32px;
			display: flex;
			justify-content: space-between;
			align-items: center;
			transition: background 0.3s, border-color 0.3s;
		}

		.header-left {
			display: flex;
			align-items: center;
			gap: 12px;
		}

		.logo {
			display: flex;
			align-items: center;
			gap: 8px;
			text-decoration: none;
		}

		.logo-icon {
			font-size: 26px;
			background: var(--accent-gradient);
			-webkit-background-clip: text;
			-webkit-text-fill-color: transparent;
		}

		.logo-text {
			font-size: 22px;
			font-weight: 700;
			letter-spacing: -0.5px;
			background: var(--accent-gradient);
			-webkit-background-clip: text;
			-webkit-text-fill-color: transparent;
		}

		.portal-badge {
			font-size: 11px;
			font-weight: 600;
			text-transform: uppercase;
			letter-spacing: 0.8px;
			background: var(--badge-bg);
			color: var(--badge-text);
			padding: 3px 8px;
			border-radius: 6px;
			margin-left: 4px;
		}

		.header-right {
			display: flex;
			align-items: center;
			gap: 12px;
		}

		.user-chip {
			display: flex;
			align-items: center;
			gap: 8px;
			background: var(--card-bg);
			border: 1px solid var(--card-border);
			padding: 6px 14px;
			border-radius: 20px;
			font-size: 13px;
			font-weight: 500;
			color: var(--text-main);
		}

		.user-chip .user-icon {
			font-size: 18px;
			color: var(--accent);
		}

		.icon-btn {
			background: var(--card-bg);
			border: 1px solid var(--card-border);
			color: var(--text-main);
			width: 38px;
			height: 38px;
			border-radius: 10px;
			display: flex;
			align-items: center;
			justify-content: center;
			cursor: pointer;
			transition: all 0.2s;
		}

		.icon-btn:hover {
			border-color: var(--accent);
			transform: translateY(-1px);
		}

		.icon-btn .material-icons {
			font-size: 20px;
		}

		.logout-btn {
			display: flex;
			align-items: center;
			gap: 6px;
			background: rgba(239, 68, 68, 0.1);
			border: 1px solid rgba(239, 68, 68, 0.25);
			color: #f87171;
			text-decoration: none;
			padding: 8px 14px;
			border-radius: 10px;
			font-size: 13px;
			font-weight: 600;
			transition: all 0.2s;
		}

		.logout-btn:hover {
			background: rgba(239, 68, 68, 0.2);
			border-color: #ef4444;
			color: #ffffff;
			transform: translateY(-1px);
		}

		.logout-btn .material-icons {
			font-size: 17px;
		}

		/* Main Content */
		.main-wrap {
			max-width: 1280px;
			width: 100%%;
			margin: 0 auto;
			padding: 40px 32px;
			flex: 1;
		}

		.hero-section {
			margin-bottom: 32px;
		}

		.hero-section h1 {
			font-size: 28px;
			font-weight: 700;
			letter-spacing: -0.5px;
			margin-bottom: 6px;
			background: var(--accent-gradient);
			-webkit-background-clip: text;
			-webkit-text-fill-color: transparent;
		}

		.hero-section p {
			font-size: 14px;
			color: var(--text-muted);
		}

		/* Controls Bar */
		.controls-bar {
			display: flex;
			justify-content: space-between;
			align-items: center;
			gap: 16px;
			margin-bottom: 28px;
			flex-wrap: wrap;
		}

		.search-box {
			position: relative;
			flex: 1;
			max-width: 420px;
			min-width: 260px;
		}

		.search-box .search-icon {
			position: absolute;
			left: 14px;
			top: 50%%;
			transform: translateY(-50%%);
			font-size: 20px;
			color: var(--text-muted);
			pointer-events: none;
		}

		.search-box input {
			width: 100%%;
			background: var(--input-bg);
			border: 1px solid var(--input-border);
			border-radius: 12px;
			padding: 11px 40px 11px 42px;
			color: var(--text-main);
			font-size: 14px;
			outline: none;
			transition: all 0.2s;
		}

		.search-box input:focus {
			border-color: var(--accent);
			box-shadow: 0 0 0 3px rgba(56, 189, 248, 0.15);
		}

		.search-clear-btn {
			position: absolute;
			right: 12px;
			top: 50%%;
			transform: translateY(-50%%);
			background: transparent;
			border: none;
			color: var(--text-muted);
			cursor: pointer;
			display: flex;
			align-items: center;
			justify-content: center;
			padding: 2px;
			border-radius: 50%%;
		}

		.search-clear-btn:hover {
			color: var(--text-main);
		}

		.controls-right {
			display: flex;
			align-items: center;
			gap: 14px;
		}

		.count-badge {
			font-size: 13px;
			font-weight: 500;
			color: var(--text-muted);
			background: var(--card-bg);
			border: 1px solid var(--card-border);
			padding: 8px 14px;
			border-radius: 10px;
		}

		.view-toggle {
			display: flex;
			background: var(--input-bg);
			border: 1px solid var(--input-border);
			border-radius: 12px;
			padding: 3px;
			gap: 2px;
		}

		.view-btn {
			background: var(--btn-inactive-bg);
			border: none;
			color: var(--text-muted);
			padding: 7px 14px;
			border-radius: 9px;
			font-size: 13px;
			font-weight: 600;
			display: flex;
			align-items: center;
			gap: 6px;
			cursor: pointer;
			transition: all 0.2s;
		}

		.view-btn:hover {
			color: var(--text-main);
		}

		.view-btn.active {
			background: var(--btn-active-bg);
			color: var(--accent);
			box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
		}

		.view-btn .material-icons {
			font-size: 18px;
		}

		/* Grid View */
		.apps-grid {
			display: grid;
			grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
			gap: 22px;
		}

		.app-card {
			background: var(--card-bg);
			backdrop-filter: blur(16px);
			-webkit-backdrop-filter: blur(16px);
			border: 1px solid var(--card-border);
			border-radius: 18px;
			padding: 24px;
			text-decoration: none;
			color: inherit;
			display: flex;
			flex-direction: column;
			box-shadow: var(--glass-shadow);
			transition: transform 0.2s ease, border-color 0.2s ease, box-shadow 0.2s ease, background 0.2s ease;
			position: relative;
			overflow: hidden;
		}

		.app-card:hover {
			transform: translateY(-4px);
			border-color: var(--card-border-hover);
			background: var(--card-hover);
			box-shadow: 0 16px 30px -5px rgba(0, 0, 0, 0.3), 0 0 20px -5px rgba(56, 189, 248, 0.2);
		}

		.card-top {
			display: flex;
			justify-content: space-between;
			align-items: flex-start;
			margin-bottom: 18px;
		}

		.app-icon-wrap {
			width: 48px;
			height: 48px;
			border-radius: 14px;
			background: linear-gradient(135deg, rgba(56, 189, 248, 0.18), rgba(129, 140, 248, 0.18));
			border: 1px solid rgba(56, 189, 248, 0.3);
			display: flex;
			align-items: center;
			justify-content: center;
			color: var(--accent);
		}

		.app-icon-wrap .material-icons {
			font-size: 26px;
		}

		.app-icon-wrap.small {
			width: 40px;
			height: 40px;
			border-radius: 11px;
		}

		.app-icon-wrap.small .material-icons {
			font-size: 22px;
		}

		.launch-icon {
			font-size: 20px;
			color: var(--text-muted);
			opacity: 0.6;
			transition: all 0.2s;
		}

		.app-card:hover .launch-icon {
			color: var(--accent);
			opacity: 1;
			transform: translate(2px, -2px);
		}

		.card-info {
			display: flex;
			flex-direction: column;
			gap: 6px;
		}

		.app-title {
			font-size: 17px;
			font-weight: 700;
			color: var(--text-main);
			white-space: nowrap;
			overflow: hidden;
			text-overflow: ellipsis;
		}

		.category-badge {
			align-self: flex-start;
			font-size: 11px;
			font-weight: 600;
			background: var(--badge-bg);
			color: var(--badge-text);
			padding: 2px 8px;
			border-radius: 5px;
		}

		.category-badge.small {
			font-size: 10px;
			padding: 1px 6px;
		}

		.app-domain {
			font-size: 12.5px;
			color: var(--text-muted);
			white-space: nowrap;
			overflow: hidden;
			text-overflow: ellipsis;
			margin-top: 4px;
		}

		/* List View */
		.apps-list {
			display: flex;
			flex-direction: column;
			gap: 12px;
		}

		.app-list-item {
			background: var(--card-bg);
			backdrop-filter: blur(16px);
			-webkit-backdrop-filter: blur(16px);
			border: 1px solid var(--card-border);
			border-radius: 14px;
			padding: 14px 20px;
			display: flex;
			align-items: center;
			justify-content: space-between;
			cursor: pointer;
			box-shadow: var(--glass-shadow);
			transition: transform 0.2s ease, border-color 0.2s ease, background 0.2s ease;
		}

		.app-list-item:hover {
			transform: translateX(4px);
			border-color: var(--card-border-hover);
			background: var(--card-hover);
		}

		.list-item-left {
			display: flex;
			align-items: center;
			gap: 14px;
			min-width: 240px;
		}

		.list-item-info {
			display: flex;
			flex-direction: column;
			gap: 3px;
		}

		.list-item-title {
			font-size: 15px;
			font-weight: 600;
			color: var(--text-main);
		}

		.list-item-center {
			flex: 1;
			padding: 0 20px;
		}

		.list-item-domain {
			font-size: 13px;
			font-family: monospace;
			color: var(--text-muted);
		}

		.list-item-right {
			display: flex;
			align-items: center;
			gap: 12px;
		}

		.badge-authorized {
			font-size: 11px;
			font-weight: 600;
			background: var(--badge-auth-bg);
			color: var(--badge-auth-text);
			padding: 4px 10px;
			border-radius: 20px;
		}

		.btn-launch {
			background: var(--accent);
			color: #090d16;
			text-decoration: none;
			padding: 6px 14px;
			border-radius: 8px;
			font-size: 12.5px;
			font-weight: 700;
			display: flex;
			align-items: center;
			gap: 4px;
			transition: filter 0.2s, transform 0.2s;
		}

		.btn-launch:hover {
			filter: brightness(1.15);
			transform: translateY(-1px);
		}

		.btn-launch .material-icons {
			font-size: 15px;
		}

		/* Empty State */
		.empty-state {
			text-align: center;
			padding: 60px 20px;
			background: var(--card-bg);
			border: 1px solid var(--card-border);
			border-radius: 20px;
			box-shadow: var(--glass-shadow);
		}

		.empty-icon {
			font-size: 48px;
			color: var(--text-muted);
			margin-bottom: 12px;
		}

		.empty-state h3 {
			font-size: 18px;
			margin-bottom: 6px;
			color: var(--text-main);
		}

		.empty-state p {
			font-size: 14px;
			color: var(--text-muted);
		}

		@media (max-width: 768px) {
			.app-header {
				padding: 12px 18px;
			}
			.main-wrap {
				padding: 24px 18px;
			}
			.user-chip {
				display: none;
			}
			.controls-bar {
				flex-direction: column;
				align-items: stretch;
			}
			.search-box {
				max-width: 100%%;
			}
			.controls-right {
				justify-content: space-between;
			}
			.list-item-center {
				display: none;
			}
		}
	</style>
</head>
<body>
	<header class="app-header">
		<div class="header-left">
			<a href="/pylon/apps" class="logo">
				<span class="material-icons logo-icon">bolt</span>
				<span class="logo-text">pylon</span>
			</a>
			<span class="portal-badge">Apps</span>
		</div>
		<div class="header-right">
			<div class="user-chip">
				<span class="material-icons user-icon">account_circle</span>
				<span>%s</span>
			</div>
			<button id="btn-theme" class="icon-btn" title="Toggle Light/Dark Mode">
				<span class="material-icons" id="theme-icon">light_mode</span>
			</button>
			<a href="/pylon/logout" class="logout-btn" title="Sign Out">
				<span class="material-icons">logout</span>
				<span>Logout</span>
			</a>
		</div>
	</header>

	<main class="main-wrap">
		<div class="hero-section">
			<h1>Applications Portal</h1>
			<p>Click any application below to launch and access your authorized services.</p>
		</div>

		<div class="controls-bar">
			<div class="search-box">
				<span class="material-icons search-icon">search</span>
				<input type="text" id="search-input" placeholder="Search applications by name or domain..." autocomplete="off">
				<button id="search-clear" class="search-clear-btn" style="display:none;" title="Clear search">
					<span class="material-icons">close</span>
				</button>
			</div>

			<div class="controls-right">
				<div class="count-badge">
					<span id="visible-count">%d</span> apps available
				</div>
				<div class="view-toggle">
					<button id="btn-grid" class="view-btn active" title="Grid View">
						<span class="material-icons">grid_view</span>
						<span>Grid</span>
					</button>
					<button id="btn-list" class="view-btn" title="List View">
						<span class="material-icons">view_list</span>
						<span>List</span>
					</button>
				</div>
			</div>
		</div>

		<div id="apps-grid" class="apps-grid">
			%s
		</div>

		<div id="apps-list" class="apps-list" style="display: none;">
			%s
		</div>

		<div id="empty-state" class="empty-state" style="display: none;">
			<span class="material-icons empty-icon">search_off</span>
			<h3 id="empty-title">No applications found</h3>
			<p id="empty-subtitle">Try adjusting your search criteria.</p>
		</div>
	</main>

	<script>
		(function() {
			const totalApps = %d;
			const searchInput = document.getElementById('search-input');
			const searchClear = document.getElementById('search-clear');
			const visibleCount = document.getElementById('visible-count');
			const btnGrid = document.getElementById('btn-grid');
			const btnList = document.getElementById('btn-list');
			const gridView = document.getElementById('apps-grid');
			const listView = document.getElementById('apps-list');
			const emptyState = document.getElementById('empty-state');
			const emptyTitle = document.getElementById('empty-title');
			const emptySubtitle = document.getElementById('empty-subtitle');
			const btnTheme = document.getElementById('btn-theme');
			const themeIcon = document.getElementById('theme-icon');

			// 1. Theme Management
			function setTheme(theme) {
				if (theme === 'light') {
					document.body.classList.add('light-mode');
					themeIcon.textContent = 'dark_mode';
					localStorage.setItem('pylon_apps_theme', 'light');
				} else {
					document.body.classList.remove('light-mode');
					themeIcon.textContent = 'light_mode';
					localStorage.setItem('pylon_apps_theme', 'dark');
				}
			}

			const savedTheme = localStorage.getItem('pylon_apps_theme') || (window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark');
			setTheme(savedTheme);

			btnTheme.addEventListener('click', function() {
				const isLight = document.body.classList.contains('light-mode');
				setTheme(isLight ? 'dark' : 'light');
			});

			// 2. View Mode (Grid vs List)
			function setViewMode(mode) {
				if (mode === 'list') {
					btnList.classList.add('active');
					btnGrid.classList.remove('active');
					listView.style.display = 'flex';
					gridView.style.display = 'none';
					localStorage.setItem('pylon_apps_view', 'list');
				} else {
					btnGrid.classList.add('active');
					btnList.classList.remove('active');
					gridView.style.display = 'grid';
					listView.style.display = 'none';
					localStorage.setItem('pylon_apps_view', 'grid');
				}
			}

			const savedView = localStorage.getItem('pylon_apps_view') || 'grid';
			setViewMode(savedView);

			btnGrid.addEventListener('click', function() { setViewMode('grid'); });
			btnList.addEventListener('click', function() { setViewMode('list'); });

			// 3. Search & Filter
			function filterApps() {
				const query = searchInput.value.trim().toLowerCase();
				if (query) {
					searchClear.style.display = 'flex';
				} else {
					searchClear.style.display = 'none';
				}

				const cards = gridView.querySelectorAll('.app-card');
				const listItems = listView.querySelectorAll('.app-list-item');
				let count = 0;

				cards.forEach(function(card, idx) {
					const name = (card.getAttribute('data-name') || '').toLowerCase();
					const domain = (card.getAttribute('data-domain') || '').toLowerCase();
					const category = (card.getAttribute('data-category') || '').toLowerCase();

					const matches = !query || name.includes(query) || domain.includes(query) || category.includes(query);

					card.style.display = matches ? 'flex' : 'none';
					if (listItems[idx]) {
						listItems[idx].style.display = matches ? 'flex' : 'none';
					}

					if (matches) count++;
				});

				visibleCount.textContent = count;

				if (count === 0) {
					if (totalApps === 0) {
						emptyTitle.textContent = 'No Applications Available';
						emptySubtitle.textContent = 'You do not currently have access to any proxied applications. Contact your administrator.';
					} else {
						emptyTitle.textContent = 'No matching applications';
						emptySubtitle.textContent = 'No applications match "' + query + '".';
					}
					emptyState.style.display = 'block';
					gridView.style.display = 'none';
					listView.style.display = 'none';
				} else {
					emptyState.style.display = 'none';
					const currentMode = btnList.classList.contains('active') ? 'list' : 'grid';
					setViewMode(currentMode);
				}
			}

			searchInput.addEventListener('input', filterApps);

			searchClear.addEventListener('click', function() {
				searchInput.value = '';
				filterApps();
				searchInput.focus();
			});

			if (totalApps === 0) {
				filterApps();
			}
		})();
	</script>
</body>
</html>`, escapedEmail, appsCount, gridHTML.String(), listHTML.String(), appsCount)

	_, _ = w.Write([]byte(fullHTML))
}

func sliceContains(s []string, str string) bool {
	for _, v := range s {
		if v == str {
			return true
		}
	}
	return false
}

func getSubdomain(r *http.Request) string {
	host := r.Host
	host = strings.TrimSpace(host)
	hostParts := strings.Split(host, ".")

	lengthOfHostParts := len(hostParts)

	if lengthOfHostParts == 4 {
		return hostParts[1]
	}

	if lengthOfHostParts == 3 {
		subdomain := hostParts[0]
		if subdomain == "www" {
			return ""
		}
		return subdomain
	}

	return ""
}

func generateState() string {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		return ""
	}
	return hex.EncodeToString(b)
}

func isValidRedirect(referer string, tldn string) bool {
	u, err := url.Parse("https://" + referer)
	if err != nil {
		return false
	}
	host := u.Hostname()

	if host == tldn || strings.HasSuffix(host, "."+tldn) {
		return true
	}

	return isAllowedDomain(host)
}

func emailFromIdToken(idToken string) (string, error) {
	jwt := strings.Split(idToken, ".")
	if len(jwt) < 2 {
		return "", errors.New("invalid jwt format")
	}
	jwtData := strings.TrimSuffix(jwt[1], "=")
	b, err := base64.RawURLEncoding.DecodeString(jwtData)
	if err != nil {
		return "", err
	}

	var email struct {
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
	}
	err = json.Unmarshal(b, &email)
	if err != nil {
		return "", err
	}
	if email.Email == "" {
		return "", errors.New("missing email in token payload")
	}
	if !email.EmailVerified {
		return "", fmt.Errorf("email %s not verified", email.Email)
	}
	return email.Email, nil
}

func (pd *ProxyDetails) userInAllowedList(email string) bool {
	if len(pd.AllowedUsers) == 0 {
		return true
	}
	for _, b := range pd.AllowedUsers {
		if b == email {
			return true
		}
	}
	return false
}

func (pd *ProxyDetails) isUnauthenticatedRoute(path string) bool {
	if len(pd.UnauthenticatedRoutesRegex.String()) > 0 && pd.UnauthenticatedRoutesRegex.MatchString(path) {
		log.Printf("Bypass Pylon due to regex match: %v for path: %s for internal host: %s", pd.UnauthenticatedRoutesRegex.String(), path, pd.Internal)
		return true
	}
	return false
}

func githubRegisterHandler(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "Missing registration code", http.StatusBadRequest)
		return
	}

	// Exchange code for app credentials
	apiURL := fmt.Sprintf("https://api.github.com/app-manifests/%s/conversions", code)
	req, err := http.NewRequest("POST", apiURL, nil)
	if err != nil {
		log.Print("Error creating conversion request:", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Print("Error doing conversion request:", err)
		http.Error(w, "Failed to register App with GitHub", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		log.Printf("GitHub conversion API returned status %d", resp.StatusCode)
		http.Error(w, "GitHub App registration failed", http.StatusBadRequest)
		return
	}

	var appDetails struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
		Name         string `json:"name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&appDetails); err != nil {
		log.Print("Error decoding app details:", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Add to config
	cfgMu.Lock()
	tldn := cfg.TLDN
	// If oauth_providers doesn't exist, make it
	if cfg.OAuthProviders == nil {
		cfg.OAuthProviders = make(map[string]OAuthProvider)
	}
	cfg.OAuthProviders["github"] = OAuthProvider{
		ID:           "github",
		Name:         "GitHub App",
		Type:         "github",
		ClientID:     appDetails.ClientID,
		ClientSecret: appDetails.ClientSecret,
		RedirectURL:  fmt.Sprintf("https://%s/pylon/callback/github", tldn),
		Scopes:       []string{"read:user", "user:email"},
	}
	cfgCopy := cfg
	cfgMu.Unlock()

	// Write config to disk
	pretty, err := json.MarshalIndent(cfgCopy, "", "    ")
	if err == nil {
		_ = os.WriteFile(getConfigPath(), pretty, 0600)
	}

	// Reload config in memory
	_ = loadConfig()

	// Redirect to user portal
	targetHost := "apps." + tldn
	if tldn == "" {
		targetHost = r.Host
	}
	http.Redirect(w, r, fmt.Sprintf("https://%s/", targetHost), http.StatusFound)
}


