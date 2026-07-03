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

type AppListResponse struct {
	Apps []string `json:"apps"`
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

		u, err := url.Parse(p.Internal)
		if err != nil {
			return fmt.Errorf("invalid internal URL %q: %v", p.Internal, err)
		}

		rp := httputil.NewSingleHostReverseProxy(u)
		rp.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: conf.InsecureSkipVerify,
			},
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
	cfgMu.RUnlock()

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

	// 4. Resolve Proxy Destination
	pd, found := lookupProxy(r.Host)
	if !found {
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

	if referer == "" {
		fmt.Fprintf(w, "Authenticated as %s", email)
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

	// Dashboard Subdomain Handler
	subdomain := getSubdomain(r)
	isDashboard := strings.HasPrefix(subdomain, "dashboard")

	isDashboardRedirect := false
	isDashboardRedirectParam := r.URL.Query().Get("isDashboardRedirect")
	if strings.HasPrefix(isDashboardRedirectParam, "true") {
		isDashboardRedirect = true
	}

	if isDashboard && !isDashboardRedirect {
		log.Print("Dashboard request; rendering dashboard")
		http.Redirect(w, r, "?isDashboardRedirect=true/#/dashboard", http.StatusFound)
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
	} else {
		r.Header.Set("X-Forwarded-Proto", "http")
	}

	u, _ := url.Parse(pd.Internal)
	r.Header.Set("X-Forwarded-Port", u.Port())
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

func AppListHandler(w http.ResponseWriter, r *http.Request, user string) {
	enableCORS(&w, r)

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method == "GET" {
		cfgMu.RLock()
		proxiesList := cfg.Proxies
		cfgMu.RUnlock()

		allowedApps := new(AppListResponse)

		for _, proxy := range proxiesList {
			if sliceContains(proxy.AllowedUsers, user) {
				allowedApps.Apps = append(allowedApps.Apps, proxy.External)
			}
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

	// Redirect back to admin console
	http.Redirect(w, r, "http://"+tldn+":3001/#/", http.StatusFound)
}


