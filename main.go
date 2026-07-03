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

type ProxyDetails struct {
	Internal                   string
	AllowedUsers               []string               `json:"allowed_users"`
	UnauthenticatedRoutesRegex *regexp.Regexp
	ReverseProxy               *httputil.ReverseProxy
}

type Config struct {
	TLDN               string        `json:"tldn"`
	AllowedUsers       []string      `json:"allowed_users"`
	AdminPasswordHash  string        `json:"admin_password_hash"`
	InsecureSkipVerify bool          `json:"insecure_skip_verify"`
	Proxies            []struct {
		Internal              string   `json:"internal"`
		External              string   `json:"external"`
		AllowedUsers          []string `json:"allowed_users"`
		UnauthenticatedRoutes []string `json:"unauthenticated_routes"`
	} `json:"proxies"`
	SessionKey   string        `json:"session_key"`
	CookieExpire time.Duration `json:"cookie_expire"`
	OAuth        struct {
		Auth_URL      string `json:"auth_url"`
		Client_ID     string `json:"client_id"`
		Client_Secret string `json:"client_secret"`
		Redirect_URL  string `json:"redirect_url"`
	} `json:"oauth"`
}

type ProxyServer struct {
	redirect_server *http.Server
	server          *http.Server
	wg              *sync.WaitGroup
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
	f, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}

	var conf Config
	err = json.Unmarshal(f, &conf)
	if err != nil {
		return err
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

		// Configure and reuse reverse proxy and transport
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

func isAllowedDomain(host string) bool {
	cfgMu.RLock()
	authURLStr := cfg.OAuth.Auth_URL
	redirectURLStr := cfg.OAuth.Redirect_URL
	cfgMu.RUnlock()

	authURL, err := url.Parse(authURLStr)
	if err == nil && authURL.Host == host {
		return true
	}
	redirectURL, err := url.Parse(redirectURLStr)
	if err == nil && redirectURL.Host == host {
		return true
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
		// Bypass CORS preflight requests
		if r.Method == "OPTIONS" {
			next.ServeHTTP(w, r)
			return
		}

		user, pass, ok := r.BasicAuth()

		cfgMu.RLock()
		hash := cfg.AdminPasswordHash
		cfgMu.RUnlock()

		if hash == "" {
			log.Printf("Admin access blocked: admin_password_hash is empty in config.json")
			w.Header().Set("WWW-Authenticate", `Basic realm="Pylon Admin Dashboard"`)
			http.Error(w, "Unauthorized (Admin password hash not configured)", http.StatusUnauthorized)
			return
		}

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

func matchesOAuthURL(r *http.Request, oauthURLStr string) bool {
	u, err := url.Parse(oauthURLStr)
	if err != nil {
		return false
	}
	return r.Host == u.Host && r.URL.Path == u.Path
}

func mainProxyHandler(w http.ResponseWriter, r *http.Request) {
	// Handle CORS preflight options
	if r.Method == "OPTIONS" {
		enableCORS(&w, r)
		w.WriteHeader(http.StatusOK)
		return
	}

	cfgMu.RLock()
	authURLStr := cfg.OAuth.Auth_URL
	redirectURLStr := cfg.OAuth.Redirect_URL
	cfgMu.RUnlock()

	// 1. Check if OAuth Auth URL
	if matchesOAuthURL(r, authURLStr) {
		oauth2authhandler(w, r)
		return
	}

	// 2. Check if OAuth Redirect URL
	if matchesOAuthURL(r, redirectURLStr) {
		oauth2callbackhandler(w, r)
		return
	}

	// 3. Resolve Proxy Destination
	pd, found := lookupProxy(r.Host)
	if !found {
		http.Error(w, "Proxy Host Not Found", http.StatusNotFound)
		return
	}

	pd.proxy(w, r)
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
			cfgMu.RLock()
			authURLStr := cfg.OAuth.Auth_URL
			cfgMu.RUnlock()
			http.Redirect(w, r, fmt.Sprintf("%s?referer=%s", authURLStr, referer), http.StatusFound)
			return
		}

		email := emailVal.(string)
		if !pd.userInAllowedList(email) {
			cfgMu.RLock()
			authURLStr := cfg.OAuth.Auth_URL
			cfgMu.RUnlock()

			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, `<h3>User %s is unauthorized to access this resource.</h3>
							<button onclick="window.location.href = '%s';">Login</button>`, email, authURLStr)
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
		payload, err := json.MarshalIndent(cfg, "", "    ")
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

		// Preserve admin password hash if not supplied in client payload
		if new_config.AdminPasswordHash == "" {
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

		// Reload configuration dynamically in memory
		if err := loadConfig(); err != nil {
			log.Print("Failed to reload newly written config:", err)
			http.Error(w, "Failed to apply config changes internally", http.StatusInternalServerError)
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

func oauth2authhandler(w http.ResponseWriter, r *http.Request) {
	referer := r.URL.Query().Get("referer")

	state := generateState()
	if state == "" {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Set short-lived state verification cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "pylon_oauth_state",
		Value:    state,
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
		Path:     "/",
		MaxAge:   300,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	cfgMu.RLock()
	clientID := cfg.OAuth.Client_ID
	clientSecret := cfg.OAuth.Client_Secret
	redirectURL := cfg.OAuth.Redirect_URL
	cfgMu.RUnlock()

	googleAuth := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Scopes: []string{
			"email",
			"profile",
		},
		Endpoint: google.Endpoint,
	}

	url := googleAuth.AuthCodeURL(state)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
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

func oauth2callbackhandler(w http.ResponseWriter, r *http.Request) {
	// Verify state parameter (CSRF protection)
	stateParam := r.URL.Query().Get("state")
	stateCookie, err := r.Cookie("pylon_oauth_state")
	if err != nil || stateCookie.Value == "" || stateCookie.Value != stateParam {
		http.Error(w, "CSRF State Verification Failed", http.StatusBadRequest)
		log.Printf("OAuth callback state mismatch: param=%s, cookie=%v", stateParam, stateCookie)
		return
	}

	// Retrieve and parse referer cookie
	var referer string
	refererCookie, err := r.Cookie("pylon_oauth_referer")
	if err == nil {
		referer = refererCookie.Value
	}

	// Clear OAuth handshake cookies
	http.SetCookie(w, &http.Cookie{
		Name:     "pylon_oauth_state",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "pylon_oauth_referer",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})

	cfgMu.RLock()
	clientID := cfg.OAuth.Client_ID
	clientSecret := cfg.OAuth.Client_Secret
	redirectURL := cfg.OAuth.Redirect_URL
	tldn := cfg.TLDN
	cfgMu.RUnlock()

	googleAuth := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Scopes: []string{
			"email",
			"profile",
		},
		Endpoint: google.Endpoint,
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

	email, err := emailFromIdToken(tkn.Extra("id_token").(string))
	if err != nil {
		log.Print(err)
		http.Error(w, "Failed to decode verified email", http.StatusUnauthorized)
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
