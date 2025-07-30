package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/sessions"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

var cfg = loadConfig()

type ProxyDetails struct {
	Internal                   string
	AllowedUsers               []string `json:"allowed_users"`
	UnauthenticatedRoutesRegex *regexp.Regexp
}

type Config struct {
	TLDN         string   `json:"tldn"`
	AllowedUsers []string `json:"allowed_users"`
	Proxies      []struct {
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

var store = sessions.NewCookieStore([]byte(cfg.SessionKey))
var server = &ProxyServer{wg: &sync.WaitGroup{}}

func main() {
	// Frontend handler and api endpoint
	frontend := http.NewServeMux()

	fs := http.FileServer(http.Dir("frontend"))

	frontend.Handle("/", fs)
	frontend.HandleFunc("/config", ConfigHandler)

	// OAuth2 Handlers
	authUrlHost := cfg.OAuth.Auth_URL
	if u, err := url.Parse(cfg.OAuth.Auth_URL); err == nil {
		authUrlHost = u.Host
	}
	redirectUrlHost := cfg.OAuth.Redirect_URL
	if u, err := url.Parse(cfg.OAuth.Redirect_URL); err == nil {
		redirectUrlHost = u.Host
	}

	http.HandleFunc(authUrlHost, oauth2authhandler)
	http.HandleFunc(redirectUrlHost, oauth2callbackhandler)

	server.startServer()

	log.Fatal(http.ListenAndServe(":3001", frontend))
}

// Helper function to detect WebSocket requests
func isWebSocketRequest(r *http.Request) bool {
	containsHeader := func(name, value string) bool {
		h := r.Header[name]
		for _, v := range h {
			if strings.Contains(strings.ToLower(v), value) { // Use strings.Contains for robustness, as header value might be "upgrade, keep-alive"
				return true
			}
		}
		return false
	}

	return containsHeader("Connection", "upgrade") &&
		containsHeader("Upgrade", "websocket")
}

func (ps *ProxyServer) startServer() {
	proxy_mux := http.NewServeMux()

	var domains []string

	for _, p := range cfg.Proxies {
		fmt.Println(p.External)
		domains = append(domains, p.External)
		unauthenticatedRegex := regexp.MustCompile(strings.Join(p.UnauthenticatedRoutes[:], "|"))
		internal := &ProxyDetails{Internal: p.Internal, AllowedUsers: p.AllowedUsers, UnauthenticatedRoutesRegex: unauthenticatedRegex}
		proxy_mux.HandleFunc(p.External+"/", internal.proxy)
	}

	auth_url, _ := url.Parse(cfg.OAuth.Auth_URL)
	redirect_url, _ := url.Parse(cfg.OAuth.Redirect_URL)
	domains = append(domains, auth_url.Host)
	domains = append(domains, redirect_url.Host)

	// Ensure these handlers are also registered on the proxy_mux for HTTPS
	proxy_mux.HandleFunc(auth_url.Host, oauth2authhandler)
	proxy_mux.HandleFunc(redirect_url.Host, oauth2callbackhandler)

	// create the autocert.Manager with domains and path to the cache
	certManager := autocert.Manager{
		Cache:      autocert.DirCache("/certs"),
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(domains...),
	}

	// create the TLS proxy server
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

	go func() {
		// serve HTTP, which will redirect to HTTPS
		defer ps.wg.Done()
		err := ps.redirect_server.ListenAndServe()
		if err != nil {
			if err == http.ErrServerClosed {
				return
			}
			log.Printf("Error starting redirect server: %v", err) // Use Printf for errors
		}
	}()

	// serve HTTPS!
	go func() {
		defer ps.wg.Done()
		err := ps.server.ListenAndServeTLS("", "")
		if err != nil {
			if err == http.ErrServerClosed {
				return
			}
			log.Printf("Error starting proxy server: %v", err) // Use Printf for errors
		}
	}()

	fmt.Println("Serving...")
}

func (ps *ProxyServer) restartServer() {
	ps.wg.Add(2) // Add 2 for the two servers

	fmt.Println("Attempting to shut down server")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second) // Add a shutdown timeout
	defer cancel()

	err1 := ps.server.Shutdown(ctx)
	err2 := ps.redirect_server.Shutdown(ctx)

	if err1 != nil && err1 != http.ErrServerClosed {
		log.Printf("Error shutting down proxy server: %v", err1)
	}
	if err2 != nil && err2 != http.ErrServerClosed {
		log.Printf("Error shutting down redirect server: %v", err2)
	}

	log.Print("Waiting for servers to shut down")
	ps.wg.Wait()
	log.Print("Servers successfully shut down")
	cfg = loadConfig() // Reload config after shutdown

	server.startServer()
}

func (pd *ProxyDetails) proxy(w http.ResponseWriter, r *http.Request) {
	// Handle OPTIONS preflight first
	if r.Method == "OPTIONS" {
		enableCORS(&w, r)
		w.WriteHeader(http.StatusOK)
		return
	}

	session, _ := store.Get(r, "pylon")
	email := session.Values["email"]

	// Dashboard checkers
	// TODO: pre-compile these regexps once.
	isDashboard, err := regexp.MatchString("^dashboard", getSubdomain(r))
	if err != nil {
		log.Printf("unable to parse dashboard subdomain: %v", err) // Log the error not the whole host
	}

	isDashboardRedirect := false
	isDashboardRedirectParam := r.URL.Query().Get("isDashboardRedirect")
	log.Printf("isDashboardRedirect: %s", isDashboardRedirectParam)
	if isDashboardRedirectParam == "true/" { // Dumb hack because we can't see SPA hash routes
		isDashboardRedirect = true
	}

	if isDashboard && !isDashboardRedirect {
		log.Print("Dashboard request; rendering dashboard")
		http.Redirect(w, r, "?isDashboardRedirect=true/#/dashboard", http.StatusFound)
		return
	}

	isPylonApi, err := regexp.MatchString("^/8ef55d02bd174c29177d5618bfb3a2f3/?.*", r.URL.Path) // Fixed regex for trailing slash
	if err != nil {
		log.Printf("unable to parse isPylonApi path: %v", err)
	}
	if isPylonApi {
		log.Printf("matches pylon api path; handling pylon request")
		resource := strings.TrimPrefix(r.URL.Path, "/8ef55d02bd174c29177d5618bfb3a2f3/")
		if resource == "allowedApps" {
			AppListHandler(w, r, email.(string))
		}
		return
	}

	var authenticatedEmail string
	if email != nil {
		authenticatedEmail = email.(string)
	}

	if !pd.isUnauthenticatedRoute(r.URL.Path) {
		if authenticatedEmail == "" { // User is not authenticated
			referer := fmt.Sprintf("%s%s", r.Host, r.URL.Path)
			fmt.Println(referer)
			http.Redirect(w, r, fmt.Sprintf("%s?referer=%s", cfg.OAuth.Auth_URL, referer), http.StatusFound)
			return
		}
		if !pd.userInAllowedList(authenticatedEmail) { // User is authenticated but not allowed
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, `<h3>User %s is unauthorized to access this resource.</h3>
							<button onclick="window.location.href = '%s';">Login</button>`, authenticatedEmail, cfg.OAuth.Auth_URL)
			log.Printf("user %s not allowed for %s", authenticatedEmail, r.URL.Path)
			return
		}
		// If authenticated and allowed, add identity header for the backend
		r.Header.Set("X-Pylon-User", authenticatedEmail)
	}

	// Parse the internal URL
	u, err := url.Parse(pd.Internal)
	if err != nil {
		log.Printf("Error parsing internal URL %s: %v", pd.Internal, err)
		http.Error(w, "Internal Proxy Error", http.StatusInternalServerError)
		return
	}

	remoteAddr := strings.Split(r.RemoteAddr, ":")[0]

	if isWebSocketRequest(r) {
		log.Printf("Handling WebSocket upgrade request for %s to backend %s", r.URL.Path, u.String())

		// Hijack the client connection from the HTTP server
		hj, ok := w.(http.Hijacker)
		if !ok {
			log.Print("http.ResponseWriter does not implement http.Hijacker. Cannot proxy WebSocket.")
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		clientConn, _, err := hj.Hijack() // The bufrw is often not needed immediately after hijack for upgrade
		if err != nil {
			log.Printf("Error hijacking client connection for WebSocket: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		defer clientConn.Close() // Ensure client connection is closed when this handler exits

		// Establish a direct TCP connection to the backend WebSocket server
		backendConn, err := net.Dial("tcp", u.Host)
		if err != nil {
			log.Printf("Error dialing backend %s for WebSocket: %v", u.Host, err)
			return
		}
		defer backendConn.Close() // Ensure backend connection is closed

		// Set Headers for the request going to the backend
		r.URL.Scheme = u.Scheme
		r.URL.Host = u.Host
		r.Host = u.Host // Set the Host header to the backend's host

		// Add X-Forwarded-For for standard proxying
		r.Header.Set("X-Forwarded-Proto", r.URL.Scheme)
		if r.TLS != nil {
			r.Header.Set("X-Forwarded-Ssl", "on")
			r.Header.Set("X-Forwarded-Proto", "https")
		} else {
			r.Header.Set("X-Forwarded-Proto", "http")
		}
		r.Header.Set("X-Forwarded-Port", u.Port())
		r.Header.Set("X-Forwarded-Host", r.Host) // Set to the backend host for backend's view
		if remoteAddr != "" {
			r.Header.Set("X-Forwarded-For", remoteAddr)
		}

		// Write the client's original HTTP upgrade request directly to the backend TCP connection
		err = r.Write(backendConn)
		if err != nil {
			log.Printf("Error writing upgrade request to backend: %v", err)
			return
		}

		log.Printf("WebSocket connection established (handshake complete) between client %s and backend %s. Starting data copy.", clientConn.RemoteAddr(), backendConn.RemoteAddr())

		var wg sync.WaitGroup
		wg.Add(2)

		go func() {
			defer wg.Done()
			_, err := io.Copy(backendConn, clientConn) // Client to Backend
			if err != nil && err != io.EOF {
				log.Printf("Error copying from client to backend (WebSocket): %v", err)
			}
		}()

		go func() {
			defer wg.Done()
			_, err := io.Copy(clientConn, backendConn) // Backend to Client
			if err != nil && err != io.EOF {
				log.Printf("Error copying from backend to client (WebSocket): %v", err)
			}
		}()

		wg.Wait()
		log.Printf("WebSocket connection closed for %s", r.URL.Path)
		return // Return immediately after handling WebSocket. Do not proceed to standard HTTP proxy.
	}

	proxy := httputil.NewSingleHostReverseProxy(u)
	proxy.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	// Apply X-Forwarded headers for regular HTTP requests
	r.Header.Set("X-Forwarded-Proto", r.URL.Scheme)
	if r.TLS != nil {
		r.Header.Set("X-Forwarded-Ssl", "on")
		r.Header.Set("X-Forwarded-Proto", "https")
	} else {
		r.Header.Set("X-Forwarded-Proto", "http")
	}

	r.Header.Set("X-Forwarded-Port", u.Port())
	r.URL.Host = u.Host
	r.URL.Scheme = u.Scheme
	r.Header.Set("X-Forwarded-Host", r.Host)
	if remoteAddr != "" {
		r.Header.Set("X-Forwarded-For", remoteAddr)
	}

	r.Host = u.Host

	proxy.ServeHTTP(w, r)
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
		return
	}

	if r.Method == "GET" {
		f, err := ioutil.ReadFile("/config/config.json")
		if err != nil {
			log.Fatalf("Error reading config.json: %v", err)
		}

		w.Write(f)
	}

	if r.Method == "POST" {
		decoder := json.NewDecoder(r.Body)
		var new_config Config
		err := decoder.Decode(&new_config)
		if err != nil {
			log.Printf("Error decoding config json: %v", err)
			http.Error(w, "Error decoding JSON", http.StatusBadRequest)
			return
		}
		pretty, err := json.MarshalIndent(new_config, "", "    ")
		if err != nil {
			log.Printf("Error marshalling config json: %v", err)
			http.Error(w, "Error marshalling JSON", http.StatusInternalServerError)
			return
		}

		err = ioutil.WriteFile("/config/config.json", pretty, 0666)
		if err != nil {
			log.Printf("Error writing to config file: %v", err)
			http.Error(w, "Error writing config", http.StatusInternalServerError)
			return
		}

		server.restartServer()
		w.Write([]byte("okay"))
		return
	}
}

func AppListHandler(w http.ResponseWriter, r *http.Request, user string) {
	enableCORS(&w, r)

	if r.Method == "OPTIONS" {
		return
	}

	if r.Method == "GET" {
		f, err := ioutil.ReadFile("/config/config.json")
		if err != nil {
			log.Fatalf("Error reading config.json for AppListHandler: %v", err) // Use Fatalf for critical errors
		}

		var conf Config
		err = json.Unmarshal([]byte(f), &conf)
		if err != nil {
			log.Fatalf("Error unmarshalling config for AppListHandler: %v", err) // Use Fatalf for critical errors
		}

		allowedApps := new(AppListResponse)

		for _, proxy := range conf.Proxies {
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

	return
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
	fmt.Println("host parts", hostParts)

	lengthOfHostParts := len(hostParts)

	if lengthOfHostParts > 2 {
		if strings.HasSuffix(host, cfg.TLDN) {
			prefix := strings.TrimSuffix(host, "."+cfg.TLDN)
			if prefix == "" || prefix == "www" { // Treat "www" as no effective subdomain
				return ""
			}
			return prefix
		}
	}
	return ""
}

func loadConfig() (cfg Config) {
	f, err := ioutil.ReadFile("/config/config.json")
	if err != nil {
		log.Fatalf("Error reading config.json at startup: %v", err)
	}

	var conf Config
	err = json.Unmarshal([]byte(f), &conf)
	if err != nil {
		log.Fatalf("Error unmarshalling config at startup: %v", err) // Use Fatalf for critical errors
	}

	return conf
}

func oauth2authhandler(w http.ResponseWriter, r *http.Request) {
	referer := r.URL.Query().Get("referer") // Referer is passed as 'state' param to Google
	googleAuth := &oauth2.Config{
		ClientID:     cfg.OAuth.Client_ID,
		ClientSecret: cfg.OAuth.Client_Secret,
		RedirectURL:  cfg.OAuth.Redirect_URL,
		Scopes: []string{
			"email",
			"profile",
		},
		Endpoint: google.Endpoint,
	}

	url := googleAuth.AuthCodeURL(referer)
	http.Redirect(w, r, url, http.StatusFound) // Changed to StatusFound (302) for standard OAuth
}

func oauth2callbackhandler(w http.ResponseWriter, r *http.Request) {
	googleAuth := &oauth2.Config{
		ClientID:     cfg.OAuth.Client_ID,
		ClientSecret: cfg.OAuth.Client_Secret,
		RedirectURL:  cfg.OAuth.Redirect_URL,
		Scopes: []string{
			"email",
			"profile",
		},
		Endpoint: google.Endpoint,
	}

	tkn, err := googleAuth.Exchange(context.TODO(), r.URL.Query().Get("code"))
	if err != nil {
		log.Printf("Error exchanging token: %v", err)
		http.Error(w, "Authentication failed", http.StatusInternalServerError)
		return
	}

	if !tkn.Valid() {
		log.Print("Invalid token received from OAuth callback")
		http.Error(w, "Invalid token", http.StatusInternalServerError)
		return
	}

	email, err := emailFromIdToken(tkn.Extra("id_token").(string))
	if err != nil {
		log.Printf("Error extracting email from ID token: %v", err)
		http.Error(w, "Authentication failed", http.StatusInternalServerError)
		return
	}

	session, _ := store.Get(r, "pylon")
	session.Values["email"] = email
	session.Options = &sessions.Options{
		Path:     "/",
		Domain:   cfg.TLDN,
		MaxAge:   int(cfg.CookieExpire.Seconds()), // Set cookie expiration
		Secure:   true,
		HttpOnly: true,                 // Prevent JavaScript access
		SameSite: http.SameSiteLaxMode, // Or SameSiteStrictMode
	}
	err = session.Save(r, w)
	if err != nil {
		log.Printf("Error saving session: %v", err)
		http.Error(w, "Error saving session", http.StatusInternalServerError)
		return
	}

	referer := r.URL.Query().Get("state") // State parameter is used for referer
	if referer == "" {
		fmt.Fprintf(w, "Authenticated as %s. You can now access your applications.", email)
		return
	}

	// Ensure the redirect URL is fully qualified with HTTPS
	if !strings.HasPrefix(referer, "http://") && !strings.HasPrefix(referer, "https://") {
		referer = "https://" + referer // Default to https if scheme is missing
	}
	http.Redirect(w, r, referer, http.StatusFound)
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
	// Check if the regex is compiled and if it matches
	if pd.UnauthenticatedRoutesRegex != nil && len(pd.UnauthenticatedRoutesRegex.String()) > 0 && pd.UnauthenticatedRoutesRegex.MatchString(path) {
		log.Printf("Bypass Pylon due to regex match: %q for path: %s for internal host: %s", pd.UnauthenticatedRoutesRegex.String(), path, pd.Internal)
		return true
	} else {
		return false
	}
}

func emailFromIdToken(idToken string) (string, error) {
	// id_token is a base64 encode ID token payload
	// https://developers.google.com/accounts/docs/OAuth2Login#obtainuserinfo
	jwtParts := strings.Split(idToken, ".")
	if len(jwtParts) != 3 {
		return "", errors.New("invalid ID token format")
	}

	// ID token payload is the second part
	jwtData := jwtParts[1]
	// JWT segments are Base64Url-encoded, sometimes without padding.
	// RawURLEncoding handles this automatically.
	b, err := base64.RawURLEncoding.DecodeString(jwtData)
	if err != nil {
		return "", fmt.Errorf("error decoding ID token payload: %w", err)
	}

	var emailInfo struct {
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
	}
	err = json.Unmarshal(b, &emailInfo)
	if err != nil {
		return "", fmt.Errorf("error unmarshalling ID token payload: %w", err)
	}
	if emailInfo.Email == "" {
		return "", errors.New("missing email in ID token")
	}
	if !emailInfo.EmailVerified {
		return "", fmt.Errorf("email %s not listed as verified in ID token", emailInfo.Email)
	}
	return emailInfo.Email, nil
}
