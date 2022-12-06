package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
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
	http.HandleFunc(strings.Split(cfg.OAuth.Auth_URL, "://")[1], oauth2authhandler)
	http.HandleFunc(strings.Split(cfg.OAuth.Redirect_URL, "://")[1], oauth2callbackhandler)

	server.startServer()

	log.Fatal(http.ListenAndServe(":3001", frontend))
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

	proxy_mux.HandleFunc(strings.Split(cfg.OAuth.Auth_URL, "://")[1], oauth2authhandler)
	proxy_mux.HandleFunc(strings.Split(cfg.OAuth.Redirect_URL, "://")[1], oauth2callbackhandler)

	// create the autocert.Manager with domains and path to the cache
	certManager := autocert.Manager{
		Cache:      autocert.DirCache("/certs"),
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(domains...),
	}

	// create the TLS proxy server
	ps.server = &http.Server{
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
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
			log.Print("Error starting redirect server")
			log.Print(err)
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
			log.Print("Error starting proxy server")
			log.Print(err)
		}
	}()

	fmt.Println("Serving...")
}

func (ps *ProxyServer) restartServer() {
	ps.wg.Add(2)

	fmt.Println("Attempting to shut down server")
	ps.server.Shutdown(context.Background())
	ps.redirect_server.Shutdown(context.Background())
	log.Print("Waiting for servers to shut down")
	ps.wg.Wait()
	log.Print("Servers successfully shut down")
	cfg = loadConfig()

	server.startServer()
}

func (pd *ProxyDetails) proxy(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "pylon")
	email := session.Values["email"]

	// Dashboard checkers
	isDashboard, err := regexp.MatchString("^dashboard", getSubdomain(r))
	if err != nil {
		log.Printf("unable to parse dashboard subdomain: %v", r.URL.Host)
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

	isPylonApi, err := regexp.MatchString("^/8ef55d02bd174c29177d5618bfb3a2f3/*", r.URL.Path)
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

	// Bypass unauthenticated route regex
	if !pd.isUnauthenticatedRoute(r.URL.Path) {
		if email == nil {
			referer := fmt.Sprintf("%s%s", r.Host, r.URL.Path)
			fmt.Println(referer)
			http.Redirect(w, r, fmt.Sprintf("%s?referer=%s", cfg.OAuth.Auth_URL, referer), http.StatusFound)
			return
		}
		if !pd.userInAllowedList(email.(string)) {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, `<h3>User %s is unauthorized to access this resource.</h3>
							<button onclick="window.location.href = '%s';">Login</button>`, email, cfg.OAuth.Auth_URL)
			log.Printf("user %s not allowed", email)
			return
		}
	}

	proxy_url := pd.Internal
	url, _ := url.Parse(proxy_url)
	remoteAddr := strings.Split(r.RemoteAddr, ":")[0]
	r.RemoteAddr = ""
	proxy := httputil.NewSingleHostReverseProxy(url)
	proxy.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	r.URL.Host = url.Host
	r.URL.Scheme = url.Scheme
	r.Header.Set("X-Forwarded-Host", r.Host)
	_, ok := r.Header["X-Forwarded-For"]
	if !ok {
		r.Header.Set("X-Forwarded-For", remoteAddr)
	}
	r.Host = url.Host

	proxy.ServeHTTP(w, r)
}

func enableCORS(w *http.ResponseWriter, r *http.Request) {
	(*w).Header().Set("Access-Control-Allow-Origin", "*")
	(*w).Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
	(*w).Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
}

func ConfigHandler(w http.ResponseWriter, r *http.Request) {
	enableCORS(&w, r)

	if r.Method == "OPTIONS" {
		return
	}

	if r.Method == "GET" {
		f, err := ioutil.ReadFile("/config/config.json")
		if err != nil {
			log.Fatal(err)
		}

		w.Write(f)
	}

	if r.Method == "POST" {
		decoder := json.NewDecoder(r.Body)
		var new_config Config
		err := decoder.Decode(&new_config)
		if err != nil {
			log.Print("Error decoding config json")
			w.Write([]byte("not okay"))
			return
		}
		pretty, err := json.MarshalIndent(new_config, "", "    ")
		if err != nil {
			log.Print("Error decoding json config post data")
			w.Write([]byte("not okay"))
			return
		}
		if err != nil {
			log.Print("Error decoding json config post data")
			w.Write([]byte("not okay"))
			return
		}

		err = ioutil.WriteFile("/config/config.json", pretty, 0666)
		if err != nil {
			log.Print("Error writing to config file")
			w.Write([]byte("not okay"))
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
			log.Fatal(err)
		}

		var conf Config
		err = json.Unmarshal([]byte(f), &conf)
		if err != nil {
			log.Fatal(err)
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
		}

		w.Write(jsonResponse)
	}

	return
}

// cacheDir makes a consistent cache directory inside /tmp. Returns "" on error.
// func cacheDir() (dir string) {
// 	if u, _ := user.Current(); u != nil {
// 		dir = filepath.Join(os.TempDir(), "cache-golang-autocert-"+u.Username)
// 		if err := os.MkdirAll(dir, 0700); err == nil {
// 			return dir
// 		}
// 	}
// 	return ""
// }

func sliceContains(s []string, str string) bool {
	for _, v := range s {
		if v == str {
			return true
		}
	}

	return false
}

func getSubdomain(r *http.Request) string {
	//The Host that the user queried.
	host := r.Host
	host = strings.TrimSpace(host)
	//Figure out if a subdomain exists in the host given.
	hostParts := strings.Split(host, ".")
	fmt.Println("host parts", hostParts)

	lengthOfHostParts := len(hostParts)

	// scenarios
	// A. site.com  -> length : 2
	// B. www.site.com -> length : 3
	// C. www.hello.site.com -> length : 4

	if lengthOfHostParts == 4 {
		return strings.Join([]string{hostParts[1]}, "") // scenario C
	}

	if lengthOfHostParts == 3 { // scenario B with a check
		subdomain := strings.Join([]string{hostParts[0]}, "")

		if subdomain == "www" {
			return ""
		} else {
			return subdomain
		}
	}

	return ""
}

func loadConfig() (cfg Config) {
	f, err := ioutil.ReadFile("/config/config.json")
	if err != nil {
		log.Fatal(err)
	}

	var conf Config
	err = json.Unmarshal([]byte(f), &conf)
	if err != nil {
		log.Printf("Error unmarshalling config: %v", err)
	}

	return conf
}

func oauth2authhandler(w http.ResponseWriter, r *http.Request) {
	referer := r.URL.Query().Get("referer")
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
	http.Redirect(w, r, url, http.StatusPermanentRedirect)
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
		log.Print("Error exchanging token")
		return
	}

	if !tkn.Valid() {
		log.Print("Invalid token")
		return
	}

	email, err := emailFromIdToken(tkn.Extra("id_token").(string))
	if err != nil {
		log.Print(err)
		return
	}

	// if !pd.userInAllowedList(email) {
	//         w.Header().Set("Content-Type", "text/html")
	//         fmt.Fprintf(w, `<h3>User %s is unauthorized to access this resource.</h3>
	//                 <button onclick="window.location.href = '/auth';">Login</button>`, email)
	//         log.Printf("user %s not allowed", email)
	//         return
	// }

	session, _ := store.Get(r, "pylon")
	session.Values["email"] = email
	session.Options = &sessions.Options{
		Path:   "/",
		Domain: cfg.TLDN,
	}
	err = session.Save(r, w)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	referer := r.URL.Query().Get("state")
	if referer == "" {
		fmt.Fprintf(w, "Authenticated as %s", email)
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
	} else {
		return false
	}
}

func emailFromIdToken(idToken string) (string, error) {

	// id_token is a base64 encode ID token payload
	// https://developers.google.com/accounts/docs/OAuth2Login#obtainuserinfo
	jwt := strings.Split(idToken, ".")
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
		return "", errors.New("missing email")
	}
	if !email.EmailVerified {
		return "", fmt.Errorf("email %s not listed as verified", email.Email)
	}
	return email.Email, nil
}
