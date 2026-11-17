package main

// OAuth 2.1 authorization server for non-browser clients (MCP connectors,
// CLIs, API clients).
//
// Routes that set "allow_oauth_clients" become OAuth protected resources.
// Each such host is its own issuer and serves:
//
//	/.well-known/oauth-protected-resource   (RFC 9728)
//	/.well-known/oauth-authorization-server (RFC 8414)
//	/pylon/oauth/register                   (RFC 7591 dynamic client registration)
//	/pylon/oauth/authorize                  (authorization code + PKCE S256)
//	/pylon/oauth/token                      (authorization_code, refresh_token)
//	/pylon/oauth/revoke                     (RFC 7009)
//
// The user signs in through the normal Pylon login (upstream identity
// provider), approves the client on a consent page, and the client receives
// a bearer token that is only valid for that host and is subject to the
// route's allowed_users list on every request.

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	oauthAccessTokenTTL  = time.Hour
	oauthRefreshTokenTTL = 30 * 24 * time.Hour // sliding: renewed on every refresh
	oauthAuthCodeTTL     = 2 * time.Minute
	oauthConsentTTL      = 10 * time.Minute
	oauthMaxClients      = 500
	oauthMaxRedirectURIs = 10

	oauthAccessTokenPrefix  = "pylon_at_"
	oauthRefreshTokenPrefix = "pylon_rt_"
	oauthClientIDPrefix     = "pylon_client_"
)

type OAuthClient struct {
	ID           string    `json:"client_id"`
	Name         string    `json:"client_name,omitempty"`
	RedirectURIs []string  `json:"redirect_uris"`
	AuthMethod   string    `json:"token_endpoint_auth_method"`
	SecretHash   string    `json:"secret_hash,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
}

// OAuthGrant is one user's approval of one client for one host. It owns the
// current refresh token and any access tokens derived from it.
type OAuthGrant struct {
	ID              string     `json:"id"`
	ClientID        string     `json:"client_id"`
	Host            string     `json:"host"`
	Claims          UserClaims `json:"claims"`
	Scope           string     `json:"scope,omitempty"`
	RefreshHash     string     `json:"refresh_hash"`
	PrevRefreshHash string     `json:"prev_refresh_hash,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	LastUsed        time.Time  `json:"last_used"`
	ExpiresAt       time.Time  `json:"expires_at"`
}

type oauthAccessToken struct {
	GrantID string
	Expires time.Time
}

type oauthAuthCode struct {
	ClientID    string
	RedirectURI string
	Challenge   string
	Host        string
	Scope       string
	Claims      UserClaims
	Expires     time.Time
	GrantID     string // set once redeemed, to detect replay
}

type oauthStore struct {
	mu      sync.Mutex
	path    string // empty: in-memory only
	clients map[string]*OAuthClient
	grants  map[string]*OAuthGrant
	access  map[string]*oauthAccessToken // by token hash; memory only
	codes   map[string]*oauthAuthCode    // by code hash; memory only
}

type oauthPersistedState struct {
	Clients []*OAuthClient `json:"clients"`
	Grants  []*OAuthGrant  `json:"grants"`
}

var oauthState = newOAuthStore()

func newOAuthStore() *oauthStore {
	return &oauthStore{
		clients: make(map[string]*OAuthClient),
		grants:  make(map[string]*OAuthGrant),
		access:  make(map[string]*oauthAccessToken),
		codes:   make(map[string]*oauthAuthCode),
	}
}

func oauthStatePath() string {
	return filepath.Join(filepath.Dir(getConfigPath()), "oauth_state.json")
}

// load reads persisted clients and grants and enables persistence to path.
func (s *oauthStore) load(path string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.path = path

	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var st oauthPersistedState
	if err := json.Unmarshal(b, &st); err != nil {
		return err
	}
	now := time.Now()
	for _, c := range st.Clients {
		if c != nil && c.ID != "" {
			s.clients[c.ID] = c
		}
	}
	for _, g := range st.Grants {
		if g != nil && g.ID != "" && g.ExpiresAt.After(now) {
			s.grants[g.ID] = g
		}
	}
	return nil
}

// saveLocked persists clients and grants. Caller must hold s.mu.
func (s *oauthStore) saveLocked() {
	if s.path == "" {
		return
	}
	st := oauthPersistedState{}
	for _, c := range s.clients {
		st.Clients = append(st.Clients, c)
	}
	for _, g := range s.grants {
		st.Grants = append(st.Grants, g)
	}
	sort.Slice(st.Clients, func(i, j int) bool { return st.Clients[i].CreatedAt.Before(st.Clients[j].CreatedAt) })
	sort.Slice(st.Grants, func(i, j int) bool { return st.Grants[i].CreatedAt.Before(st.Grants[j].CreatedAt) })

	b, err := json.MarshalIndent(st, "", "    ")
	if err != nil {
		log.Printf("oauth: failed to encode state: %v", err)
		return
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0600); err != nil {
		log.Printf("oauth: failed to write state: %v", err)
		return
	}
	if err := os.Rename(tmp, s.path); err != nil {
		log.Printf("oauth: failed to replace state file: %v", err)
	}
}

// pruneLocked drops expired codes, access tokens and grants. Caller must hold s.mu.
func (s *oauthStore) pruneLocked(now time.Time) {
	for k, c := range s.codes {
		if now.After(c.Expires) {
			delete(s.codes, k)
		}
	}
	for k, t := range s.access {
		if now.After(t.Expires) {
			delete(s.access, k)
		}
	}
	for id, g := range s.grants {
		if now.After(g.ExpiresAt) {
			s.revokeGrantLocked(id)
		}
	}
}

// revokeGrantLocked removes a grant and its access tokens. Caller must hold s.mu.
func (s *oauthStore) revokeGrantLocked(id string) bool {
	if _, ok := s.grants[id]; !ok {
		return false
	}
	delete(s.grants, id)
	for k, t := range s.access {
		if t.GrantID == id {
			delete(s.access, k)
		}
	}
	return true
}

func (s *oauthStore) revokeGrant(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	ok := s.revokeGrantLocked(id)
	if ok {
		s.saveLocked()
	}
	return ok
}

func (s *oauthStore) getClient(id string) *OAuthClient {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.clients[id]
	if !ok {
		return nil
	}
	cp := *c
	return &cp
}

func (s *oauthStore) addClient(c *OAuthClient) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Registration is unauthenticated, so bound the store: evict the oldest
	// clients that nobody has ever authorized.
	if len(s.clients) >= oauthMaxClients {
		inUse := make(map[string]bool)
		for _, g := range s.grants {
			inUse[g.ClientID] = true
		}
		var idle []*OAuthClient
		for _, existing := range s.clients {
			if !inUse[existing.ID] {
				idle = append(idle, existing)
			}
		}
		sort.Slice(idle, func(i, j int) bool { return idle[i].CreatedAt.Before(idle[j].CreatedAt) })
		for i := 0; i < len(idle) && len(s.clients) >= oauthMaxClients; i++ {
			delete(s.clients, idle[i].ID)
		}
	}
	s.clients[c.ID] = c
	s.saveLocked()
}

func (s *oauthStore) putCode(code string, ac *oauthAuthCode) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(time.Now())
	s.codes[oauthHash(code)] = ac
}

// issueTokensLocked mints an access token and rotates the grant's refresh token.
func (s *oauthStore) issueTokensLocked(g *OAuthGrant, now time.Time) (access, refresh string) {
	access = oauthAccessTokenPrefix + oauthRandomToken()
	refresh = oauthRefreshTokenPrefix + oauthRandomToken()
	s.access[oauthHash(access)] = &oauthAccessToken{GrantID: g.ID, Expires: now.Add(oauthAccessTokenTTL)}
	g.PrevRefreshHash = g.RefreshHash
	g.RefreshHash = oauthHash(refresh)
	g.LastUsed = now
	g.ExpiresAt = now.Add(oauthRefreshTokenTTL)
	return access, refresh
}

// lookupAccessToken returns the grant behind a valid access token.
func (s *oauthStore) lookupAccessToken(token string) *OAuthGrant {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.access[oauthHash(token)]
	if !ok || time.Now().After(t.Expires) {
		return nil
	}
	g, ok := s.grants[t.GrantID]
	if !ok {
		return nil
	}
	cp := *g
	return &cp
}

func oauthRandomToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("oauth: crypto/rand failed: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func oauthHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func oauthIssuer(r *http.Request) string {
	return "https://" + r.Host
}

// oauthRoute returns the proxy route for the request host if it accepts OAuth clients.
func oauthRoute(r *http.Request) (*ProxyDetails, bool) {
	pd, found := lookupProxy(r.Host)
	if !found || !pd.OAuthEnabled || pd.ReverseProxy == nil {
		return nil, false
	}
	return pd, true
}

// handleOAuthServer serves the OAuth endpoints for hosts that enabled them.
// It reports whether the request was handled.
func handleOAuthServer(w http.ResponseWriter, r *http.Request) bool {
	path := r.URL.Path
	const prm = "/.well-known/oauth-protected-resource"
	const asm = "/.well-known/oauth-authorization-server"

	isPRM := path == prm || strings.HasPrefix(path, prm+"/")
	isASM := path == asm || strings.HasPrefix(path, asm+"/")
	if !isPRM && !isASM && !strings.HasPrefix(path, "/pylon/oauth/") {
		return false
	}

	if _, ok := oauthRoute(r); !ok {
		if isPRM || isASM {
			// Not ours: let the upstream service answer its own well-known paths.
			return false
		}
		http.Error(w, "OAuth client access is not enabled for this host", http.StatusNotFound)
		return true
	}

	switch {
	case isPRM:
		oauthProtectedResourceMetadataHandler(w, r, strings.TrimPrefix(path, prm))
	case isASM:
		oauthServerMetadataHandler(w, r)
	case path == "/pylon/oauth/register":
		oauthRegisterHandler(w, r)
	case path == "/pylon/oauth/authorize":
		oauthAuthorizeHandler(w, r)
	case path == "/pylon/oauth/token":
		oauthTokenHandler(w, r)
	case path == "/pylon/oauth/revoke":
		oauthRevokeHandler(w, r)
	default:
		http.NotFound(w, r)
	}
	return true
}

func oauthWriteJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func oauthWriteError(w http.ResponseWriter, status int, code, description string) {
	oauthWriteJSON(w, status, map[string]string{"error": code, "error_description": description})
}

func oauthProtectedResourceMetadataHandler(w http.ResponseWriter, r *http.Request, resourcePath string) {
	issuer := oauthIssuer(r)
	oauthWriteJSON(w, http.StatusOK, map[string]interface{}{
		"resource":                 issuer + strings.TrimSuffix(resourcePath, "/"),
		"authorization_servers":    []string{issuer},
		"bearer_methods_supported": []string{"header"},
		"resource_name":            r.Host,
	})
}

func oauthServerMetadataHandler(w http.ResponseWriter, r *http.Request) {
	issuer := oauthIssuer(r)
	oauthWriteJSON(w, http.StatusOK, map[string]interface{}{
		"issuer":                                     issuer,
		"authorization_endpoint":                     issuer + "/pylon/oauth/authorize",
		"token_endpoint":                             issuer + "/pylon/oauth/token",
		"registration_endpoint":                      issuer + "/pylon/oauth/register",
		"revocation_endpoint":                        issuer + "/pylon/oauth/revoke",
		"response_types_supported":                   []string{"code"},
		"response_modes_supported":                   []string{"query"},
		"grant_types_supported":                      []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":           []string{"S256"},
		"token_endpoint_auth_methods_supported":      []string{"none", "client_secret_post", "client_secret_basic"},
		"revocation_endpoint_auth_methods_supported": []string{"none", "client_secret_post", "client_secret_basic"},
	})
}

// --- Dynamic client registration (RFC 7591) ---

func oauthIsLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func oauthValidRedirectURI(raw string) bool {
	if len(raw) > 2000 {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Fragment != "" || strings.Contains(raw, "#") {
		return false
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return u.Hostname() != ""
	case "http":
		// Plain HTTP only for native clients listening on loopback.
		return oauthIsLoopbackHost(u.Hostname())
	case "javascript", "data", "vbscript", "file", "blob", "about":
		return false
	default:
		// Private-use schemes for native apps (e.g. cursor://, vscode://).
		return true
	}
}

// oauthRedirectURIMatches compares exactly, except that loopback redirects may
// use any port (RFC 8252 section 7.3).
func oauthRedirectURIMatches(registered, requested string) bool {
	if registered == requested {
		return true
	}
	a, errA := url.Parse(registered)
	b, errB := url.Parse(requested)
	if errA != nil || errB != nil {
		return false
	}
	if a.Scheme != "http" || b.Scheme != "http" || !oauthIsLoopbackHost(a.Hostname()) || !oauthIsLoopbackHost(b.Hostname()) {
		return false
	}
	return a.Hostname() == b.Hostname() && a.Path == b.Path && a.RawQuery == b.RawQuery
}

func oauthClientAllowsRedirect(c *OAuthClient, redirectURI string) bool {
	for _, reg := range c.RedirectURIs {
		if oauthRedirectURIMatches(reg, redirectURI) {
			return true
		}
	}
	return false
}

func oauthRegisterHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		oauthWriteError(w, http.StatusMethodNotAllowed, "invalid_request", "POST required")
		return
	}

	var req struct {
		RedirectURIs            []string `json:"redirect_uris"`
		ClientName              string   `json:"client_name"`
		TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
		GrantTypes              []string `json:"grant_types"`
		ResponseTypes           []string `json:"response_types"`
		Scope                   string   `json:"scope"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		oauthWriteError(w, http.StatusBadRequest, "invalid_client_metadata", "request body must be a JSON object")
		return
	}

	if len(req.RedirectURIs) == 0 || len(req.RedirectURIs) > oauthMaxRedirectURIs {
		oauthWriteError(w, http.StatusBadRequest, "invalid_redirect_uri", fmt.Sprintf("between 1 and %d redirect_uris are required", oauthMaxRedirectURIs))
		return
	}
	for _, u := range req.RedirectURIs {
		if !oauthValidRedirectURI(u) {
			oauthWriteError(w, http.StatusBadRequest, "invalid_redirect_uri", "redirect URIs must be https, loopback http, or a private-use scheme, without a fragment")
			return
		}
	}

	authMethod := req.TokenEndpointAuthMethod
	if authMethod == "" {
		authMethod = "client_secret_basic" // RFC 7591 default
	}
	if authMethod != "none" && authMethod != "client_secret_post" && authMethod != "client_secret_basic" {
		oauthWriteError(w, http.StatusBadRequest, "invalid_client_metadata", "unsupported token_endpoint_auth_method")
		return
	}
	for _, gt := range req.GrantTypes {
		if gt != "authorization_code" && gt != "refresh_token" {
			oauthWriteError(w, http.StatusBadRequest, "invalid_client_metadata", "unsupported grant type: "+gt)
			return
		}
	}
	for _, rt := range req.ResponseTypes {
		if rt != "code" {
			oauthWriteError(w, http.StatusBadRequest, "invalid_client_metadata", "unsupported response type: "+rt)
			return
		}
	}

	name := strings.TrimSpace(req.ClientName)
	if len(name) > 100 {
		name = name[:100]
	}

	now := time.Now()
	client := &OAuthClient{
		ID:           oauthClientIDPrefix + oauthRandomToken()[:24],
		Name:         name,
		RedirectURIs: req.RedirectURIs,
		AuthMethod:   authMethod,
		CreatedAt:    now,
	}
	resp := map[string]interface{}{
		"client_id":                  client.ID,
		"client_id_issued_at":        now.Unix(),
		"redirect_uris":              client.RedirectURIs,
		"token_endpoint_auth_method": authMethod,
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
	}
	if name != "" {
		resp["client_name"] = name
	}
	if req.Scope != "" {
		resp["scope"] = req.Scope
	}
	if authMethod != "none" {
		secret := oauthRandomToken()
		client.SecretHash = oauthHash(secret)
		resp["client_secret"] = secret
		resp["client_secret_expires_at"] = 0
	}

	oauthState.addClient(client)
	log.Printf("oauth: registered client %s (%q) via %s", client.ID, client.Name, r.Host)
	oauthWriteJSON(w, http.StatusCreated, resp)
}

// --- Authorization endpoint ---

type oauthAuthorizeRequest struct {
	Client      *OAuthClient
	RedirectURI string
	State       string
	Challenge   string
	Scope       string
}

func oauthRedirectWithParams(w http.ResponseWriter, r *http.Request, redirectURI string, params map[string]string) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, "Invalid redirect URI", http.StatusBadRequest)
		return
	}
	q := u.Query()
	for k, v := range params {
		if v != "" {
			q.Set(k, v)
		}
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// oauthResourceMatchesHost checks an RFC 8707 resource indicator against the
// host this token would be issued for.
func oauthResourceMatchesHost(resource, host string) bool {
	u, err := url.Parse(resource)
	if err != nil {
		return false
	}
	return u.Scheme == "https" && strings.EqualFold(u.Host, host)
}

// oauthParseAuthorize validates an authorization request. Problems with the
// client or redirect URI are shown to the user (ok=false, response written);
// other problems are reported back to the client via redirect.
func oauthParseAuthorize(w http.ResponseWriter, r *http.Request) (*oauthAuthorizeRequest, bool) {
	q := r.Form

	client := oauthState.getClient(q.Get("client_id"))
	if client == nil {
		oauthRenderMessage(w, http.StatusBadRequest, "Unknown application",
			"This application is not registered with Pylon. Try removing and re-adding the connection in the application.")
		return nil, false
	}
	redirectURI := q.Get("redirect_uri")
	if redirectURI == "" && len(client.RedirectURIs) == 1 {
		redirectURI = client.RedirectURIs[0]
	}
	if !oauthClientAllowsRedirect(client, redirectURI) {
		oauthRenderMessage(w, http.StatusBadRequest, "Invalid redirect URI",
			"The redirect URI in this request does not match the one the application registered.")
		return nil, false
	}

	req := &oauthAuthorizeRequest{
		Client:      client,
		RedirectURI: redirectURI,
		State:       q.Get("state"),
		Challenge:   q.Get("code_challenge"),
		Scope:       q.Get("scope"),
	}

	fail := func(code, desc string) (*oauthAuthorizeRequest, bool) {
		oauthRedirectWithParams(w, r, redirectURI, map[string]string{
			"error": code, "error_description": desc, "state": req.State,
		})
		return nil, false
	}

	if q.Get("response_type") != "code" {
		return fail("unsupported_response_type", "only response_type=code is supported")
	}
	if len(req.Challenge) < 43 || len(req.Challenge) > 128 || q.Get("code_challenge_method") != "S256" {
		return fail("invalid_request", "PKCE with code_challenge_method=S256 is required")
	}
	if len(req.Scope) > 1000 {
		return fail("invalid_scope", "scope too long")
	}
	if res := q.Get("resource"); res != "" && !oauthResourceMatchesHost(res, r.Host) {
		return fail("invalid_target", "resource must be on "+r.Host)
	}
	return req, true
}

// oauthConsentToken binds a consent form to the signed-in user and the exact
// request being approved, so it cannot be forged cross-site or replayed for a
// different client.
func oauthConsentToken(email, host string, req *oauthAuthorizeRequest, expires int64) string {
	cfgMu.RLock()
	key := cfg.SessionKey
	cfgMu.RUnlock()

	mac := hmac.New(sha256.New, []byte("pylon-oauth-consent:"+key))
	for _, part := range []string{strconv.FormatInt(expires, 10), email, host, req.Client.ID, req.RedirectURI, req.Challenge, req.State, req.Scope} {
		fmt.Fprintf(mac, "%d:%s|", len(part), part)
	}
	return strconv.FormatInt(expires, 10) + "." + hex.EncodeToString(mac.Sum(nil))
}

func oauthVerifyConsentToken(token, email, host string, req *oauthAuthorizeRequest) bool {
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 {
		return false
	}
	expires, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || time.Now().Unix() > expires {
		return false
	}
	want := oauthConsentToken(email, host, req, expires)
	return subtle.ConstantTimeCompare([]byte(want), []byte(token)) == 1
}

func oauthAuthorizeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "frame-ancestors 'none'")

	pd, _ := oauthRoute(r)

	req, ok := oauthParseAuthorize(w, r)
	if !ok {
		return
	}

	// Require a Pylon session; send the user through the normal login and back.
	session, _ := getSessionStore().Get(r, "pylon")
	claims := getClaimsFromSession(session)
	if claims == nil {
		if r.Method != http.MethodGet {
			oauthRenderMessage(w, http.StatusUnauthorized, "Session expired", "Your Pylon session expired. Start the connection again from the application.")
			return
		}
		referer := r.Host + r.URL.RequestURI()
		http.Redirect(w, r, "/pylon/login?referer="+url.QueryEscape(referer), http.StatusFound)
		return
	}

	if !pd.userInAllowedList(claims.Email) {
		log.Printf("oauth: user %s not allowed for host %s (client %s)", claims.Email, r.Host, req.Client.ID)
		oauthRenderMessage(w, http.StatusForbidden, "Access denied",
			fmt.Sprintf("%s is not allowed to access %s. Sign out of Pylon and sign in with a permitted account, then try again.", claims.Email, r.Host))
		return
	}

	if r.Method == http.MethodGet {
		expires := time.Now().Add(oauthConsentTTL).Unix()
		oauthRenderConsent(w, r, req, claims, oauthConsentToken(claims.Email, r.Host, req, expires))
		return
	}

	// POST: the user's decision.
	if !oauthVerifyConsentToken(r.PostForm.Get("consent_token"), claims.Email, r.Host, req) {
		oauthRenderMessage(w, http.StatusBadRequest, "Request expired", "This approval page expired or is invalid. Start the connection again from the application.")
		return
	}

	if r.PostForm.Get("decision") != "approve" {
		oauthRedirectWithParams(w, r, req.RedirectURI, map[string]string{
			"error": "access_denied", "error_description": "the user denied the request", "state": req.State,
		})
		return
	}

	code := oauthRandomToken()
	oauthState.putCode(code, &oauthAuthCode{
		ClientID:    req.Client.ID,
		RedirectURI: req.RedirectURI,
		Challenge:   req.Challenge,
		Host:        r.Host,
		Scope:       req.Scope,
		Claims:      *claims,
		Expires:     time.Now().Add(oauthAuthCodeTTL),
	})
	log.Printf("oauth: %s approved client %s (%q) for %s", claims.Email, req.Client.ID, req.Client.Name, r.Host)

	oauthRedirectWithParams(w, r, req.RedirectURI, map[string]string{"code": code, "state": req.State})
}

const oauthPageStyle = `
	body { font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
		background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%); color: #f8fafc;
		display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; padding: 16px; box-sizing: border-box; }
	.container { background: rgba(30, 41, 59, 0.7); backdrop-filter: blur(16px); -webkit-backdrop-filter: blur(16px);
		border: 1px solid rgba(255, 255, 255, 0.1); border-radius: 24px; padding: 40px; width: 100%; max-width: 440px;
		box-sizing: border-box; box-shadow: 0 20px 25px -5px rgb(0 0 0 / 0.5); text-align: center; }
	h1 { font-size: 24px; font-weight: 700; margin: 0 0 12px; background: linear-gradient(to right, #38bdf8, #818cf8);
		-webkit-background-clip: text; -webkit-text-fill-color: transparent; }
	p { color: #94a3b8; font-size: 14px; line-height: 1.6; margin: 0 0 20px; }
	strong { color: #f8fafc; overflow-wrap: anywhere; }
	dl { text-align: left; background: rgba(15, 23, 42, 0.5); border: 1px solid rgba(255, 255, 255, 0.08);
		border-radius: 12px; padding: 14px 16px; margin: 0 0 24px; font-size: 13px; }
	dt { color: #94a3b8; margin-top: 8px; } dt:first-child { margin-top: 0; }
	dd { margin: 2px 0 0; color: #f8fafc; overflow-wrap: anywhere; }
	.actions { display: flex; gap: 12px; }
	button { flex: 1; padding: 13px 20px; border-radius: 12px; border: none; font-family: inherit; font-weight: 600;
		font-size: 15px; cursor: pointer; color: white; }
	button.approve { background: #4f46e5; } button.deny { background: rgba(255, 255, 255, 0.1); }
	button:hover { filter: brightness(1.15); }
`

func oauthRenderMessage(w http.ResponseWriter, status int, title, message string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	fmt.Fprintf(w, `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>%s - Pylon</title><style>%s</style></head>
<body><div class="container"><h1>%s</h1><p>%s</p></div></body></html>`,
		html.EscapeString(title), oauthPageStyle, html.EscapeString(title), html.EscapeString(message))
}

func oauthRenderConsent(w http.ResponseWriter, r *http.Request, req *oauthAuthorizeRequest, claims *UserClaims, consentToken string) {
	clientName := req.Client.Name
	if clientName == "" {
		clientName = "An application"
	}
	redirectTarget := req.RedirectURI
	if u, err := url.Parse(req.RedirectURI); err == nil && u.Host != "" {
		redirectTarget = u.Scheme + "://" + u.Host
	}

	// Carry the original request through the form so the POST is re-validated.
	var hidden strings.Builder
	for _, k := range []string{"client_id", "redirect_uri", "response_type", "state", "code_challenge", "code_challenge_method", "scope", "resource"} {
		if v := r.Form.Get(k); v != "" {
			fmt.Fprintf(&hidden, `<input type="hidden" name="%s" value="%s">`, k, html.EscapeString(v))
		}
	}
	fmt.Fprintf(&hidden, `<input type="hidden" name="consent_token" value="%s">`, html.EscapeString(consentToken))

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Authorize access - Pylon</title><style>%s</style></head>
<body><div class="container">
<h1>Authorize access</h1>
<p><strong>%s</strong> wants to access <strong>%s</strong> on your behalf.</p>
<dl>
<dt>Signed in as</dt><dd>%s</dd>
<dt>Application (self-reported name)</dt><dd>%s</dd>
<dt>You will be sent back to</dt><dd>%s</dd>
</dl>
<p>Only approve if you started this connection yourself. You can revoke access later from the Pylon admin panel.</p>
<form method="POST" action="/pylon/oauth/authorize">%s
<div class="actions">
<button type="submit" name="decision" value="deny" class="deny">Deny</button>
<button type="submit" name="decision" value="approve" class="approve">Approve</button>
</div></form>
</div></body></html>`,
		oauthPageStyle,
		html.EscapeString(clientName), html.EscapeString(r.Host),
		html.EscapeString(claims.Email), html.EscapeString(clientName), html.EscapeString(redirectTarget),
		hidden.String())
}

// --- Token endpoint ---

// oauthAuthenticateClient identifies the client on token/revocation requests
// and checks its secret if it has one.
func oauthAuthenticateClient(r *http.Request) *OAuthClient {
	clientID := r.PostForm.Get("client_id")
	secret := r.PostForm.Get("client_secret")
	if id, pass, ok := r.BasicAuth(); ok {
		if unescaped, err := url.QueryUnescape(id); err == nil {
			id = unescaped
		}
		if unescaped, err := url.QueryUnescape(pass); err == nil {
			pass = unescaped
		}
		clientID, secret = id, pass
	}
	client := oauthState.getClient(clientID)
	if client == nil {
		return nil
	}
	if client.SecretHash != "" && subtle.ConstantTimeCompare([]byte(oauthHash(secret)), []byte(client.SecretHash)) != 1 {
		return nil
	}
	return client
}

func oauthTokenHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		oauthWriteError(w, http.StatusMethodNotAllowed, "invalid_request", "POST required")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		oauthWriteError(w, http.StatusBadRequest, "invalid_request", "malformed form body")
		return
	}

	client := oauthAuthenticateClient(r)
	if client == nil {
		oauthWriteError(w, http.StatusUnauthorized, "invalid_client", "unknown client or bad client credentials")
		return
	}
	if res := r.PostForm.Get("resource"); res != "" && !oauthResourceMatchesHost(res, r.Host) {
		oauthWriteError(w, http.StatusBadRequest, "invalid_target", "resource must be on "+r.Host)
		return
	}

	var grant *OAuthGrant
	var access, refresh string
	now := time.Now()

	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		codeHash := oauthHash(r.PostForm.Get("code"))
		verifier := r.PostForm.Get("code_verifier")

		oauthState.mu.Lock()
		oauthState.pruneLocked(now)
		ac, ok := oauthState.codes[codeHash]
		if !ok || ac.ClientID != client.ID || ac.Host != r.Host {
			oauthState.mu.Unlock()
			oauthWriteError(w, http.StatusBadRequest, "invalid_grant", "authorization code is invalid or expired")
			return
		}
		if ac.GrantID != "" {
			// Code replay: treat the tokens issued from it as compromised.
			oauthState.revokeGrantLocked(ac.GrantID)
			delete(oauthState.codes, codeHash)
			oauthState.saveLocked()
			oauthState.mu.Unlock()
			log.Printf("oauth: authorization code replayed for client %s; grant revoked", client.ID)
			oauthWriteError(w, http.StatusBadRequest, "invalid_grant", "authorization code was already used")
			return
		}
		if ru := r.PostForm.Get("redirect_uri"); ru != "" && ru != ac.RedirectURI {
			oauthState.mu.Unlock()
			oauthWriteError(w, http.StatusBadRequest, "invalid_grant", "redirect_uri does not match the authorization request")
			return
		}
		sum := sha256.Sum256([]byte(verifier))
		if verifier == "" || subtle.ConstantTimeCompare([]byte(base64.RawURLEncoding.EncodeToString(sum[:])), []byte(ac.Challenge)) != 1 {
			oauthState.mu.Unlock()
			oauthWriteError(w, http.StatusBadRequest, "invalid_grant", "PKCE verification failed")
			return
		}

		grant = &OAuthGrant{
			ID:        oauthRandomToken()[:22],
			ClientID:  client.ID,
			Host:      ac.Host,
			Claims:    ac.Claims,
			Scope:     ac.Scope,
			CreatedAt: now,
		}
		access, refresh = oauthState.issueTokensLocked(grant, now)
		grant.PrevRefreshHash = ""
		oauthState.grants[grant.ID] = grant
		ac.GrantID = grant.ID
		oauthState.saveLocked()
		oauthState.mu.Unlock()

	case "refresh_token":
		tokenHash := oauthHash(r.PostForm.Get("refresh_token"))

		oauthState.mu.Lock()
		oauthState.pruneLocked(now)
		for _, g := range oauthState.grants {
			if g.ClientID != client.ID || g.Host != r.Host {
				continue
			}
			if g.RefreshHash == tokenHash {
				grant = g
				break
			}
			if g.PrevRefreshHash != "" && g.PrevRefreshHash == tokenHash {
				// A rotated-out refresh token came back: possible theft.
				oauthState.revokeGrantLocked(g.ID)
				oauthState.saveLocked()
				log.Printf("oauth: rotated refresh token reused for client %s (%s); grant revoked", client.ID, g.Claims.Email)
				break
			}
		}
		if grant == nil {
			oauthState.mu.Unlock()
			oauthWriteError(w, http.StatusBadRequest, "invalid_grant", "refresh token is invalid, expired or revoked")
			return
		}
		// Access follows the route's current settings: stop refreshing once
		// the route is gone, no longer allows OAuth clients, or drops the user.
		if pd, ok := oauthRoute(r); !ok || !pd.userInAllowedList(grant.Claims.Email) {
			oauthState.revokeGrantLocked(grant.ID)
			oauthState.saveLocked()
			oauthState.mu.Unlock()
			oauthWriteError(w, http.StatusBadRequest, "invalid_grant", "access to this resource was removed")
			return
		}
		access, refresh = oauthState.issueTokensLocked(grant, now)
		oauthState.saveLocked()
		oauthState.mu.Unlock()

	default:
		oauthWriteError(w, http.StatusBadRequest, "unsupported_grant_type", "supported grant types: authorization_code, refresh_token")
		return
	}

	resp := map[string]interface{}{
		"access_token":  access,
		"token_type":    "Bearer",
		"expires_in":    int(oauthAccessTokenTTL / time.Second),
		"refresh_token": refresh,
	}
	if grant.Scope != "" {
		resp["scope"] = grant.Scope
	}
	oauthWriteJSON(w, http.StatusOK, resp)
}

// oauthRevokeHandler implements RFC 7009. Revoking either token ends the grant.
func oauthRevokeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		oauthWriteError(w, http.StatusMethodNotAllowed, "invalid_request", "POST required")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		oauthWriteError(w, http.StatusBadRequest, "invalid_request", "malformed form body")
		return
	}
	client := oauthAuthenticateClient(r)
	if client == nil {
		oauthWriteError(w, http.StatusUnauthorized, "invalid_client", "unknown client or bad client credentials")
		return
	}

	tokenHash := oauthHash(r.PostForm.Get("token"))
	oauthState.mu.Lock()
	grantID := ""
	if t, ok := oauthState.access[tokenHash]; ok {
		grantID = t.GrantID
	} else {
		for _, g := range oauthState.grants {
			if g.RefreshHash == tokenHash {
				grantID = g.ID
				break
			}
		}
	}
	if g, ok := oauthState.grants[grantID]; ok && g.ClientID == client.ID {
		oauthState.revokeGrantLocked(grantID)
		oauthState.saveLocked()
	}
	oauthState.mu.Unlock()

	// Per RFC 7009 the response is 200 whether or not the token existed.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(http.StatusOK)
}

// --- Resource server side (used by the proxy) ---

// oauthBearerToken extracts a bearer token from the Authorization header.
func oauthBearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) > 7 && strings.EqualFold(h[:7], "Bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}

// oauthClaimsForRequest returns the user behind a Pylon access token that is
// valid for this host, or nil.
func oauthClaimsForRequest(r *http.Request) *UserClaims {
	token := oauthBearerToken(r)
	if !strings.HasPrefix(token, oauthAccessTokenPrefix) {
		return nil
	}
	grant := oauthState.lookupAccessToken(token)
	if grant == nil || grant.Host != r.Host {
		return nil
	}
	claims := grant.Claims
	return &claims
}

// oauthWantsChallenge decides whether an unauthenticated request should get an
// OAuth 401 challenge rather than the browser login redirect.
func oauthWantsChallenge(r *http.Request) bool {
	if r.Header.Get("Authorization") != "" {
		return true
	}
	isNavigation := (r.Method == http.MethodGet || r.Method == http.MethodHead) && strings.Contains(r.Header.Get("Accept"), "text/html")
	return !isNavigation
}

func oauthWriteChallenge(w http.ResponseWriter, r *http.Request, invalidToken bool) {
	challenge := fmt.Sprintf(`Bearer resource_metadata="%s/.well-known/oauth-protected-resource"`, oauthIssuer(r))
	if invalidToken {
		challenge += `, error="invalid_token", error_description="The access token is invalid or expired"`
	}
	w.Header().Set("WWW-Authenticate", challenge)
	w.Header().Set("Access-Control-Expose-Headers", "WWW-Authenticate")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = w.Write([]byte(`{"error":"unauthorized","error_description":"Authentication required"}` + "\n"))
}

// --- Admin API (port 3001) ---

type oauthGrantInfo struct {
	ID         string    `json:"id"`
	Host       string    `json:"host"`
	Email      string    `json:"email"`
	ClientID   string    `json:"client_id"`
	ClientName string    `json:"client_name"`
	CreatedAt  time.Time `json:"created_at"`
	LastUsed   time.Time `json:"last_used"`
	ExpiresAt  time.Time `json:"expires_at"`
}

// OAuthGrantsHandler lists active OAuth client grants (GET) and revokes one
// (DELETE ?id=...).
func OAuthGrantsHandler(w http.ResponseWriter, r *http.Request) {
	enableCORS(&w, r)

	switch r.Method {
	case http.MethodOptions:
		w.WriteHeader(http.StatusOK)

	case http.MethodGet:
		oauthState.mu.Lock()
		oauthState.pruneLocked(time.Now())
		list := make([]oauthGrantInfo, 0, len(oauthState.grants))
		for _, g := range oauthState.grants {
			info := oauthGrantInfo{
				ID: g.ID, Host: g.Host, Email: g.Claims.Email, ClientID: g.ClientID,
				CreatedAt: g.CreatedAt, LastUsed: g.LastUsed, ExpiresAt: g.ExpiresAt,
			}
			if c, ok := oauthState.clients[g.ClientID]; ok {
				info.ClientName = c.Name
			}
			list = append(list, info)
		}
		oauthState.mu.Unlock()
		sort.Slice(list, func(i, j int) bool { return list[i].CreatedAt.After(list[j].CreatedAt) })

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"grants": list})

	case http.MethodDelete:
		if !oauthState.revokeGrant(r.URL.Query().Get("id")) {
			http.Error(w, "Grant not found", http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)

	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}
