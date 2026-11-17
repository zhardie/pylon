package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const oauthTestHost = "mcp.example.com"

// setupOAuthTest configures an OAuth-enabled route in front of a fake upstream
// that echoes the identity and Authorization headers it receives.
func setupOAuthTest(t *testing.T, allowedUsers []string) {
	t.Helper()
	setupTestConfig()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Seen-Email", r.Header.Get("X-Pylon-User-Email"))
		w.Header().Set("X-Seen-Authorization", r.Header.Get("Authorization"))
		w.Write([]byte("upstream ok"))
	}))
	t.Cleanup(upstream.Close)
	u, _ := url.Parse(upstream.URL)

	proxiesMu.Lock()
	proxies = map[string]*ProxyDetails{
		oauthTestHost: {
			Internal:                   upstream.URL,
			AllowedUsers:               allowedUsers,
			UnauthenticatedRoutesRegex: regexp.MustCompile(""),
			ReverseProxy:               httputil.NewSingleHostReverseProxy(u),
			OAuthEnabled:               true,
		},
		"plain.example.com": {
			Internal:                   upstream.URL,
			UnauthenticatedRoutesRegex: regexp.MustCompile(""),
			ReverseProxy:               httputil.NewSingleHostReverseProxy(u),
		},
	}
	proxiesMu.Unlock()

	oauthState = newOAuthStore()
}

func serve(req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	mainProxyHandler(rec, req)
	return rec
}

func registerTestClient(t *testing.T, body string) map[string]interface{} {
	t.Helper()
	req := httptest.NewRequest("POST", "https://"+oauthTestHost+"/pylon/oauth/register", strings.NewReader(body))
	rec := serve(req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("register: status %d: %s", rec.Code, rec.Body.String())
	}
	var out map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func pkcePair() (verifier, challenge string) {
	verifier = "test-verifier-0123456789-0123456789-0123456789-abc"
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:])
}

func authorizeQuery(clientID, redirectURI, challenge string) url.Values {
	return url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {redirectURI},
		"state":                 {"xyz&state"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"resource":              {"https://" + oauthTestHost + "/mcp"},
	}
}

var hiddenInputRe = regexp.MustCompile(`<input type="hidden" name="([^"]+)" value="([^"]*)">`)

// approveConsent loads the consent page as email and submits the decision.
func approveConsent(t *testing.T, q url.Values, email, decision string) *httptest.ResponseRecorder {
	t.Helper()
	target := "https://" + oauthTestHost + "/pylon/oauth/authorize"
	rec := serve(createAuthenticatedRequest("GET", target+"?"+q.Encode(), email))
	if rec.Code != http.StatusOK {
		t.Fatalf("consent page: status %d: %s", rec.Code, rec.Body.String())
	}
	form := url.Values{"decision": {decision}}
	for _, m := range hiddenInputRe.FindAllStringSubmatch(rec.Body.String(), -1) {
		form.Set(m[1], strings.NewReplacer("&amp;", "&", "&#34;", `"`, "&#39;", "'", "&lt;", "<", "&gt;", ">").Replace(m[2]))
	}
	post := httptest.NewRequest("POST", target, strings.NewReader(form.Encode()))
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	post.Header.Set("Cookie", createAuthenticatedRequest("GET", target, email).Header.Get("Cookie"))
	return serve(post)
}

func tokenRequest(form url.Values) (*httptest.ResponseRecorder, map[string]interface{}) {
	req := httptest.NewRequest("POST", "https://"+oauthTestHost+"/pylon/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := serve(req)
	var out map[string]interface{}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec, out
}

// obtainTokens runs registration, consent and code exchange for email.
func obtainTokens(t *testing.T, email string) (clientID string, tokens map[string]interface{}) {
	t.Helper()
	const redirectURI = "https://claude.ai/api/mcp/auth_callback"
	client := registerTestClient(t, `{"client_name":"Claude","redirect_uris":["`+redirectURI+`"],"token_endpoint_auth_method":"none"}`)
	clientID = client["client_id"].(string)
	verifier, challenge := pkcePair()

	rec := approveConsent(t, authorizeQuery(clientID, redirectURI, challenge), email, "approve")
	if rec.Code != http.StatusFound {
		t.Fatalf("approve: status %d: %s", rec.Code, rec.Body.String())
	}
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if !strings.HasPrefix(loc.String(), redirectURI+"?") || loc.Query().Get("state") != "xyz&state" {
		t.Fatalf("unexpected redirect: %s", loc)
	}

	rec, tokens = tokenRequest(url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {loc.Query().Get("code")},
		"client_id":     {clientID},
		"redirect_uri":  {redirectURI},
		"code_verifier": {verifier},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("token: status %d: %s", rec.Code, rec.Body.String())
	}
	return clientID, tokens
}

func bearerRequest(host, token string) *http.Request {
	req := httptest.NewRequest("POST", "https://"+host+"/mcp", strings.NewReader("{}"))
	req.Header.Set("Accept", "application/json, text/event-stream")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return req
}

func TestOAuth_Metadata(t *testing.T) {
	setupOAuthTest(t, nil)

	rec := serve(httptest.NewRequest("GET", "https://"+oauthTestHost+"/.well-known/oauth-protected-resource/mcp", nil))
	var prm map[string]interface{}
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &prm) != nil {
		t.Fatalf("protected resource metadata: %d %s", rec.Code, rec.Body.String())
	}
	if prm["resource"] != "https://"+oauthTestHost+"/mcp" {
		t.Errorf("resource = %v", prm["resource"])
	}
	if as := prm["authorization_servers"].([]interface{}); len(as) != 1 || as[0] != "https://"+oauthTestHost {
		t.Errorf("authorization_servers = %v", as)
	}

	rec = serve(httptest.NewRequest("GET", "https://"+oauthTestHost+"/.well-known/oauth-authorization-server", nil))
	var asm map[string]interface{}
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &asm) != nil {
		t.Fatalf("server metadata: %d %s", rec.Code, rec.Body.String())
	}
	if asm["issuer"] != "https://"+oauthTestHost || asm["token_endpoint"] != "https://"+oauthTestHost+"/pylon/oauth/token" {
		t.Errorf("unexpected server metadata: %v", asm)
	}
}

func TestOAuth_DisabledRouteIsUntouched(t *testing.T) {
	setupOAuthTest(t, nil)

	// OAuth endpoints do not exist on routes that have not opted in.
	rec := serve(httptest.NewRequest("POST", "https://plain.example.com/pylon/oauth/register", strings.NewReader(`{}`)))
	if rec.Code != http.StatusNotFound {
		t.Errorf("register on plain route: status %d", rec.Code)
	}
	// Unauthenticated API-style requests still get the login redirect.
	rec = serve(bearerRequest("plain.example.com", ""))
	if rec.Code != http.StatusFound || rec.Header().Get("WWW-Authenticate") != "" {
		t.Errorf("plain route: status %d, challenge %q", rec.Code, rec.Header().Get("WWW-Authenticate"))
	}
	// A token for another host is not accepted and is passed over, not honoured.
	_, tokens := obtainTokens(t, "alice@example.com")
	rec = serve(bearerRequest("plain.example.com", tokens["access_token"].(string)))
	if rec.Code != http.StatusFound {
		t.Errorf("token on plain route: status %d", rec.Code)
	}
}

func TestOAuth_Challenge(t *testing.T) {
	setupOAuthTest(t, nil)

	rec := serve(bearerRequest(oauthTestHost, ""))
	want := `Bearer resource_metadata="https://` + oauthTestHost + `/.well-known/oauth-protected-resource"`
	if rec.Code != http.StatusUnauthorized || rec.Header().Get("WWW-Authenticate") != want {
		t.Errorf("status %d, challenge %q", rec.Code, rec.Header().Get("WWW-Authenticate"))
	}

	rec = serve(bearerRequest(oauthTestHost, oauthAccessTokenPrefix+"bogus"))
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Header().Get("WWW-Authenticate"), `error="invalid_token"`) {
		t.Errorf("bogus token: status %d, challenge %q", rec.Code, rec.Header().Get("WWW-Authenticate"))
	}

	// Browsers still get the login redirect.
	req := httptest.NewRequest("GET", "https://"+oauthTestHost+"/", nil)
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	if rec = serve(req); rec.Code != http.StatusFound {
		t.Errorf("browser: status %d", rec.Code)
	}
}

func TestOAuth_FullFlow(t *testing.T) {
	setupOAuthTest(t, []string{"alice@example.com"})
	clientID, tokens := obtainTokens(t, "alice@example.com")
	access := tokens["access_token"].(string)
	refresh := tokens["refresh_token"].(string)

	rec := serve(bearerRequest(oauthTestHost, access))
	if rec.Code != 200 || rec.Body.String() != "upstream ok" {
		t.Fatalf("proxied request: %d %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("X-Seen-Email"); got != "alice@example.com" {
		t.Errorf("upstream saw email %q", got)
	}
	if got := rec.Header().Get("X-Seen-Authorization"); got != "" {
		t.Errorf("pylon token leaked upstream: %q", got)
	}

	// Refresh rotates the refresh token.
	rec, refreshed := tokenRequest(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}, "client_id": {clientID}})
	if rec.Code != 200 || refreshed["refresh_token"] == refresh {
		t.Fatalf("refresh: %d %s", rec.Code, rec.Body.String())
	}
	if rec = serve(bearerRequest(oauthTestHost, refreshed["access_token"].(string))); rec.Code != 200 {
		t.Errorf("refreshed access token: status %d", rec.Code)
	}

	// Reusing the rotated-out refresh token revokes the whole grant.
	if rec, _ = tokenRequest(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}, "client_id": {clientID}}); rec.Code != 400 {
		t.Errorf("reused refresh token: status %d", rec.Code)
	}
	if rec = serve(bearerRequest(oauthTestHost, refreshed["access_token"].(string))); rec.Code != http.StatusUnauthorized {
		t.Errorf("access token after grant revoked: status %d", rec.Code)
	}
}

func TestOAuth_AuthorizeRequiresLoginAndAllowedUser(t *testing.T) {
	setupOAuthTest(t, []string{"alice@example.com"})
	const redirectURI = "https://claude.ai/api/mcp/auth_callback"
	client := registerTestClient(t, `{"redirect_uris":["`+redirectURI+`"],"token_endpoint_auth_method":"none"}`)
	_, challenge := pkcePair()
	q := authorizeQuery(client["client_id"].(string), redirectURI, challenge)
	target := "https://" + oauthTestHost + "/pylon/oauth/authorize?" + q.Encode()

	// No session: through the login gateway and back to the same request.
	rec := serve(httptest.NewRequest("GET", target, nil))
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if rec.Code != http.StatusFound || loc.Path != "/pylon/login" {
		t.Fatalf("unauthenticated authorize: %d %s", rec.Code, loc)
	}
	if got := "https://" + loc.Query().Get("referer"); got != target {
		t.Errorf("referer round trip:\n got %s\nwant %s", got, target)
	}

	// Signed in but not on the route's allow list.
	if rec = serve(createAuthenticatedRequest("GET", target, "mallory@example.com")); rec.Code != http.StatusForbidden {
		t.Errorf("disallowed user: status %d", rec.Code)
	}

	// Deny goes back to the client with an error, not a code.
	rec = approveConsent(t, q, "alice@example.com", "deny")
	loc, _ = url.Parse(rec.Header().Get("Location"))
	if loc.Query().Get("error") != "access_denied" || loc.Query().Get("code") != "" {
		t.Errorf("deny redirect: %s", loc)
	}

	// A POST without a valid consent token (cross-site forgery) issues nothing.
	form := url.Values{"decision": {"approve"}, "consent_token": {"9999999999.deadbeef"}}
	for k, v := range q {
		form[k] = v
	}
	post := httptest.NewRequest("POST", "https://"+oauthTestHost+"/pylon/oauth/authorize", strings.NewReader(form.Encode()))
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	post.Header.Set("Cookie", createAuthenticatedRequest("GET", target, "alice@example.com").Header.Get("Cookie"))
	if rec = serve(post); rec.Code != http.StatusBadRequest || rec.Header().Get("Location") != "" {
		t.Errorf("forged consent: status %d location %q", rec.Code, rec.Header().Get("Location"))
	}
}

func TestOAuth_AuthorizeRejectsBadRequests(t *testing.T) {
	setupOAuthTest(t, nil)
	const redirectURI = "https://claude.ai/api/mcp/auth_callback"
	client := registerTestClient(t, `{"redirect_uris":["`+redirectURI+`"],"token_endpoint_auth_method":"none"}`)
	clientID := client["client_id"].(string)
	_, challenge := pkcePair()
	get := func(q url.Values) *httptest.ResponseRecorder {
		return serve(createAuthenticatedRequest("GET", "https://"+oauthTestHost+"/pylon/oauth/authorize?"+q.Encode(), "alice@example.com"))
	}

	// Unregistered redirect URI: never redirect there.
	q := authorizeQuery(clientID, "https://evil.example.net/cb", challenge)
	if rec := get(q); rec.Code != http.StatusBadRequest || rec.Header().Get("Location") != "" {
		t.Errorf("bad redirect_uri: status %d location %q", rec.Code, rec.Header().Get("Location"))
	}

	// Missing PKCE.
	q = authorizeQuery(clientID, redirectURI, challenge)
	q.Del("code_challenge")
	if rec := get(q); !strings.Contains(rec.Header().Get("Location"), "error=invalid_request") {
		t.Errorf("missing PKCE: %d %q", rec.Code, rec.Header().Get("Location"))
	}

	// Resource on a different host.
	q = authorizeQuery(clientID, redirectURI, challenge)
	q.Set("resource", "https://plain.example.com/mcp")
	if rec := get(q); !strings.Contains(rec.Header().Get("Location"), "error=invalid_target") {
		t.Errorf("foreign resource: %d %q", rec.Code, rec.Header().Get("Location"))
	}
}

func TestOAuth_TokenEndpointChecks(t *testing.T) {
	setupOAuthTest(t, nil)
	const redirectURI = "http://127.0.0.1:1234/callback"
	client := registerTestClient(t, `{"redirect_uris":["`+redirectURI+`"],"token_endpoint_auth_method":"none"}`)
	clientID := client["client_id"].(string)
	verifier, challenge := pkcePair()

	newCode := func() string {
		// Loopback clients may come back on a different port.
		q := authorizeQuery(clientID, "http://127.0.0.1:55555/callback", challenge)
		rec := approveConsent(t, q, "alice@example.com", "approve")
		loc, _ := url.Parse(rec.Header().Get("Location"))
		if loc.Host != "127.0.0.1:55555" || loc.Query().Get("code") == "" {
			t.Fatalf("approve redirect: %d %s", rec.Code, loc)
		}
		return loc.Query().Get("code")
	}

	// Wrong PKCE verifier.
	rec, _ := tokenRequest(url.Values{"grant_type": {"authorization_code"}, "code": {newCode()}, "client_id": {clientID}, "code_verifier": {"wrong"}})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("wrong verifier: status %d", rec.Code)
	}

	// Code replay fails and revokes the tokens from the first exchange.
	code := newCode()
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "client_id": {clientID}, "code_verifier": {verifier}}
	rec, tokens := tokenRequest(form)
	if rec.Code != 200 {
		t.Fatalf("first exchange: %d %s", rec.Code, rec.Body.String())
	}
	if rec, _ = tokenRequest(form); rec.Code != http.StatusBadRequest {
		t.Errorf("replayed code: status %d", rec.Code)
	}
	if rec = serve(bearerRequest(oauthTestHost, tokens["access_token"].(string))); rec.Code != http.StatusUnauthorized {
		t.Errorf("token after code replay: status %d", rec.Code)
	}

	// Unknown client.
	if rec, _ = tokenRequest(url.Values{"grant_type": {"authorization_code"}, "code": {"x"}, "client_id": {"nope"}}); rec.Code != http.StatusUnauthorized {
		t.Errorf("unknown client: status %d", rec.Code)
	}
}

func TestOAuth_ConfidentialClientNeedsSecret(t *testing.T) {
	setupOAuthTest(t, nil)
	const redirectURI = "https://claude.ai/api/mcp/auth_callback"
	client := registerTestClient(t, `{"redirect_uris":["`+redirectURI+`"],"token_endpoint_auth_method":"client_secret_post"}`)
	clientID, secret := client["client_id"].(string), client["client_secret"].(string)
	verifier, challenge := pkcePair()

	code := func() string {
		rec := approveConsent(t, authorizeQuery(clientID, redirectURI, challenge), "alice@example.com", "approve")
		loc, _ := url.Parse(rec.Header().Get("Location"))
		return loc.Query().Get("code")
	}
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code()}, "client_id": {clientID}, "code_verifier": {verifier}}
	if rec, _ := tokenRequest(form); rec.Code != http.StatusUnauthorized {
		t.Errorf("missing secret: status %d", rec.Code)
	}
	form.Set("client_secret", secret)
	if rec, _ := tokenRequest(form); rec.Code != 200 {
		t.Errorf("with secret: status %d %s", rec.Code, rec.Body.String())
	}
}

func TestOAuth_RegisterRejectsBadRedirects(t *testing.T) {
	setupOAuthTest(t, nil)
	for _, uri := range []string{"http://evil.example.net/cb", "javascript:alert(1)", "https://ok.example.net/cb#frag", "not a url"} {
		req := httptest.NewRequest("POST", "https://"+oauthTestHost+"/pylon/oauth/register", strings.NewReader(`{"redirect_uris":["`+uri+`"]}`))
		if rec := serve(req); rec.Code != http.StatusBadRequest {
			t.Errorf("redirect uri %q accepted: status %d", uri, rec.Code)
		}
	}
}

func TestOAuth_AccessFollowsAllowList(t *testing.T) {
	setupOAuthTest(t, []string{"alice@example.com"})
	clientID, tokens := obtainTokens(t, "alice@example.com")

	// Remove alice from the route.
	proxiesMu.Lock()
	proxies[oauthTestHost].AllowedUsers = []string{"bob@example.com"}
	proxiesMu.Unlock()

	if rec := serve(bearerRequest(oauthTestHost, tokens["access_token"].(string))); rec.Code != http.StatusForbidden {
		t.Errorf("removed user: status %d", rec.Code)
	}
	rec, _ := tokenRequest(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tokens["refresh_token"].(string)}, "client_id": {clientID}})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("refresh for removed user: status %d", rec.Code)
	}
}

func TestOAuth_PersistenceAndAdminRevoke(t *testing.T) {
	setupOAuthTest(t, nil)
	path := filepath.Join(t.TempDir(), "oauth_state.json")
	if err := oauthState.load(path); err != nil {
		t.Fatal(err)
	}
	clientID, tokens := obtainTokens(t, "alice@example.com")

	// Simulate a restart: access tokens are gone, the refresh token still works.
	oauthState = newOAuthStore()
	if err := oauthState.load(path); err != nil {
		t.Fatal(err)
	}
	if rec := serve(bearerRequest(oauthTestHost, tokens["access_token"].(string))); rec.Code != http.StatusUnauthorized {
		t.Errorf("access token after restart: status %d", rec.Code)
	}
	rec, refreshed := tokenRequest(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tokens["refresh_token"].(string)}, "client_id": {clientID}})
	if rec.Code != 200 {
		t.Fatalf("refresh after restart: %d %s", rec.Code, rec.Body.String())
	}

	// Admin lists and revokes the grant.
	adminRec := httptest.NewRecorder()
	OAuthGrantsHandler(adminRec, httptest.NewRequest("GET", "/oauth/grants", nil))
	var list struct {
		Grants []oauthGrantInfo `json:"grants"`
	}
	if err := json.Unmarshal(adminRec.Body.Bytes(), &list); err != nil || len(list.Grants) != 1 {
		t.Fatalf("grants list: %s", adminRec.Body.String())
	}
	if g := list.Grants[0]; g.Email != "alice@example.com" || g.ClientName != "Claude" || g.Host != oauthTestHost {
		t.Errorf("unexpected grant: %+v", g)
	}
	adminRec = httptest.NewRecorder()
	OAuthGrantsHandler(adminRec, httptest.NewRequest("DELETE", "/oauth/grants?id="+list.Grants[0].ID, nil))
	if adminRec.Code != http.StatusNoContent {
		t.Errorf("revoke: status %d", adminRec.Code)
	}
	if rec := serve(bearerRequest(oauthTestHost, refreshed["access_token"].(string))); rec.Code != http.StatusUnauthorized {
		t.Errorf("access token after admin revoke: status %d", rec.Code)
	}
}

func TestLoginGateway_EscapesReferer(t *testing.T) {
	setupTestConfig()
	cfgMu.Lock()
	cfg.OAuthProviders = map[string]OAuthProvider{"google": {ID: "google", Type: "google"}}
	cfgMu.Unlock()

	referer := "mcp.example.com/pylon/oauth/authorize?client_id=a&state=b"
	req := httptest.NewRequest("GET", "https://mcp.example.com/pylon/login?referer="+url.QueryEscape(referer), nil)
	rec := serve(req)
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if got := loc.Query().Get("referer"); got != referer {
		t.Errorf("referer = %q, want %q", got, referer)
	}
}
