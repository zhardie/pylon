# pylon

Pylon is an automagical reverse web proxy written in Go that handles authentication, HTTPS (via Let's Encrypt), and DNS automation for you.
This is especially useful if you want to run several services on a homelab without setting up multiple nginx proxies and manually provisioning certificates, DNS records, or custom authentication methods.

## Features:

- 🔒 **Automated HTTPS**: Automatic SSL/TLS certificates via Let's Encrypt ACME.
- 🔑 **Multi-Provider Authentication**: Support for Google, GitHub, Microsoft (Entra ID), GitLab, and custom OpenID Connect (OIDC) identity providers.
- 🌐 **DNS Provider Integrations**: Automated CNAME provisioning and DNS resolution health checks via **Cloudflare DNS API**.
- 🚀 **Admin Dashboard**: Web UI to manage routes, access controls, DNS status, and authentication settings in real time.
- 📱 **User Portal**: Fast application dashboard for authorized users to access all allowed web services.
- 🤖 **OAuth for MCP Connectors**: Pylon can act as an OAuth 2.1 authorization server so clients like Claude can reach MCP servers behind it.
- 👤 **Identity Forwarding & User Claims**: Protected SPAs and backend services can piggyback off Pylon auth via `/pylon/claims` or injected `X-Pylon-*` request headers.

## Prerequisites:

1. An account with one of the supported OAuth identity providers (Google, GitHub, Microsoft, GitLab, or OIDC).
2. A domain name with DNS managed by a supported provider (e.g. Cloudflare) or pointed to your server.

## Quick Start:

1. Create a `config.json` (or use environment variables):
   ```json
   {
       "tldn": "yourdomain.com",
       "session_key": "generate_a_random_secret_key_here",
       "dns": {
           "provider": "cloudflare",
           "api_token": "your_cloudflare_api_token",
           "target": "yourdomain.com",
           "proxied": false,
           "auto_sync": true
       }
   }
   ```

2. Fire up the proxy server:
   ```bash
   docker run -d \
     -v ~/pylon/certs:/certs \
     -v ~/pylon/config:/config \
     -p 80:80 \
     -p 443:443 \
     -p 3001:3001 \
     zhardie/pylon:latest
   ```

3. Open `http://localhost:3001` to access the administration dashboard.

## DNS Provider Integration (Cloudflare):

Pylon can automatically configure DNS records whenever you add or edit proxy routes:

- **Automated CNAME Creation**: Adding a new app (e.g. `newapp.yourdomain.com`) automatically creates a CNAME record pointing to `yourdomain.com` in Cloudflare.
- **DNS Health Check**: The admin dashboard verifies DNS resolution for all configured routes on load.
- **One-Click Missing Record Resolution**: Warning indicators highlight missing DNS records with a one-click button to resolve them directly in Cloudflare.
- **Batch DNS Sync**: Sync all configured proxy routes to Cloudflare in a single click.

### Cloudflare API Token Permissions:
Create a custom API token in the [Cloudflare Dashboard](https://dash.cloudflare.com/profile/api-tokens) with the following permissions:
- `Zone - DNS - Edit`
- `Zone - Zone - Read`

### Environment Variables:

| Variable | Description |
|---|---|
| `PYLON_TLDN` | Primary top-level domain name (e.g. `yourdomain.com`) |
| `PYLON_ADMIN_PASSWORD` | Admin password for port 3001 basic auth |
| `PYLON_SESSION_KEY` | Secret key used to sign session cookies |
| `PYLON_DNS_PROVIDER` | DNS provider name (e.g. `cloudflare`, `none`) |
| `PYLON_CLOUDFLARE_API_TOKEN` | Cloudflare API Bearer token |
| `PYLON_CLOUDFLARE_ZONE_ID` | Optional Cloudflare Zone ID override |
| `PYLON_CLOUDFLARE_PROXIED` | Enable Cloudflare CDN proxy (`true` / `false`) |
| `PYLON_DNS_TARGET` | CNAME target override (defaults to `PYLON_TLDN`) |
| `PYLON_DNS_AUTO_SYNC` | Auto-create DNS records on save (`true` / `false`) |

## App Identity & Claims (Piggybacking on Pylon Auth)

Apps protected behind Pylon can easily access the identity of the signed-in user without running their own OAuth flows:

### 1. Frontend SPAs (`GET /pylon/claims`)
Client-side apps on any protected subdomain can make a same-origin `fetch('/pylon/claims')`. Because the session cookie is scoped to your root domain, the browser automatically attaches it:

```javascript
const res = await fetch('/pylon/claims');
if (res.ok) {
    const user = await res.json();
    console.log(user);
    // {
    //   "authenticated": true,
    //   "id": "109283746528192847",
    //   "email": "user@example.com",
    //   "first_name": "Jane",
    //   "last_name": "Doe",
    //   "name": "Jane Doe",
    //   "provider": "google"
    // }
}
```
If the user is not authenticated, `/pylon/claims` returns HTTP `401 Unauthorized` with `{"authenticated": false, "error": "unauthorized"}`.

### 2. Upstream Backend Headers
When Pylon proxies requests to internal services, it strips untrusted client headers and automatically injects verified user identity headers:

- `X-Pylon-User-Id`: Immutable user identifier from the auth provider (e.g., Google sub, GitHub numerical ID, Microsoft GUID)
- `X-Pylon-User-Email`: User email address
- `X-Pylon-User-First-Name`: First / given name
- `X-Pylon-User-Last-Name`: Last / family name
- `X-Pylon-User-Name`: Full display name
- `X-Pylon-User-Avatar`: Avatar URL (if provided)
- `X-Pylon-User-Provider`: Identity provider type (e.g., `google`, `github`, `microsoft`, `gitlab`, `oidc`)
- `X-Forwarded-User` & `X-Forwarded-Email`: Standard reverse-proxy user headers

## OAuth Clients & MCP Servers

Browser sessions don't work for non-browser clients such as Claude's custom connectors, which authenticate to remote MCP servers with OAuth. Pylon can be the OAuth 2.1 authorization server for a route, so an MCP server with no authentication of its own can sit safely behind it.

### Setup
1. Add a proxy route for the MCP server (e.g. `unraid-mcp.yourdomain.com` → `http://192.168.1.20:8080`).
2. Open the route's advanced settings, add the emails allowed to use it under **Authorized User Emails**, and enable **Allow OAuth clients on this route** (or set `"allow_oauth_clients": true` on the route in `config.json`).
3. In Claude, add a custom connector with the MCP server's URL, e.g. `https://unraid-mcp.yourdomain.com/mcp`. Claude discovers Pylon's OAuth endpoints, registers itself, and sends you to Pylon to sign in with your identity provider and approve the connection.

> Leave **Authorized User Emails** empty and *anyone* who can sign in to your identity provider (e.g. any Google account) can connect a client. Always list the allowed users on MCP routes.

### How it works
On routes with `allow_oauth_clients`, each host is its own OAuth issuer:

| Endpoint | Purpose |
|---|---|
| `/.well-known/oauth-protected-resource` | Protected resource metadata (RFC 9728) |
| `/.well-known/oauth-authorization-server` | Authorization server metadata (RFC 8414) |
| `/pylon/oauth/register` | Dynamic client registration (RFC 7591) |
| `/pylon/oauth/authorize` | Authorization code flow with mandatory PKCE (S256) and a consent page |
| `/pylon/oauth/token` | Code exchange and refresh (refresh tokens rotate) |
| `/pylon/oauth/revoke` | Token revocation (RFC 7009) |

- Unauthenticated non-browser requests get `401` with a `WWW-Authenticate: Bearer resource_metadata=...` challenge; browsers still get the login redirect.
- Access tokens last 1 hour and are valid only for the host they were issued for. Refresh tokens expire after 30 days without use.
- The route's allowed users are enforced on every request and refresh, so removing a user cuts off their clients.
- Pylon consumes its token and forwards the same `X-Pylon-*` identity headers as for browser sessions; the upstream never sees the token.
- Registered clients and grants are stored (tokens hashed) in `oauth_state.json` next to `config.json`, so connections survive restarts.
- Connected clients are listed in the route's advanced settings in the admin dashboard, where they can be revoked.

### Upstream credentials
If the internal service needs its own credential (for example an MCP server that expects an API key), add it under **Upstream Request Headers** in the route's advanced settings, or in `config.json`:

```json
{
    "internal": "http://192.168.1.20:8080",
    "external": "unraid-mcp.yourdomain.com",
    "allowed_users": ["you@yourdomain.com"],
    "allow_oauth_clients": true,
    "upstream_headers": { "Authorization": "Bearer your-upstream-api-key" }
}
```

Pylon adds these headers to every request it has authenticated (browser session or OAuth token) and never on unauthenticated bypass routes, so the client only ever holds a Pylon token and the upstream key stays on the server.
