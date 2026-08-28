# pylon

Pylon is an automagical reverse web proxy written in Go that handles authentication, HTTPS (via Let's Encrypt), and DNS automation for you.
This is especially useful if you want to run several services on a homelab without setting up multiple nginx proxies and manually provisioning certificates, DNS records, or custom authentication methods.

## Features:

- 🔒 **Automated HTTPS**: Automatic SSL/TLS certificates via Let's Encrypt ACME.
- 🔑 **Multi-Provider Authentication**: Support for Google, GitHub, Microsoft (Entra ID), GitLab, and custom OpenID Connect (OIDC) identity providers.
- 🌐 **DNS Provider Integrations**: Automated CNAME provisioning and DNS resolution health checks via **Cloudflare DNS API**.
- 🚀 **Admin Dashboard**: Web UI to manage routes, access controls, DNS status, and authentication settings in real time.
- 📱 **User Portal**: Fast application dashboard for authorized users to access all allowed web services.

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

- **Automated CNAME Creation**: Adding a new app (e.g. `newapp.hardie.dev`) automatically creates a CNAME record pointing to `hardie.dev` in Cloudflare.
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
| `PYLON_TLDN` | Primary top-level domain name (e.g. `hardie.dev`) |
| `PYLON_ADMIN_PASSWORD` | Admin password for port 3001 basic auth |
| `PYLON_SESSION_KEY` | Secret key used to sign session cookies |
| `PYLON_DNS_PROVIDER` | DNS provider name (e.g. `cloudflare`, `none`) |
| `PYLON_CLOUDFLARE_API_TOKEN` | Cloudflare API Bearer token |
| `PYLON_CLOUDFLARE_ZONE_ID` | Optional Cloudflare Zone ID override |
| `PYLON_CLOUDFLARE_PROXIED` | Enable Cloudflare CDN proxy (`true` / `false`) |
| `PYLON_DNS_TARGET` | CNAME target override (defaults to `PYLON_TLDN`) |
| `PYLON_DNS_AUTO_SYNC` | Auto-create DNS records on save (`true` / `false`) |
