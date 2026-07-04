<script lang="ts">
import { onMount } from 'svelte'
import { onboarded } from '../stores.js'
import IconButton from '@smui/icon-button'
import Textfield from '@smui/textfield'
import DataTable, { Head, Body, Row, Cell } from '@smui/data-table'
import ProxyDetail from '../lib/ProxyDetail.svelte'
import Snackbar, { Actions, Label as SnackLabel } from '@smui/snackbar'
import Button, { Icon, Label } from '@smui/button'
import LayoutGrid, { Cell as GridCell } from '@smui/layout-grid'

let config: any = null
let proxyDetail: any = null
let configSnackbar: Snackbar
let configSnackbarText = ""

// Onboarding & Tab state
let onboardStep = 1
let activeTab = 'proxies'
let newPassword = ""
let selectedProviderType = "google"

onMount(async () => {
    // Dev Mode Mock Config
    if (import.meta.env.DEV) {
        config = {
            "tldn": "bar.com",
            "allowed_users": [],
            "admin_password_hash": "",
            "insecure_skip_verify": true,
            "proxies": [
                {
                    "internal": "http://192.168.1.1:1001",
                    "external": "foo.bar.com",
                    "allowed_users": ["foo@bar.com"],
                    "unauthenticated_routes": []
                }
            ],
            "session_key": "some-session-key",
            "cookie_expire": 86400000000000,
            "oauth_providers": {},
            "onboarded": false
        }
        onboarded.set(config.onboarded)
    } else {
        // Prod Mode Fetch
        await fetchConfig()
    }
})

async function fetchConfig() {
    try {
        const res = await fetch(`/config`)
        if (res.status === 401) {
            // Browser will prompt for Basic Auth credentials
            window.location.reload()
            return
        }
        config = await res.json()
        if (!config.proxies || config.proxies.length === 0) {
            config.proxies = [{internal: null, external: null, allowed_users: [], unauthenticated_routes: []}]
        }
        onboarded.set(config.onboarded)
    } catch (err) {
        console.error("Failed to load config:", err)
    }
}

function deleteProxy(index: number) {
    config.proxies.splice(index, 1)
    if (config.proxies.length <= 0) {
        addProxy({internal: null, external: null, allowed_users: [], unauthenticated_routes: []})
    }
    config = config
}

function addProxy(proxy: any) {
    config.proxies = [...config.proxies, proxy]
}

function addProvider() {
    if (!config.oauth_providers) {
        config.oauth_providers = {}
    }
    
    // Check if type already added to make unique ID
    let count = 0
    for (let key in config.oauth_providers) {
        if (config.oauth_providers[key].type === selectedProviderType) {
            count++
        }
    }
    const provId = count === 0 ? selectedProviderType : `${selectedProviderType}_${count}`
    
    let defaultName = "Google"
    let defaultScopes = ["email", "profile"]
    
    switch (selectedProviderType) {
        case "github":
            defaultName = "GitHub"
            defaultScopes = ["read:user", "user:email"]
            break
        case "microsoft":
            defaultName = "Microsoft"
            defaultScopes = ["openid", "email", "profile"]
            break
        case "gitlab":
            defaultName = "GitLab"
            defaultScopes = ["read_user"]
            break
        case "oidc":
            defaultName = "Custom OIDC"
            defaultScopes = ["openid", "email"]
            break
    }
    
    const redirectUrl = `https://${config.tldn || 'yourdomain.com'}/pylon/callback/${provId}`
    
    config.oauth_providers[provId] = {
        id: provId,
        name: defaultName,
        type: selectedProviderType,
        client_id: "",
        client_secret: "",
        redirect_url: redirectUrl,
        scopes: defaultScopes,
        auth_url: "",
        token_url: "",
        user_info_url: ""
    }
    
    config = config
}

function removeProvider(provId: string) {
    delete config.oauth_providers[provId]
    config = config
}

async function saveConfig() {
    if (newPassword) {
        config.admin_password_hash = newPassword
    }
    
    // Update redirect URLs dynamically based on current TLDN
    if (config.oauth_providers) {
        for (let provId in config.oauth_providers) {
            config.oauth_providers[provId].redirect_url = `https://${config.tldn || 'yourdomain.com'}/pylon/callback/${provId}`
        }
    }

    if (import.meta.env.DEV) {
        configSnackbarText = "DEV MODE MOCK SAVE"
        config.onboarded = true
        onboarded.set(true)
        config = config
        configSnackbar.open()
    } else {
        try {
            const res = await fetch('/config', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(config)
            })

            let response = await res.text()
            configSnackbarText = "Pylon Status: " + response
            configSnackbar.open()
            newPassword = ""
            
            // Reload updated configuration from backend
            await fetchConfig()
        } catch (err) {
            console.error("Save error:", err)
            configSnackbarText = "Error saving config"
            configSnackbar.open()
        }
    }
}

async function registerGithubAutomatically() {
    await saveConfig()
    setTimeout(() => {
        const form = document.getElementById('github-manifest-form') as HTMLFormElement
        if (form) {
            form.submit()
        }
    }, 500)
}
</script>

<div class="main-container">
{#if config}
    {#if !config.onboarded}
        <!-- ONBOARDING WIZARD -->
        <div class="wizard-card">
            <div class="wizard-header">
                <h2>🚀 Pylon Setup Wizard</h2>
                <div class="step-indicator">
                    <div class="step {onboardStep >= 1 ? 'active' : ''}">1. Credentials</div>
                    <div class="step-line {onboardStep >= 2 ? 'active' : ''}"></div>
                    <div class="step {onboardStep >= 2 ? 'active' : ''}">2. Authentication</div>
                    <div class="step-line {onboardStep >= 3 ? 'active' : ''}"></div>
                    <div class="step {onboardStep >= 3 ? 'active' : ''}">3. Review & Lock</div>
                </div>
            </div>

            <div class="wizard-body">
                {#if onboardStep === 1}
                    <div class="step-content">
                        <h3>Set Admin Credentials</h3>
                        <p class="helper-text">Configure the primary domain and password to access this administration panel.</p>
                        
                        <div class="input-group">
                            <label for="tldn">TLD Domain Name</label>
                            <input id="tldn" type="text" placeholder="e.g. yourdomain.com" bind:value={config.tldn} />
                        </div>
                        
                        <div class="input-group">
                            <label for="admin-pass">Admin Password (Username will be 'admin')</label>
                            <input id="admin-pass" type="password" placeholder="Create admin password" bind:value={newPassword} />
                        </div>
                    </div>
                {:else if onboardStep === 2}
                    <div class="step-content">
                        <h3>Add OAuth Identity Providers</h3>
                        <p class="helper-text">Enable login providers so users can gate access to internal applications.</p>
                        
                        <div class="provider-selector">
                            <select bind:value={selectedProviderType}>
                                <option value="google">Google OAuth</option>
                                <option value="github">GitHub OAuth</option>
                                <option value="microsoft">Microsoft (Entra ID)</option>
                                <option value="gitlab">GitLab OAuth</option>
                                <option value="oidc">Custom OIDC Provider</option>
                            </select>
                            <button class="btn-primary" on:click={addProvider}>Add Provider</button>
                        </div>

                        {#if selectedProviderType === 'github'}
                            <div class="github-magic-box">
                                <span class="material-icons magic-icon">auto_awesome</span>
                                <div class="magic-text">
                                    <strong>One-Click Automated Setup:</strong> Pylon can automatically register itself as a private GitHub App on your GitHub account, configure the callback URIs, and write the generated Client ID and Client Secret keys back to your config file for you.
                                </div>
                                <button class="btn-success" on:click={registerGithubAutomatically} disabled={!config.tldn}>
                                    ⚡ Register Automatically
                                </button>
                                
                                <form action="https://github.com/settings/apps/new" method="post" id="github-manifest-form" style="display: none;">
                                    <input type="hidden" name="manifest" value={JSON.stringify({
                                        name: `Pylon Gateway (${config.tldn})`,
                                        url: `https://${config.tldn}`,
                                        hook_attributes: { active: false },
                                        redirect_url: `https://${config.tldn}/pylon/github/register`,
                                        callback_urls: [`https://${config.tldn}/pylon/callback/github`],
                                        public: false,
                                        default_permissions: {},
                                        default_events: []
                                    })} />
                                </form>
                            </div>
                        {/if}

                        {#if config.oauth_providers && Object.keys(config.oauth_providers).length > 0}
                            <div class="providers-list">
                                {#each Object.keys(config.oauth_providers) as provId}
                                    {@const prov = config.oauth_providers[provId]}
                                    <div class="provider-card">
                                        <div class="provider-card-header">
                                            <h4>{prov.name} ({prov.type})</h4>
                                            <button class="btn-danger-sm" on:click={() => removeProvider(provId)}>Remove</button>
                                        </div>
                                        
                                        <div class="input-row">
                                            <div class="input-group-half">
                                                <label>Client ID</label>
                                                <input type="text" bind:value={config.oauth_providers[provId].client_id} placeholder="OAuth Client ID" />
                                            </div>
                                            <div class="input-group-half">
                                                <label>Client Secret</label>
                                                <input type="password" bind:value={config.oauth_providers[provId].client_secret} placeholder="OAuth Client Secret" />
                                            </div>
                                        </div>

                                        <div class="input-group">
                                            <label>Redirect Callback URL (Copy this to the provider console)</label>
                                            <input type="text" readonly value={`https://${config.tldn || 'yourdomain.com'}/pylon/callback/${provId}`} class="readonly-input" />
                                        </div>

                                        {#if prov.type === 'oidc'}
                                            <div class="input-row">
                                                <div class="input-group-third">
                                                    <label>Auth URL</label>
                                                    <input type="text" bind:value={config.oauth_providers[provId].auth_url} placeholder="https://..." />
                                                </div>
                                                <div class="input-group-third">
                                                    <label>Token URL</label>
                                                    <input type="text" bind:value={config.oauth_providers[provId].token_url} placeholder="https://..." />
                                                </div>
                                                <div class="input-group-third">
                                                    <label>UserInfo URL</label>
                                                    <input type="text" bind:value={config.oauth_providers[provId].user_info_url} placeholder="https://..." />
                                                </div>
                                            </div>
                                        {/if}

                                        <!-- COLLAPSIBLE DEV GUIDELINES -->
                                        <div class="setup-guide">
                                            <h5>📝 Configuration Instructions</h5>
                                            {#if prov.type === 'google'}
                                                <ol>
                                                    <li>Go to the <a href="https://console.google.com" target="_blank" rel="noopener">Google Cloud Console</a>.</li>
                                                    <li>Select or create a project, then navigate to <strong>APIs & Services > Credentials</strong>.</li>
                                                    <li>Click <strong>Create Credentials > OAuth client ID</strong>.</li>
                                                    <li>Set Authorized redirect URIs to: <br><code>https://{config.tldn || 'yourdomain.com'}/pylon/callback/{provId}</code></li>
                                                    <li>Paste the Client ID and Client Secret above.</li>
                                                </ol>
                                            {:else if prov.type === 'github'}
                                                <ol>
                                                    <li>Go to <a href="https://github.com/settings/developers" target="_blank" rel="noopener">GitHub Developer Settings</a>.</li>
                                                    <li>Click <strong>OAuth Apps > Register a new application</strong>.</li>
                                                    <li>Set Authorization callback URL to: <br><code>https://{config.tldn || 'yourdomain.com'}/pylon/callback/{provId}</code></li>
                                                    <li>Click Register, generate a new Client Secret, and paste the keys above.</li>
                                                </ol>
                                            {:else if prov.type === 'microsoft'}
                                                <ol>
                                                    <li>Go to the <a href="https://portal.azure.com" target="_blank" rel="noopener">Azure Portal</a> and select <strong>Microsoft Entra ID</strong>.</li>
                                                    <li>Go to <strong>App registrations > New registration</strong>.</li>
                                                    <li>Select Web redirect URI and set it to: <br><code>https://{config.tldn || 'yourdomain.com'}/pylon/callback/{provId}</code></li>
                                                    <li>Go to <strong>Certificates & secrets > New client secret</strong>. Paste the secret and Client ID above.</li>
                                                </ol>
                                            {:else if prov.type === 'gitlab'}
                                                <ol>
                                                    <li>Sign in to <a href="https://gitlab.com" target="_blank" rel="noopener">GitLab</a>, go to <strong>User Settings > Applications</strong>.</li>
                                                    <li>Add a new application. Check the <code>read_user</code> scope.</li>
                                                    <li>Set redirect URI to: <br><code>https://{config.tldn || 'yourdomain.com'}/pylon/callback/{provId}</code></li>
                                                    <li>Save and paste the Application ID and Secret into the fields above.</li>
                                                </ol>
                                            {:else}
                                                <ol>
                                                    <li>Register Pylon with your OIDC client console.</li>
                                                    <li>Configure redirect URI to: <br><code>https://{config.tldn || 'yourdomain.com'}/pylon/callback/{provId}</code></li>
                                                    <li>Provide client ID, secret, Auth Endpoint, Token Endpoint, and UserInfo Endpoint above.</li>
                                                </ol>
                                            {/if}
                                        </div>
                                    </div>
                                {/each}
                            </div>
                        {:else}
                            <div class="empty-notice">No authentication providers configured. Please add at least one to continue.</div>
                        {/if}
                    </div>
                {:else if onboardStep === 3}
                    <div class="step-content">
                        <h3>Review Configuration</h3>
                        <p class="helper-text">Ensure details are correct. Clicking 'Finish' will save settings and lock the dashboard.</p>
                        
                        <div class="review-details">
                            <div class="review-row">
                                <span class="review-label">Domain Target:</span>
                                <span class="review-val">{config.tldn || 'N/A'}</span>
                            </div>
                            <div class="review-row">
                                <span class="review-label">Admin Security:</span>
                                <span class="review-val">{newPassword ? "Custom Password Set" : "⚠️ Warning: Password not set!"}</span>
                            </div>
                            <div class="review-row">
                                <span class="review-label">Configured OAuth:</span>
                                <span class="review-val">{config.oauth_providers ? Object.keys(config.oauth_providers).join(', ') : 'None'}</span>
                            </div>
                        </div>

                        <div class="onboarding-warning">
                            <span class="material-icons warning-icon">info</span>
                            <div class="warning-text">
                                <strong>Important Credentials Info:</strong> After setup, the admin dashboard will lock down. When prompted by your browser, sign in with username <code>admin</code> and your chosen password.
                            </div>
                        </div>
                    </div>
                {/if}
            </div>

            <div class="wizard-footer">
                {#if onboardStep > 1}
                    <button class="btn-secondary" on:click={() => onboardStep--}>Back</button>
                {:else}
                    <div></div>
                {/if}

                {#if onboardStep < 3}
                    <button class="btn-primary" disabled={onboardStep === 1 && (!config.tldn || !newPassword)} on:click={() => onboardStep++}>Next</button>
                {:else}
                    <button class="btn-success" disabled={!config.tldn || !config.oauth_providers || Object.keys(config.oauth_providers).length === 0} on:click={saveConfig}>Finish Setup & Lock</button>
                {/if}
            </div>
        </div>
    {:else}
        <!-- REGULAR DASHBOARD PANEL -->
        <div class="dashboard-header">
            <div class="tab-bar">
                <button class="tab-btn {activeTab === 'proxies' ? 'active' : ''}" on:click={() => activeTab = 'proxies'}>
                    <span class="material-icons">router</span> Proxy Routes
                </button>
                <button class="tab-btn {activeTab === 'settings' ? 'active' : ''}" on:click={() => activeTab = 'settings'}>
                    <span class="material-icons">settings</span> Settings & Authentication
                </button>
            </div>
        </div>

        <div class="dashboard-body">
            {#if activeTab === 'proxies'}
                <LayoutGrid style="width: 100%; padding: 0;">
                    <GridCell span={12}>
                        <table class="proxy-table">
                            <thead>
                                <tr>
                                    <th>External Address (Domain)</th>
                                    <th>Internal Address (IP/Port)</th>
                                    <th style="width: 60px;"></th>
                                    <th style="width: 60px;"></th>
                                </tr>
                            </thead>
                            <tbody>
                                {#each config.proxies as proxy, i}
                                <tr class="proxy-row">
                                    <td>
                                        <input type="text" class="proxy-input" bind:value={proxy.external} placeholder="e.g. app.hardie.dev" />
                                    </td>
                                    <td>
                                        <input type="text" class="proxy-input" bind:value={proxy.internal} placeholder="e.g. http://localhost:8080" />
                                    </td>
                                    <td class="action-cell">
                                        <button class="btn-icon-ghost" on:click={() => (proxyDetail = proxy)} aria-label="Info">
                                            <span class="material-icons">info</span>
                                        </button>
                                    </td>
                                    <td class="action-cell">
                                        <button class="btn-icon-ghost delete" on:click={() => (deleteProxy(i))} aria-label="Delete">
                                            <span class="material-icons">delete</span>
                                        </button>
                                    </td>
                                </tr>
                                {/each}
                                <tr class="add-row">
                                    <td colspan="2">
                                        <div class="action-bar">
                                            <button class="btn-success btn-icon-group" on:click={saveConfig}>
                                                <span class="material-icons">save</span>
                                                <span>Save Changes</span>
                                            </button>
                                        </div>
                                    </td>
                                    <td></td>
                                    <td class="action-cell">
                                        <button class="btn-add" on:click={() => {addProxy({internal: null, external: null, allowed_users: [], unauthenticated_routes: []})}} aria-label="Add Proxy Route">
                                            <span class="material-icons">add</span>
                                        </button>
                                    </td>
                                </tr>
                            </tbody>
                        </table>
                    </GridCell>
                </LayoutGrid>
            {:else if activeTab === 'settings'}
                <div class="settings-tab">
                    <div class="settings-section">
                        <h3>General Settings</h3>
                        <div class="input-row">
                            <div class="input-group-half">
                                <label>TLD Domain Name</label>
                                <input type="text" bind:value={config.tldn} placeholder="e.g. yourdomain.com" />
                            </div>
                            <div class="input-group-half">
                                <label>Update Admin Password (Username: 'admin')</label>
                                <input type="password" bind:value={newPassword} placeholder="New admin password" />
                            </div>
                        </div>
                        <div class="checkbox-group">
                            <label>
                                <input type="checkbox" bind:checked={config.insecure_skip_verify} />
                                Bypass TLS verification for upstream backends (InsecureSkipVerify)
                            </label>
                        </div>
                    </div>

                    <div class="settings-section">
                        <h3>OAuth Authentication Providers</h3>
                        <div class="provider-selector">
                            <select bind:value={selectedProviderType}>
                                <option value="google">Google OAuth</option>
                                <option value="github">GitHub OAuth</option>
                                <option value="microsoft">Microsoft (Entra ID)</option>
                                <option value="gitlab">GitLab OAuth</option>
                                <option value="oidc">Custom OIDC Provider</option>
                            </select>
                            <button class="btn-primary" on:click={addProvider}>Add Provider</button>
                        </div>

                        {#if selectedProviderType === 'github'}
                            <div class="github-magic-box">
                                <span class="material-icons magic-icon">auto_awesome</span>
                                <div class="magic-text">
                                    <strong>One-Click Automated Setup:</strong> Pylon can automatically register itself as a private GitHub App on your GitHub account, configure the callback URIs, and write the generated Client ID and Client Secret keys back to your config file for you.
                                </div>
                                <button class="btn-success" on:click={registerGithubAutomatically} disabled={!config.tldn}>
                                    ⚡ Register Automatically
                                </button>
                                
                                <form action="https://github.com/settings/apps/new" method="post" id="github-manifest-form" style="display: none;">
                                    <input type="hidden" name="manifest" value={JSON.stringify({
                                        name: `Pylon Gateway (${config.tldn})`,
                                        url: `https://${config.tldn}`,
                                        hook_attributes: { active: false },
                                        redirect_url: `https://${config.tldn}/pylon/github/register`,
                                        callback_urls: [`https://${config.tldn}/pylon/callback/github`],
                                        public: false,
                                        default_permissions: {},
                                        default_events: []
                                    })} />
                                </form>
                            </div>
                        {/if}

                        {#if config.oauth_providers && Object.keys(config.oauth_providers).length > 0}
                            <div class="providers-list">
                                {#each Object.keys(config.oauth_providers) as provId}
                                    {@const prov = config.oauth_providers[provId]}
                                    <div class="provider-card">
                                        <div class="provider-card-header">
                                            <h4>{prov.name} ({prov.type})</h4>
                                            <button class="btn-danger-sm" on:click={() => removeProvider(provId)}>Remove</button>
                                        </div>
                                        
                                        <div class="input-row">
                                            <div class="input-group-half">
                                                <label>Client ID</label>
                                                <input type="text" bind:value={config.oauth_providers[provId].client_id} />
                                            </div>
                                            <div class="input-group-half">
                                                <label>Client Secret</label>
                                                <input type="password" bind:value={config.oauth_providers[provId].client_secret} placeholder="••••••••••••••••" />
                                            </div>
                                        </div>

                                        <div class="input-group">
                                            <label>Redirect Callback URL</label>
                                            <input type="text" readonly value={`https://${config.tldn || 'yourdomain.com'}/pylon/callback/${provId}`} class="readonly-input" />
                                        </div>

                                        {#if prov.type === 'oidc'}
                                            <div class="input-row">
                                                <div class="input-group-third">
                                                    <label>Auth URL</label>
                                                    <input type="text" bind:value={config.oauth_providers[provId].auth_url} />
                                                </div>
                                                <div class="input-group-third">
                                                    <label>Token URL</label>
                                                    <input type="text" bind:value={config.oauth_providers[provId].token_url} />
                                                </div>
                                                <div class="input-group-third">
                                                    <label>UserInfo URL</label>
                                                    <input type="text" bind:value={config.oauth_providers[provId].user_info_url} />
                                                </div>
                                            </div>
                                        {/if}
                                    </div>
                                {/each}
                            </div>
                        {:else}
                            <div class="empty-notice">No OAuth providers configured. Authentication gateway will block access.</div>
                        {/if}
                    </div>

                    <div style="margin-top: 32px; display: flex; justify-content: flex-end;">
                        <button class="btn-success" on:click={saveConfig}>Save System Configuration</button>
                    </div>
                </div>
            {/if}

            <ProxyDetail bind:config bind:proxyDetail />
        </div>
    {/if}
{/if}

<Snackbar bind:this={configSnackbar}>
    <SnackLabel>{configSnackbarText}</SnackLabel>
    <Actions>
        <IconButton class="material-icons" title="Dismiss" style="color: white;">close</IconButton>
    </Actions>
</Snackbar>
</div>

<style>
    /* CSS Variables for Light & Dark Mode */
    :global(body) {
        --bg-main: #f8fafc;
        --text-main: #0f172a;
        --card-bg: rgba(255, 255, 255, 0.7);
        --card-border: rgba(0, 0, 0, 0.08);
        --input-bg: #ffffff;
        --input-border: #cbd5e1;
        --input-text: #0f172a;
        --helper-text: #475569;
        --step-line: #cbd5e1;
        --step-inactive: #64748b;
        --glass-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.05), 0 8px 10px -6px rgba(0, 0, 0, 0.05);
        --card-header-bg: rgba(241, 245, 249, 0.5);
        --guide-bg: rgba(241, 245, 249, 0.8);
        --guide-border: rgba(0, 0, 0, 0.05);
        --danger-bg: rgba(239, 68, 68, 0.08);
        --danger-border: rgba(239, 68, 68, 0.2);
        --magic-bg: rgba(16, 185, 129, 0.05);
        --magic-border: rgba(16, 185, 129, 0.2);
        --tab-btn-bg: #e2e8f0;
        --tab-btn-text: #475569;
        --tab-btn-active-bg: #ffffff;
        --tab-btn-active-text: #0f172a;
        --divider: #cbd5e1;
        --icon-btn-color: #64748b;
        --icon-btn-hover: #3b82f6;
        --h3-color: #0f172a;
        --review-val: #0f172a;
        --code-bg: #e2e8f0;
        --code-text: #0f172a;

        background-color: var(--bg-main) !important;
        color: var(--text-main) !important;
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif !important;
        transition: background-color 0.25s ease, color 0.25s ease !important;
        margin: 0;
    }

    :global(body.dark-mode) {
        --bg-main: #0f172a;
        --text-main: #e2e8f0;
        --card-bg: rgba(30, 41, 59, 0.4);
        --card-border: rgba(255, 255, 255, 0.08);
        --input-bg: #0f172a;
        --input-border: #334155;
        --input-text: #f1f5f9;
        --helper-text: #94a3b8;
        --step-line: #334155;
        --step-inactive: #64748b;
        --glass-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.3);
        --card-header-bg: rgba(15, 23, 42, 0.3);
        --guide-bg: rgba(15, 23, 42, 0.2);
        --guide-border: rgba(255, 255, 255, 0.05);
        --danger-bg: rgba(239, 68, 68, 0.05);
        --danger-border: rgba(239, 68, 68, 0.15);
        --magic-bg: rgba(16, 185, 129, 0.08);
        --magic-border: rgba(16, 185, 129, 0.25);
        --tab-btn-bg: #1e293b;
        --tab-btn-text: #94a3b8;
        --tab-btn-active-bg: rgba(255, 255, 255, 0.05);
        --tab-btn-active-text: #ffffff;
        --divider: #334155;
        --icon-btn-color: #94a3b8;
        --icon-btn-hover: #38bdf8;
        --h3-color: #f1f5f9;
        --review-val: #f1f5f9;
        --code-bg: #0f172a;
        --code-text: #f1f5f9;
    }

    .main-container {
        padding: 40px;
        max-width: 1200px;
        margin: 0 auto;
        min-height: calc(100vh - 120px);
    }

    /* Glassmorphism Wizard & Settings Cards */
    .wizard-card {
        background: var(--card-bg);
        backdrop-filter: blur(16px);
        -webkit-backdrop-filter: blur(16px);
        border: 1px solid var(--card-border);
        border-radius: 24px;
        padding: 40px;
        box-shadow: var(--glass-shadow);
        max-width: 800px;
        margin: 40px auto 0 auto;
        transition: background 0.3s, border-color 0.3s;
    }

    .wizard-header {
        margin-bottom: 40px;
        text-align: center;
    }

    .wizard-header h2 {
        font-size: 28px;
        margin-top: 0;
        margin-bottom: 24px;
        background: linear-gradient(to right, #38bdf8, #818cf8);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
    }

    .step-indicator {
        display: flex;
        align-items: center;
        justify-content: center;
        margin-top: 20px;
    }

    .step {
        font-size: 14px;
        font-weight: 600;
        color: var(--step-inactive);
        transition: color 0.3s;
    }

    .step.active {
        color: #38bdf8;
    }

    .step-line {
        height: 2px;
        width: 60px;
        background-color: var(--step-line);
        margin: 0 16px;
        transition: background-color 0.3s;
    }

    .step-line.active {
        background-color: #38bdf8;
    }

    .wizard-body {
        min-height: 260px;
    }

    .step-content h3 {
        font-size: 20px;
        margin-top: 0;
        margin-bottom: 8px;
        color: var(--h3-color);
    }

    .helper-text {
        font-size: 14px;
        color: var(--helper-text);
        margin-bottom: 24px;
        line-height: 1.5;
    }

    .input-group {
        display: flex;
        flex-direction: column;
        margin-bottom: 20px;
    }

    .input-group label {
        font-size: 13px;
        font-weight: 600;
        color: var(--helper-text);
        margin-bottom: 8px;
    }

    .input-group input, .input-group-half input, .input-group-third input, .provider-selector select {
        background-color: var(--input-bg);
        border: 1px solid var(--input-border);
        border-radius: 10px;
        padding: 12px 16px;
        color: var(--input-text);
        font-size: 15px;
        transition: border-color 0.2s, box-shadow 0.2s, background-color 0.2s, color 0.2s;
    }

    .input-group input:focus, .input-group-half input:focus, .input-group-third input:focus, .provider-selector select:focus {
        outline: none;
        border-color: #38bdf8;
        box-shadow: 0 0 0 3px rgba(56, 189, 248, 0.15);
    }

    .readonly-input {
        background-color: var(--tab-btn-bg) !important;
        color: var(--helper-text) !important;
        cursor: not-allowed;
    }

    .input-row {
        display: flex;
        gap: 20px;
        margin-bottom: 20px;
    }

    .input-group-half {
        flex: 1;
        display: flex;
        flex-direction: column;
    }

    .input-group-half label, .input-group-third label {
        font-size: 13px;
        font-weight: 600;
        color: var(--helper-text);
        margin-bottom: 8px;
    }

    .input-group-third {
        flex: 1;
        display: flex;
        flex-direction: column;
    }

    .provider-selector {
        display: flex;
        gap: 16px;
        margin-bottom: 30px;
    }

    .provider-selector select {
        flex: 1;
        cursor: pointer;
        -webkit-appearance: none;
        appearance: none;
        background-image: url("data:image/svg+xml;charset=UTF-8,%3csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%2364748b' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3e%3cpolyline points='6 9 12 15 18 9'%3e%3c/polyline%3e%3c/svg%3e");
        background-repeat: no-repeat;
        background-position: right 16px center;
        background-size: 16px;
        padding-right: 40px !important;
    }

    .providers-list {
        display: flex;
        flex-direction: column;
        gap: 20px;
    }

    .provider-card {
        background-color: var(--card-header-bg);
        border: 1px solid var(--card-border);
        border-radius: 16px;
        padding: 24px;
        transition: background-color 0.3s, border-color 0.3s;
    }

    .provider-card-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 20px;
        border-bottom: 1px solid var(--divider);
        padding-bottom: 12px;
    }

    .provider-card-header h4 {
        margin: 0;
        font-size: 16px;
        color: #38bdf8;
    }

    .setup-guide {
        margin-top: 20px;
        background-color: var(--guide-bg);
        border-radius: 12px;
        padding: 16px 20px;
        font-size: 13px;
        border: 1px solid var(--guide-border);
        border-left: 4px solid #818cf8;
    }

    .setup-guide h5 {
        margin-top: 0;
        margin-bottom: 10px;
        color: #a5b4fc;
        font-size: 14px;
    }

    .setup-guide ol {
        margin: 0;
        padding-left: 20px;
        color: var(--helper-text);
        line-height: 1.8;
    }

    .setup-guide a {
        color: #38bdf8;
        text-decoration: none;
    }

    .setup-guide a:hover {
        text-decoration: underline;
    }

    .setup-guide code {
        background-color: var(--code-bg);
        color: var(--code-text);
        padding: 2px 6px;
        border-radius: 4px;
        font-family: monospace;
    }

    .review-details {
        background-color: var(--card-header-bg);
        border-radius: 14px;
        padding: 20px;
        border: 1px solid var(--card-border);
    }

    .review-row {
        display: flex;
        justify-content: space-between;
        padding: 12px 0;
        border-bottom: 1px solid var(--divider);
    }

    .review-row:last-child {
        border-bottom: none;
    }

    .review-label {
        color: var(--helper-text);
        font-weight: 500;
    }

    .review-val {
        color: var(--review-val);
        font-weight: 600;
    }

    .wizard-footer {
        display: flex;
        justify-content: space-between;
        margin-top: 40px;
        border-top: 1px solid var(--divider);
        padding-top: 24px;
    }

    .empty-notice {
        text-align: center;
        color: var(--step-inactive);
        font-size: 14px;
        padding: 40px;
        border: 2px dashed var(--divider);
        border-radius: 16px;
    }

    /* Buttons Style */
    .btn-primary, .btn-secondary, .btn-success, .btn-danger-sm {
        font-family: inherit;
        font-weight: 600;
        font-size: 14px;
        padding: 10px 24px;
        border-radius: 10px;
        cursor: pointer;
        transition: filter 0.2s, transform 0.1s;
        border: none;
    }

    .btn-primary:active, .btn-secondary:active, .btn-success:active {
        transform: scale(0.98);
    }

    .btn-primary {
        background-color: #38bdf8;
        color: #0f172a;
    }

    .btn-primary:hover:not(:disabled) {
        filter: brightness(1.1);
    }

    .btn-primary:disabled {
        background-color: var(--tab-btn-bg);
        color: var(--step-inactive);
        cursor: not-allowed;
    }

    .btn-secondary {
        background-color: var(--tab-btn-bg);
        color: var(--text-main);
        border: 1px solid var(--card-border);
    }

    .btn-secondary:hover {
        filter: brightness(1.1);
    }

    .btn-success {
        background-color: #10b981;
        color: white;
    }

    .btn-success:hover:not(:disabled) {
        filter: brightness(1.1);
    }

    .btn-success:disabled {
        background-color: var(--tab-btn-bg);
        color: var(--step-inactive);
        cursor: not-allowed;
    }

    .btn-danger-sm {
        background-color: #ef4444;
        color: white;
        padding: 6px 14px;
        font-size: 12px;
        border-radius: 6px;
    }

    .btn-danger-sm:hover {
        filter: brightness(1.1);
    }

    /* Dashboard Header & Tab Styles */
    .dashboard-header {
        margin-bottom: 40px;
        border-bottom: 1px solid var(--divider);
        padding-bottom: 2px;
    }

    .tab-bar {
        display: flex;
        gap: 8px;
    }

    .tab-btn {
        background: transparent;
        border: none;
        color: var(--helper-text);
        font-family: inherit;
        font-weight: 600;
        font-size: 15px;
        padding: 12px 20px;
        cursor: pointer;
        display: flex;
        align-items: center;
        gap: 8px;
        position: relative;
        transition: color 0.2s;
    }

    .tab-btn span {
        font-size: 20px;
    }

    .tab-btn:hover {
        color: var(--text-main);
    }

    .tab-btn.active {
        color: #38bdf8;
    }

    .tab-btn.active::after {
        content: '';
        position: absolute;
        bottom: -2px;
        left: 0;
        right: 0;
        height: 2px;
        background-color: #38bdf8;
        border-radius: 2px;
    }

    .dashboard-body {
        background: var(--card-bg);
        border: 1px solid var(--card-border);
        border-radius: 20px;
        padding: 32px;
        box-shadow: var(--glass-shadow);
        transition: background 0.3s, border-color 0.3s;
    }

    /* Proxy Table Customizations */
    .proxy-table {
        width: 100%;
        border-collapse: collapse;
        text-align: left;
        margin-top: 10px;
    }

    .proxy-table th {
        color: var(--helper-text);
        font-weight: 600;
        font-size: 12px;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        padding: 12px 16px;
        border-bottom: 2px solid var(--divider);
    }

    .proxy-table td {
        padding: 12px 16px;
        vertical-align: middle;
    }

    .proxy-row {
        border-bottom: 1px solid var(--card-border);
        transition: background-color 0.2s;
    }

    .proxy-row:hover {
        background-color: var(--card-header-bg);
    }

    .proxy-input {
        width: 100%;
        background-color: var(--input-bg);
        border: 1px solid var(--input-border);
        border-radius: 8px;
        padding: 10px 14px;
        color: var(--input-text);
        font-size: 14px;
        box-sizing: border-box;
        transition: border-color 0.2s, box-shadow 0.2s, background-color 0.2s, color 0.2s;
    }

    .proxy-input:focus {
        outline: none;
        border-color: #38bdf8;
        box-shadow: 0 0 0 3px rgba(56, 189, 248, 0.15);
    }

    .action-cell {
        text-align: center;
        width: 60px;
        padding: 12px 8px !important;
    }

    .action-bar {
        display: flex;
        justify-content: flex-start;
        padding: 16px 0;
    }

    .btn-icon-group {
        display: inline-flex;
        align-items: center;
        gap: 8px;
    }
    
    .btn-icon-group span.material-icons {
        font-size: 18px;
    }

    .btn-add {
        background-color: rgba(16, 185, 129, 0.1);
        border: 1px solid rgba(16, 185, 129, 0.2);
        color: #10b981;
        width: 36px;
        height: 36px;
        border-radius: 50%;
        display: flex;
        align-items: center;
        justify-content: center;
        cursor: pointer;
        transition: all 0.2s;
        padding: 0;
        margin: 0 auto;
    }

    .btn-add:hover {
        background-color: rgba(16, 185, 129, 0.2);
        border-color: rgba(16, 185, 129, 0.4);
        transform: scale(1.05);
    }

    .btn-add:active {
        transform: scale(0.95);
    }

    .btn-add span {
        font-size: 20px;
        font-weight: 700;
    }

    .btn-icon-ghost {
        background: transparent;
        border: none;
        color: var(--icon-btn-color);
        cursor: pointer;
        padding: 6px;
        border-radius: 6px;
        display: flex;
        align-items: center;
        justify-content: center;
        transition: background-color 0.2s, color 0.2s;
        margin: 0 auto;
    }

    .btn-icon-ghost:hover {
        background-color: var(--card-header-bg);
        color: var(--icon-btn-hover);
    }

    .btn-icon-ghost.delete:hover {
        background-color: var(--danger-bg);
        color: #ef4444;
    }

    .btn-icon-ghost span {
        font-size: 20px;
    }

    /* Settings Tab */
    .settings-tab {
        display: flex;
        flex-direction: column;
        gap: 40px;
    }

    .settings-section {
        background: var(--card-header-bg);
        border-radius: 16px;
        padding: 28px;
        border: 1px solid var(--card-border);
        transition: background-color 0.3s, border-color 0.3s;
    }

    .settings-section h3 {
        margin-top: 0;
        margin-bottom: 24px;
        font-size: 18px;
        color: var(--h3-color);
        border-bottom: 1px solid var(--divider);
        padding-bottom: 12px;
    }

    .checkbox-group {
        display: flex;
        align-items: center;
        margin-top: 10px;
    }

    .checkbox-group label {
        display: flex;
        align-items: center;
        gap: 10px;
        font-size: 14px;
        color: var(--helper-text);
        cursor: pointer;
        user-select: none;
    }

    .checkbox-group input {
        cursor: pointer;
        width: 16px;
        height: 16px;
        accent-color: #38bdf8;
    }

    .onboarding-warning {
        margin-top: 24px;
        background: rgba(245, 158, 11, 0.08);
        border: 1px solid rgba(245, 158, 11, 0.25);
        border-radius: 12px;
        padding: 16px;
        display: flex;
        gap: 12px;
        align-items: flex-start;
        text-align: left;
    }

    .warning-icon {
        color: #f59e0b;
    }

    .warning-text {
        font-size: 13.5px;
        color: #fbbf24;
        line-height: 1.5;
    }

    .warning-text code {
        background-color: var(--code-bg);
        color: var(--code-text);
        padding: 2px 6px;
        border-radius: 4px;
        font-family: monospace;
        font-weight: 600;
    }

    .github-magic-box {
        margin-top: 20px;
        background: var(--magic-bg);
        border: 1px solid var(--magic-border);
        border-radius: 12px;
        padding: 20px;
        display: flex;
        flex-direction: column;
        gap: 14px;
        align-items: flex-start;
        text-align: left;
        margin-bottom: 24px;
    }

    .magic-icon {
        color: #10b981;
    }

    .magic-text {
        font-size: 13.5px;
        color: #a7f3d0;
        line-height: 1.5;
    }
</style>