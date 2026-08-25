<script lang="ts">
import { onMount } from 'svelte'

interface AppItem {
  name: string
  external: string
  url: string
  icon: string
  description: string
}

let appItems: AppItem[] = []
let searchQuery = ""
let viewMode: 'grid' | 'list' = 'grid'
let loading = true

$: filteredApps = appItems.filter(app => {
  if (!searchQuery.trim()) return true
  const q = searchQuery.toLowerCase()
  return (
    app.name.toLowerCase().includes(q) ||
    app.external.toLowerCase().includes(q) ||
    app.description.toLowerCase().includes(q)
  )
})

onMount(async () => {
  const savedView = localStorage.getItem('pylon_svelte_view')
  if (savedView === 'list' || savedView === 'grid') {
    viewMode = savedView
  }

  if (import.meta.env.DEV) {
    appItems = [
      { name: "Grafana", external: "grafana.hardie.dev", url: "https://grafana.hardie.dev", icon: "insights", description: "Monitoring" },
      { name: "Home Assistant", external: "hass.hardie.dev", url: "https://hass.hardie.dev", icon: "home", description: "Smart Home" },
      { name: "Jellyfin", external: "jellyfin.hardie.dev", url: "https://jellyfin.hardie.dev", icon: "movie", description: "Media" },
      { name: "Vaultwarden", external: "vault.hardie.dev", url: "https://vault.hardie.dev", icon: "lock", description: "Security" },
      { name: "Nextcloud", external: "drive.hardie.dev", url: "https://drive.hardie.dev", icon: "cloud", description: "Cloud Storage" },
      { name: "GitLab", external: "git.hardie.dev", url: "https://git.hardie.dev", icon: "code", description: "Development" },
      { name: "Portainer", external: "docker.hardie.dev", url: "https://docker.hardie.dev", icon: "layers", description: "Infrastructure" },
      { name: "Uptime Kuma", external: "status.hardie.dev", url: "https://status.hardie.dev", icon: "query_stats", description: "Status" }
    ]
    loading = false
    return
  }

  try {
    const res = await fetch('/pylon/api/apps')
    if (res.ok) {
      const data = await res.json()
      if (data.items && data.items.length > 0) {
        appItems = data.items
      } else if (data.apps && data.apps.length > 0) {
        appItems = data.apps.map((app: string) => formatFallbackApp(app))
      }
    } else {
      // Fallback to legacy endpoint
      const legacyRes = await fetch('/8ef55d02bd174c29177d5618bfb3a2f3/allowedApps')
      if (legacyRes.ok) {
        const legacyData = await legacyRes.json()
        if (legacyData.apps) {
          appItems = legacyData.apps.map((app: string) => formatFallbackApp(app))
        }
      }
    }
  } catch (err) {
    console.error("Failed to load apps:", err)
  } finally {
    loading = false
  }
})

function formatFallbackApp(external: string): AppItem {
  const clean = external.replace(/^https?:\/\//, '').replace(/\/$/, '')
  const host = clean.split('/')[0].split(':')[0]
  const sub = host.split('.')[0]
  const name = sub.charAt(0).toUpperCase() + sub.slice(1)
  return {
    name: name || clean,
    external: clean,
    url: 'https://' + clean,
    icon: 'apps',
    description: 'Application'
  }
}

function setView(mode: 'grid' | 'list') {
  viewMode = mode
  localStorage.setItem('pylon_svelte_view', mode)
}
</script>

<div class="dashboard-container">
  <div class="header-section">
    <div>
      <h1 class="page-title">Applications Portal</h1>
      <p class="page-subtitle">Access all identity-gated services authorized for your account.</p>
    </div>
  </div>

  <div class="toolbar">
    <div class="search-wrap">
      <span class="material-icons search-icon">search</span>
      <input
        type="text"
        placeholder="Search applications..."
        bind:value={searchQuery}
        class="search-input"
      />
      {#if searchQuery}
        <button class="clear-btn" on:click={() => searchQuery = ""}>
          <span class="material-icons">close</span>
        </button>
      {/if}
    </div>

    <div class="toolbar-right">
      <div class="count-pill">
        <span>{filteredApps.length}</span> apps available
      </div>

      <div class="view-toggle">
        <button
          class="toggle-btn {viewMode === 'grid' ? 'active' : ''}"
          on:click={() => setView('grid')}
          title="Grid View"
        >
          <span class="material-icons">grid_view</span>
          <span>Grid</span>
        </button>
        <button
          class="toggle-btn {viewMode === 'list' ? 'active' : ''}"
          on:click={() => setView('list')}
          title="List View"
        >
          <span class="material-icons">view_list</span>
          <span>List</span>
        </button>
      </div>
    </div>
  </div>

  {#if loading}
    <div class="loading-state">
      <span class="material-icons spin">sync</span>
      <p>Loading authorized applications...</p>
    </div>
  {:else if filteredApps.length === 0}
    <div class="empty-state">
      <span class="material-icons empty-icon">search_off</span>
      <h3>No applications found</h3>
      <p>{searchQuery ? `No apps match "${searchQuery}"` : "You do not have access to any proxied applications."}</p>
    </div>
  {:else if viewMode === 'grid'}
    <div class="apps-grid">
      {#each filteredApps as app}
        <a href={app.url} class="app-card" target="_blank" rel="noopener noreferrer">
          <div class="card-top">
            <div class="app-icon-badge">
              <span class="material-icons">{app.icon || 'apps'}</span>
            </div>
            <span class="material-icons launch-indicator">open_in_new</span>
          </div>
          <div class="card-info">
            <h3 class="app-title">{app.name}</h3>
            <span class="category-tag">{app.description}</span>
            <div class="app-domain">{app.external}</div>
          </div>
        </a>
      {/each}
    </div>
  {:else}
    <div class="apps-list">
      {#each filteredApps as app}
        <div class="app-list-row" on:click={() => window.open(app.url, '_blank')}>
          <div class="list-left">
            <div class="app-icon-badge small">
              <span class="material-icons">{app.icon || 'apps'}</span>
            </div>
            <div class="list-title-group">
              <span class="list-title">{app.name}</span>
              <span class="category-tag small">{app.description}</span>
            </div>
          </div>
          <div class="list-center">
            <span class="domain-text">{app.external}</span>
          </div>
          <div class="list-right">
            <span class="auth-badge">Authorized</span>
            <a
              href={app.url}
              class="launch-btn"
              target="_blank"
              rel="noopener noreferrer"
              on:click|stopPropagation
            >
              <span>Open</span>
              <span class="material-icons">arrow_forward</span>
            </a>
          </div>
        </div>
      {/each}
    </div>
  {/if}
</div>

<style>
  .dashboard-container {
    max-width: 1200px;
    margin: 0 auto;
    padding: 32px 40px;
    min-height: calc(100vh - 140px);
  }

  .header-section {
    margin-bottom: 28px;
  }

  .page-title {
    font-size: 28px;
    font-weight: 700;
    letter-spacing: -0.5px;
    margin: 0 0 6px 0;
    background: linear-gradient(to right, #38bdf8, #818cf8);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
  }

  .page-subtitle {
    font-size: 14px;
    color: var(--helper-text);
    margin: 0;
  }

  .toolbar {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 16px;
    margin-bottom: 28px;
    flex-wrap: wrap;
  }

  .search-wrap {
    position: relative;
    flex: 1;
    max-width: 400px;
    min-width: 240px;
  }

  .search-icon {
    position: absolute;
    left: 14px;
    top: 50%;
    transform: translateY(-50%);
    color: var(--helper-text);
    font-size: 20px;
    pointer-events: none;
  }

  .search-input {
    width: 100%;
    background-color: var(--input-bg);
    border: 1px solid var(--input-border);
    border-radius: 12px;
    padding: 10px 38px 10px 42px;
    color: var(--input-text);
    font-size: 14px;
    outline: none;
    transition: all 0.2s;
  }

  .search-input:focus {
    border-color: #38bdf8;
    box-shadow: 0 0 0 3px rgba(56, 189, 248, 0.15);
  }

  .clear-btn {
    position: absolute;
    right: 12px;
    top: 50%;
    transform: translateY(-50%);
    background: transparent;
    border: none;
    color: var(--helper-text);
    cursor: pointer;
    display: flex;
    align-items: center;
    padding: 2px;
  }

  .toolbar-right {
    display: flex;
    align-items: center;
    gap: 14px;
  }

  .count-pill {
    font-size: 13px;
    font-weight: 500;
    color: var(--helper-text);
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

  .toggle-btn {
    background: transparent;
    border: none;
    color: var(--helper-text);
    padding: 6px 14px;
    border-radius: 9px;
    font-size: 13px;
    font-weight: 600;
    display: flex;
    align-items: center;
    gap: 6px;
    cursor: pointer;
    transition: all 0.2s;
  }

  .toggle-btn:hover {
    color: var(--input-text);
  }

  .toggle-btn.active {
    background: var(--tab-btn-active-bg);
    color: #38bdf8;
    box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
  }

  .toggle-btn .material-icons {
    font-size: 18px;
  }

  /* Grid Layout */
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
    transition: transform 0.2s, border-color 0.2s, box-shadow 0.2s, background-color 0.2s;
  }

  .app-card:hover {
    transform: translateY(-4px);
    border-color: #38bdf8;
    box-shadow: 0 16px 30px -5px rgba(0, 0, 0, 0.2), 0 0 20px -5px rgba(56, 189, 248, 0.2);
  }

  .card-top {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    margin-bottom: 16px;
  }

  .app-icon-badge {
    width: 48px;
    height: 48px;
    border-radius: 14px;
    background: linear-gradient(135deg, rgba(56, 189, 248, 0.18), rgba(129, 140, 248, 0.18));
    border: 1px solid rgba(56, 189, 248, 0.3);
    display: flex;
    align-items: center;
    justify-content: center;
    color: #38bdf8;
  }

  .app-icon-badge .material-icons {
    font-size: 26px;
  }

  .app-icon-badge.small {
    width: 40px;
    height: 40px;
    border-radius: 11px;
  }

  .app-icon-badge.small .material-icons {
    font-size: 22px;
  }

  .launch-indicator {
    font-size: 20px;
    color: var(--helper-text);
    opacity: 0.6;
    transition: all 0.2s;
  }

  .app-card:hover .launch-indicator {
    color: #38bdf8;
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
    color: var(--h3-color);
    margin: 0;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .category-tag {
    align-self: flex-start;
    font-size: 11px;
    font-weight: 600;
    background: rgba(56, 189, 248, 0.12);
    color: #38bdf8;
    padding: 2px 8px;
    border-radius: 5px;
  }

  .category-tag.small {
    font-size: 10px;
    padding: 1px 6px;
  }

  .app-domain {
    font-size: 12.5px;
    color: var(--helper-text);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    margin-top: 4px;
  }

  /* List Layout */
  .apps-list {
    display: flex;
    flex-direction: column;
    gap: 12px;
  }

  .app-list-row {
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
    transition: transform 0.2s, border-color 0.2s, background-color 0.2s;
  }

  .app-list-row:hover {
    transform: translateX(4px);
    border-color: #38bdf8;
  }

  .list-left {
    display: flex;
    align-items: center;
    gap: 14px;
    min-width: 220px;
  }

  .list-title-group {
    display: flex;
    flex-direction: column;
    gap: 3px;
  }

  .list-title {
    font-size: 15px;
    font-weight: 600;
    color: var(--text-main);
  }

  .list-center {
    flex: 1;
    padding: 0 20px;
  }

  .domain-text {
    font-size: 13px;
    font-family: monospace;
    color: var(--helper-text);
  }

  .list-right {
    display: flex;
    align-items: center;
    gap: 12px;
  }

  .auth-badge {
    font-size: 11px;
    font-weight: 600;
    background: rgba(16, 185, 129, 0.12);
    color: #10b981;
    padding: 4px 10px;
    border-radius: 20px;
  }

  .launch-btn {
    background: #38bdf8;
    color: #0f172a;
    text-decoration: none;
    padding: 6px 14px;
    border-radius: 8px;
    font-size: 12.5px;
    font-weight: 700;
    display: flex;
    align-items: center;
    gap: 4px;
    transition: filter 0.2s;
  }

  .launch-btn:hover {
    filter: brightness(1.15);
  }

  .launch-btn .material-icons {
    font-size: 15px;
  }

  /* Empty / Loading States */
  .empty-state, .loading-state {
    text-align: center;
    padding: 60px 20px;
    background: var(--card-bg);
    border: 1px solid var(--card-border);
    border-radius: 20px;
    box-shadow: var(--glass-shadow);
  }

  .empty-icon {
    font-size: 48px;
    color: var(--helper-text);
    margin-bottom: 12px;
  }

  .empty-state h3 {
    margin: 0 0 6px 0;
    font-size: 18px;
    color: var(--h3-color);
  }

  .empty-state p, .loading-state p {
    margin: 0;
    font-size: 14px;
    color: var(--helper-text);
  }

  .spin {
    font-size: 36px;
    color: #38bdf8;
    animation: spin 1s linear infinite;
    margin-bottom: 12px;
  }

  @keyframes spin {
    from { transform: rotate(0deg); }
    to { transform: rotate(360deg); }
  }

  @media (max-width: 768px) {
    .dashboard-container {
      padding: 24px 18px;
    }
    .toolbar {
      flex-direction: column;
      align-items: stretch;
    }
    .search-wrap {
      max-width: 100%;
    }
    .toolbar-right {
      justify-content: space-between;
    }
    .list-center {
      display: none;
    }
  }
</style>