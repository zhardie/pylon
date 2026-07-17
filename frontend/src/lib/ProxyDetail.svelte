<script>
export let proxyDetail
export let config

let newUser = ""
let newRoute = ""

function addUser() {
    if (!newUser || !newUser.trim()) return
    if (!proxyDetail.allowed_users) proxyDetail.allowed_users = []
    proxyDetail.allowed_users.push(newUser.trim())
    proxyDetail.allowed_users = proxyDetail.allowed_users
    newUser = ""
    config = config
}

function removeUser(email) {
    proxyDetail.allowed_users.splice( proxyDetail.allowed_users.indexOf(email), 1 )
    proxyDetail.allowed_users = proxyDetail.allowed_users
    config = config
}

function addRoute() {
    if (!newRoute || !newRoute.trim()) return
    if (!proxyDetail.unauthenticated_routes) proxyDetail.unauthenticated_routes = []
    proxyDetail.unauthenticated_routes.push(newRoute.trim())
    proxyDetail.unauthenticated_routes = proxyDetail.unauthenticated_routes
    newRoute = ""
    config = config
}

function removeRoute(route) {
    proxyDetail.unauthenticated_routes.splice( proxyDetail.unauthenticated_routes.indexOf(route), 1 )
    proxyDetail.unauthenticated_routes = proxyDetail.unauthenticated_routes
    config = config
}

function closeDialog() {
    proxyDetail = null
}
</script>

{#if proxyDetail}
<div class="modal-backdrop" on:click={closeDialog}>
    <div class="modal-card" on:click|stopPropagation>
        <div class="modal-header">
            <div class="modal-title-group">
                <h3>Route Advanced Configuration</h3>
                <div class="modal-subtitle">
                    <span class="sub-label">External:</span> <span class="sub-val">{proxyDetail.external || 'Not set'}</span>
                    <span class="sub-separator">→</span>
                    <span class="sub-label">Internal:</span> <span class="sub-val">{proxyDetail.internal || 'Not set'}</span>
                </div>
            </div>
            <button class="close-btn" on:click={closeDialog} aria-label="Close">
                <span class="material-icons">close</span>
            </button>
        </div>
        
        <div class="modal-body">
            <!-- SECTION 1: ALLOWED USERS -->
            <div class="modal-section">
                <h4>🔑 Authorized User Emails</h4>
                <p class="section-desc">Restrict access to specific email addresses. Leave empty to allow any user authenticated by OAuth.</p>
                
                <div class="list-container">
                    {#if proxyDetail.allowed_users && proxyDetail.allowed_users.length > 0}
                        <div class="list-items">
                            {#each proxyDetail.allowed_users as user}
                                <div class="list-item">
                                    <span class="item-text">{user}</span>
                                    <button class="item-action delete" on:click={() => removeUser(user)} aria-label="Remove User">
                                        <span class="material-icons">delete</span>
                                    </button>
                                </div>
                            {/each}
                        </div>
                    {:else}
                        <div class="list-empty">All authenticated users are allowed to access this route.</div>
                    {/if}
                </div>
                
                <div class="add-input-group">
                    <input type="email" placeholder="e.g. user@domain.com" bind:value={newUser} on:keydown={(e) => e.key === 'Enter' && addUser()} />
                    <button class="btn-primary-sm" on:click={addUser}>
                        <span class="material-icons">person_add</span>
                        <span>Add</span>
                    </button>
                </div>
            </div>
            
            <div class="section-divider"></div>
            
            <!-- SECTION 2: UNAUTHENTICATED ROUTES -->
            <div class="modal-section">
                <h4>🔓 Unauthenticated Routes (Bypass Regex)</h4>
                <p class="section-desc">Specify url path regex patterns (like <code>^/api/public</code> or <code>\.(css|js|png)$</code>) that bypass authentication check entirely.</p>
                
                <div class="list-container">
                    {#if proxyDetail.unauthenticated_routes && proxyDetail.unauthenticated_routes.length > 0}
                        <div class="list-items">
                            {#each proxyDetail.unauthenticated_routes as route}
                                <div class="list-item">
                                    <code class="item-code">{route}</code>
                                    <button class="item-action delete" on:click={() => removeRoute(route)} aria-label="Remove Route">
                                        <span class="material-icons">delete</span>
                                    </button>
                                </div>
                            {/each}
                        </div>
                    {:else}
                        <div class="list-empty">No unauthenticated routes configured. Every path is protected.</div>
                    {/if}
                </div>
                
                <div class="add-input-group">
                    <input type="text" placeholder="e.g. ^/public-assets/.*" bind:value={newRoute} on:keydown={(e) => e.key === 'Enter' && addRoute()} />
                    <button class="btn-primary-sm" on:click={addRoute}>
                        <span class="material-icons">post_add</span>
                        <span>Add</span>
                    </button>
                </div>
            </div>
        </div>
        
        <div class="modal-footer">
            <button class="btn-secondary" on:click={closeDialog}>Close</button>
        </div>
    </div>
</div>
{/if}

<style>
    .modal-backdrop {
        position: fixed;
        top: 0;
        left: 0;
        right: 0;
        bottom: 0;
        background: rgba(15, 23, 42, 0.6);
        backdrop-filter: blur(8px);
        -webkit-backdrop-filter: blur(8px);
        display: flex;
        align-items: center;
        justify-content: center;
        z-index: 1000;
        animation: fadeIn 0.2s ease-out;
        padding: 20px;
    }

    .modal-card {
        background: var(--card-bg);
        border: 1px solid var(--card-border);
        border-radius: 24px;
        width: 100%;
        max-width: 650px;
        max-height: 90vh;
        box-shadow: var(--glass-shadow);
        display: flex;
        flex-direction: column;
        overflow: hidden;
        animation: scaleIn 0.2s cubic-bezier(0.34, 1.56, 0.64, 1);
        transition: background-color 0.3s, border-color 0.3s;
    }

    @keyframes fadeIn {
        from { opacity: 0; }
        to { opacity: 1; }
    }

    @keyframes scaleIn {
        from { opacity: 0; transform: scale(0.95); }
        to { opacity: 1; transform: scale(1); }
    }

    .modal-header {
        padding: 24px 32px;
        border-bottom: 1px solid var(--divider);
        display: flex;
        justify-content: space-between;
        align-items: flex-start;
        background: var(--card-header-bg);
    }

    .modal-title-group h3 {
        margin: 0;
        font-size: 20px;
        color: var(--h3-color);
        font-weight: 700;
    }

    .modal-subtitle {
        margin-top: 8px;
        font-size: 13px;
        display: flex;
        align-items: center;
        gap: 6px;
        flex-wrap: wrap;
    }

    .sub-label {
        color: var(--helper-text);
        font-weight: 500;
    }

    .sub-val {
        color: #38bdf8;
        font-weight: 600;
    }

    .sub-separator {
        color: var(--helper-text);
        font-weight: 400;
    }

    .close-btn {
        background: transparent;
        border: none;
        color: var(--helper-text);
        cursor: pointer;
        padding: 4px;
        border-radius: 6px;
        display: flex;
        align-items: center;
        justify-content: center;
        transition: background-color 0.2s, color 0.2s;
    }

    .close-btn:hover {
        background-color: var(--card-header-bg);
        color: var(--text-main);
    }

    .modal-body {
        padding: 32px;
        overflow-y: auto;
        display: flex;
        flex-direction: column;
        gap: 32px;
    }

    .modal-section h4 {
        margin-top: 0;
        margin-bottom: 8px;
        font-size: 16px;
        color: var(--h3-color);
        font-weight: 600;
    }

    .section-desc {
        margin-top: 0;
        margin-bottom: 16px;
        font-size: 13px;
        color: var(--helper-text);
        line-height: 1.5;
    }

    .list-container {
        border: 1px solid var(--card-border);
        background: var(--card-header-bg);
        border-radius: 12px;
        min-height: 60px;
        display: flex;
        flex-direction: column;
        margin-bottom: 16px;
        overflow: hidden;
    }

    .list-items {
        display: flex;
        flex-direction: column;
    }

    .list-item {
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 10px 16px;
        border-bottom: 1px solid var(--divider);
    }

    .list-item:last-child {
        border-bottom: none;
    }

    .item-text {
        font-size: 14px;
        color: var(--text-main);
    }

    .item-code {
        font-size: 13px;
        font-family: monospace;
        color: #818cf8;
        background: var(--code-bg);
        padding: 2px 6px;
        border-radius: 4px;
    }

    .item-action {
        background: transparent;
        border: none;
        color: var(--helper-text);
        cursor: pointer;
        padding: 4px;
        border-radius: 6px;
        display: flex;
        align-items: center;
        justify-content: center;
        transition: background-color 0.2s, color 0.2s;
    }

    .item-action.delete:hover {
        background: var(--danger-bg);
        color: #ef4444;
    }

    .list-empty {
        padding: 20px;
        text-align: center;
        color: var(--helper-text);
        font-size: 13.5px;
    }

    .add-input-group {
        display: flex;
        gap: 12px;
    }

    .add-input-group input {
        flex: 1;
        background-color: var(--input-bg);
        border: 1px solid var(--input-border);
        border-radius: 10px;
        padding: 10px 16px;
        color: var(--input-text);
        font-size: 14px;
        transition: border-color 0.2s, box-shadow 0.2s;
    }

    .add-input-group input:focus {
        outline: none;
        border-color: #38bdf8;
        box-shadow: 0 0 0 3px rgba(56, 189, 248, 0.15);
    }

    .btn-primary-sm {
        background-color: #38bdf8;
        color: #0f172a;
        font-family: inherit;
        font-weight: 600;
        font-size: 13px;
        padding: 0 16px;
        border-radius: 10px;
        cursor: pointer;
        display: flex;
        align-items: center;
        gap: 6px;
        border: none;
        transition: filter 0.2s;
    }

    .btn-primary-sm:hover {
        filter: brightness(1.1);
    }

    .btn-primary-sm span.material-icons {
        font-size: 16px;
    }

    .section-divider {
        height: 1px;
        background-color: var(--divider);
    }

    .modal-footer {
        padding: 20px 32px;
        border-top: 1px solid var(--divider);
        display: flex;
        justify-content: flex-end;
        background: var(--card-header-bg);
    }

    .btn-secondary {
        background-color: var(--tab-btn-bg);
        color: var(--text-main);
        border: 1px solid var(--card-border);
        font-family: inherit;
        font-weight: 600;
        font-size: 14px;
        padding: 10px 24px;
        border-radius: 10px;
        cursor: pointer;
        transition: filter 0.2s;
    }

    .btn-secondary:hover {
        filter: brightness(1.1);
    }
</style>