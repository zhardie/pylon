<script lang="ts">
import { darkMode, onboarded } from '../stores.js'

let menuOpen = false;

function toggleTheme() {
    darkMode.update(n => !n)
}

function logout() {
    const xmlhttp = new XMLHttpRequest();
    xmlhttp.open("GET", "/config", true, "logout", "logout");
    xmlhttp.send("");
    xmlhttp.onreadystatechange = function() {
        if (xmlhttp.readyState == 4) {
            window.location.reload();
        }
    }
}

// Reactively toggle body class
$: {
    if (typeof document !== 'undefined') {
        if ($darkMode) {
            document.body.classList.add('dark-mode')
        } else {
            document.body.classList.remove('dark-mode')
        }
    }
}

function toggleMenu() {
    menuOpen = !menuOpen;
}

function closeMenu() {
    menuOpen = false;
}
</script>

{#if $onboarded}
<header class="app-bar">
    <div class="app-bar-content">
        <div class="logo">
            <span class="logo-icon">bolt</span>
            <span class="logo-text">pylon</span>
        </div>
        
        <div class="actions">
            <div class="profile-container">
                <button class="profile-btn" on:click={toggleMenu} aria-label="User Profile">
                    <span class="material-icons">person</span>
                </button>
                
                {#if menuOpen}
                    <!-- Click outside backdrop to close menu -->
                    <div class="menu-backdrop" on:click={closeMenu}></div>
                    
                    <div class="profile-menu">
                        <div class="menu-header">
                            <span class="menu-user">Administrator</span>
                            <span class="menu-role">Gateway Admin</span>
                        </div>
                        <div class="menu-divider"></div>
                        <button class="menu-item" on:click={() => { toggleTheme(); closeMenu(); }}>
                            <span class="material-icons">{$darkMode ? 'light_mode' : 'dark_mode'}</span>
                            <span>{$darkMode ? 'Light Mode' : 'Dark Mode'}</span>
                        </button>
                        <button class="menu-item logout" on:click={logout}>
                            <span class="material-icons">logout</span>
                            <span>Logout</span>
                        </button>
                    </div>
                {/if}
            </div>
        </div>
    </div>
</header>
{/if}

<style>
    .app-bar {
        position: sticky;
        top: 0;
        z-index: 100;
        width: 100%;
        background: var(--card-bg);
        backdrop-filter: blur(16px);
        -webkit-backdrop-filter: blur(16px);
        border-bottom: 1px solid var(--card-border);
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.05);
        transition: background 0.3s, border-color 0.3s;
    }

    .app-bar-content {
        max-width: 1200px;
        margin: 0 auto;
        padding: 16px 40px;
        display: flex;
        justify-content: space-between;
        align-items: center;
    }

    .logo {
        display: flex;
        align-items: center;
        gap: 8px;
    }

    .logo-icon {
        font-family: 'Material Icons';
        font-size: 24px;
        background: linear-gradient(to right, #38bdf8, #818cf8);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
    }

    .logo-text {
        font-size: 20px;
        font-weight: 700;
        letter-spacing: -0.5px;
        background: linear-gradient(to right, #38bdf8, #818cf8);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
    }

    .profile-container {
        position: relative;
    }

    .profile-btn {
        background: var(--card-header-bg);
        border: 1px solid var(--card-border);
        color: var(--text-main);
        width: 40px;
        height: 40px;
        border-radius: 50%;
        display: flex;
        align-items: center;
        justify-content: center;
        cursor: pointer;
        transition: all 0.2s;
    }

    .profile-btn:hover {
        border-color: #38bdf8;
        box-shadow: 0 0 0 3px rgba(56, 189, 248, 0.15);
    }

    .profile-btn span {
        font-size: 22px;
    }

    .menu-backdrop {
        position: fixed;
        top: 0;
        left: 0;
        right: 0;
        bottom: 0;
        z-index: 100;
    }

    .profile-menu {
        position: absolute;
        right: 0;
        top: 48px;
        width: 200px;
        background: var(--input-bg);
        border: 1px solid var(--card-border);
        border-radius: 12px;
        box-shadow: var(--glass-shadow);
        z-index: 101;
        overflow: hidden;
        padding: 8px;
        animation: fadeIn 0.15s ease-out;
    }

    @keyframes fadeIn {
        from {
            opacity: 0;
            transform: translateY(-8px);
        }
        to {
            opacity: 1;
            transform: translateY(0);
        }
    }

    .menu-header {
        padding: 10px 12px;
        display: flex;
        flex-direction: column;
    }

    .menu-user {
        font-size: 14px;
        font-weight: 600;
        color: var(--text-main);
    }

    .menu-role {
        font-size: 11px;
        color: var(--helper-text);
        margin-top: 2px;
    }

    .menu-divider {
        height: 1px;
        background: var(--divider);
        margin: 6px 4px;
    }

    .menu-item {
        width: 100%;
        background: transparent;
        border: none;
        padding: 10px 12px;
        border-radius: 8px;
        display: flex;
        align-items: center;
        gap: 10px;
        color: var(--text-main);
        font-family: inherit;
        font-size: 13.5px;
        cursor: pointer;
        transition: background-color 0.2s;
        text-align: left;
    }

    .menu-item:hover {
        background-color: var(--card-header-bg);
    }

    .menu-item span.material-icons {
        font-size: 18px;
        color: var(--helper-text);
    }

    .menu-item.logout {
        color: #ef4444;
    }

    .menu-item.logout span.material-icons {
        color: #ef4444;
    }

    .menu-item.logout:hover {
        background-color: var(--danger-bg);
    }
</style>