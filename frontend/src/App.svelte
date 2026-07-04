<script>
import Router, { push } from 'svelte-spa-router'
import Navigation from './lib/Navigation.svelte'
import Dashboard from './routes/Dashboard.svelte';
import Home from './routes/Home.svelte'
import NotFound from './routes/NotFound.svelte'
import Test from './routes/Test.svelte';
import { darkMode } from './stores.js'

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

const routes = {
    '/': Home,
    '/test': Test,
    '/dashboard': Dashboard,
    '*': NotFound,
}

let isDashboardRedirect = new URL(window.location.toString()).searchParams.get('isDashboardRedirect')
console.log(isDashboardRedirect) // TODO: remove debug
console.log('foo')
if (isDashboardRedirect) {
  push('/dashboard')
}
</script>

<!-- Material Icons -->
<link
  rel="stylesheet"
  href="https://fonts.googleapis.com/icon?family=Material+Icons"
/>
<!-- Roboto -->
<link
  rel="stylesheet"
  href="https://fonts.googleapis.com/css?family=Roboto:300,400,500,600,700"
/>

<main>
  <Navigation />
  <Router {routes}/>
</main>

<style>
</style>
