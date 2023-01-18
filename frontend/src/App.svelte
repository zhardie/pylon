<script>
import Router, { push } from 'svelte-spa-router'
import Navigation from './lib/Navigation.svelte'
import Dashboard from './routes/Dashboard.svelte';
import Home from './routes/Home.svelte'
import NotFound from './routes/NotFound.svelte'
import Test from './routes/Test.svelte';

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

<!-- <link
  rel="stylesheet"
  href="https://cdn.jsdelivr.net/npm/svelte-material-ui@6.0.0/bare.min.css"
/> -->

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

<!-- <link
rel="stylesheet"
href="node_modules/@material/typography/dist/mdc.typography.css"
/> -->

<main>
  <Navigation />
  <Router {routes}/>
</main>

<style>
</style>
