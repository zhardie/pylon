<script>
import Router from 'svelte-spa-router'
import Navigation from './lib/Navigation.svelte'
import Home from './routes/Home.svelte'
import NotFound from './routes/NotFound.svelte'
import Test from './routes/Test.svelte';

const routes = {
    '/': Home,
    '/test': Test,
    '*': NotFound,
}
</script>

<link rel="stylesheet" href="node_modules/svelte-material-ui/bare.css" />
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

<link
rel="stylesheet"
href="node_modules/@material/typography/dist/mdc.typography.css"
/>

<main>
  <Navigation />
  <Router {routes}/>
</main>

<style>
</style>
