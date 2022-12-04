<script lang="ts">
// import { querystring } from 'svelte-spa-router'
import LayoutGrid, { Cell as GridCell } from '@smui/layout-grid'
import Card, { Content as CardContent } from '@smui/card'

type app = {
  location: string;
};

let apps: Array<app>;

let foo = new URL(window.location.toString().replace('/#', '/'))

apps = JSON.parse(new URL(window.location.toString().replace('/#', '/')).searchParams.get('apps'))

</script>

<div>
<LayoutGrid>
  {#each apps as app}
  <GridCell class="app-card">
    <Card on:click={() => window.location.href = app.location}>
      <CardContent>{app.location}</CardContent>
    </Card>
  </GridCell>
  {/each}
</LayoutGrid>
</div>

<style>
</style>