<script lang="ts">
import { onMount } from 'svelte'
import LayoutGrid, { Cell as GridCell } from '@smui/layout-grid'
import Card, { Content as CardContent } from '@smui/card'

let apps: Array<string>;

// apps = JSON.parse(new URL(window.location.toString().replace('/#', '/')).searchParams.get('apps'))

onMount(async () => {
  const res = await fetch(`/8ef55d02bd174c29177d5618bfb3a2f3/allowedApps`)
  let res_json = await res.json()
  console.log(res_json)
  apps = res_json['apps']
})

</script>

<div>
<LayoutGrid>
  {#each apps as app}
  <GridCell class="app-card">
    <Card on:click={() => window.location.href = 'http://' + app}>
      <CardContent>{app}</CardContent>
    </Card>
  </GridCell>
  {/each}
</LayoutGrid>
</div>

<style>
</style>