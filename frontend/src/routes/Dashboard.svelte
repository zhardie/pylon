<script lang="ts">
import { onMount } from 'svelte'
import LayoutGrid, { Cell as GridCell } from '@smui/layout-grid'
import Card, { Content as CardContent } from '@smui/card'

let apps: Array<string>;

// apps = JSON.parse(new URL(window.location.toString().replace('/#', '/')).searchParams.get('apps'))

onMount(async () => {
  const res = fetch(`/8ef55d02bd174c29177d5618bfb3a2f3/allowedApps`).then(async res => {
    console.log(res)
    let res_json = await res.json()
    apps = res_json['apps']
  }).catch(error => {
    console.log(error)
  })
})

</script>

<div>
{#if apps}
<LayoutGrid>
  {#each apps as app}
  <GridCell class="app-card">
    <Card on:click={() => window.location.href = 'http://' + app}>
      <CardContent>{app}</CardContent>
    </Card>
  </GridCell>
  {/each}
</LayoutGrid>
{/if}
</div>

<style>
</style>