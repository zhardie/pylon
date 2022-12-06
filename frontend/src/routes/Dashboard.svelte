<script lang="ts">

import LayoutGrid, { Cell as GridCell } from '@smui/layout-grid'
import Card, { Content as CardContent } from '@smui/card'

let apps: Array<string>;

apps = JSON.parse(new URL(window.location.toString().replace('/#', '/')).searchParams.get('apps'))

</script>

<div>
<LayoutGrid>
  {#each apps as app}
  <GridCell class="app-card">
    <Card on:click={() => window.location.href = app}>
      <CardContent>{app}</CardContent>
    </Card>
  </GridCell>
  {/each}
</LayoutGrid>
</div>

<style>
</style>