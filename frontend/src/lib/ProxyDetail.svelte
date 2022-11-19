<script>
export let proxyDetail
export let config
import { afterUpdate } from 'svelte'
import Dialog, { Title, Content, Actions } from '@smui/dialog'
import DataTable, { Head, Body, Row, Cell } from '@smui/data-table'
import Textfield from '@smui/textfield'
import IconButton from '@smui/icon-button'
import Icon from '@smui/textfield/icon'
import Button, { Label } from '@smui/button'
import LayoutGrid, { Cell as GridCell } from '@smui/layout-grid'

let newUser = null
let newRoute = null
let detailDialogOpen = true

function addUser() {
    proxyDetail.allowed_users.push(newUser)
    proxyDetail.allowed_users = proxyDetail.allowed_users
    newUser = null
    config = config
}

function removeUser(email) {
    proxyDetail.allowed_users.splice( proxyDetail.allowed_users.indexOf(email), 1 )
    proxyDetail.allowed_users = proxyDetail.allowed_users
    config = config
}

function addRoute() {
    proxyDetail.unauthenticated_routes.push(newRoute)
    proxyDetail.unauthenticated_routes = proxyDetail.unauthenticated_routes
    newRoute = null
    config = config
}

function removeRoute(route) {
    proxyDetail.unauthenticated_routes.splice( proxyDetail.unauthenticated_routes.indexOf(route), 1 )
    proxyDetail.unauthenticated_routes = proxyDetail.unauthenticated_routes
    config = config
}
</script>

<div>
{#if proxyDetail}
<Dialog
  open
  aria-labelledby="proxy-details-title"
  on:SMUIDialog:closed={() => {
    proxyDetail = null
  }}
  style="width: 100%;"
>
<div class="pd-dialog-content">
<Title id="proxy-details-title">{proxyDetail.external} > {proxyDetail.internal}</Title>
<DataTable table$aria-label="User list" style="width: 100%;">
    <Head>
        <Row>
          <Cell>Authorized User Emails</Cell>
          <Cell></Cell>
        </Row>
    </Head>
    <Body>
        {#each proxyDetail.allowed_users as user}
        <Row>
            <Cell>{user}</Cell>
            <Cell><IconButton class="material-icons" aria-label="Delete" on:click={() => removeUser(user)}>delete</IconButton></Cell>
        </Row>
        {/each}
        <Row>
            <Cell><Textfield class="pd-entry" variant="outlined" bind:value={newUser} /></Cell>
            <Cell><IconButton class="material-icons" aria-label="person_add" on:click={addUser}>person_add</IconButton></Cell>
        </Row>
    </Body>
</DataTable>
<br><br>
<DataTable table$aria-label="User list" style="width: 100%;">
    <Head>
        <Row>
          <Cell>Unauthenticated Routes (regex)</Cell>
          <Cell></Cell>
        </Row>
    </Head>
    <Body>
        {#each proxyDetail.unauthenticated_routes as route}
        <Row>
            <Cell>{route}</Cell>
            <Cell><IconButton class="material-icons" aria-label="Delete" on:click={() => removeRoute(route)}>delete</IconButton></Cell>
        </Row>
        {/each}
        <Row>
            <Cell><Textfield class="pd-entry" variant="outlined" bind:value={newRoute} /></Cell>
            <Cell><IconButton class="material-icons" aria-label="post_add" on:click={addRoute}>post_add</IconButton></Cell>
        </Row>
    </Body>
</DataTable>
</div>
</Dialog>
{/if}
</div>

<style>
    * :global(.pd-entry) {
        width: 100%;
        margin-top: .5rem;
        margin-bottom: .5rem;
    }

    * :global(#proxy-details-title) {
        margin-left: .5rem;
    }
</style>